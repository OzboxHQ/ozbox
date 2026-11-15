//! Running a box module (`infra/tofu/modules/<provider>-box`) the way the box-module contract says (variables in `infra/tofu/modules/<provider>-box/variables.tf`):
//! one state workspace per box, variables as `-var` argv elements, outputs from `tofu output -json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{BoxName, CommandRunner, CommandSpec, DiskGb, Error, Result};

/// The variables every box module accepts. Optional ones are left out of the command when `None`
/// so the module's own default applies.
#[derive(Debug, Clone)]
pub struct ModuleVars {
    pub box_name: BoxName,
    pub machine_type: String,
    pub work_disk_gb: DiskGb,
    pub image_id: String,
    pub region: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub work_snapshot_id: Option<String>,
    /// Provider-specific variables (e.g. AWS `subnet_id`, `kms_key_arn`, `root_disk_gb`), passed as `-var k=v`.
    pub extra: BTreeMap<String, String>,
}

/// The outputs every box module returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleOutputs {
    pub machine_id: String,
    pub work_volume_id: Option<String>,
    pub machine_type: Option<String>,
}

static PLAN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Escape text for use inside an HCL double-quoted string.
fn hcl_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // `${` and `%{` start interpolation / directives in HCL; `$${` and `%%{` are the literal forms.
            '$' | '%' if chars.peek() == Some(&'{') => {
                out.push(c);
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hcl_map(m: &BTreeMap<String, String>) -> String {
    let items: Vec<String> = m
        .iter()
        .map(|(k, v)| format!("{}={}", hcl_quote(k), hcl_quote(v)))
        .collect();
    format!("{{{}}}", items.join(","))
}

/// A reviewed `tofu plan` that replaces one resource. Applying it carries out exactly that plan and nothing else.
/// The plan file is removed when this is dropped.
pub struct ReplacePlan {
    file: PathBuf,
    /// The resources the plan replaces or changes, as `address: actions`, for a person to read.
    pub summary: Vec<String>,
}

impl Drop for ReplacePlan {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.file);
    }
}

/// What a plan's `resource_changes` say about replacing `replace` while `may_replace` are the only other resources
/// allowed to be destroyed. Pure, so it is tested on fixture JSON.
pub fn check_replace_plan(
    plan_json: &str,
    replace: &str,
    may_replace: &[&str],
) -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|_| Error::Provider("OpenTofu's plan could not be read".into()))?;
    let changes = v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut summary = Vec::new();
    let mut replaces_target = false;
    let mut forbidden = Vec::new();
    for c in changes {
        let Some(addr) = c.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let actions: Vec<&str> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if actions.is_empty() || actions == ["no-op"] || actions == ["read"] {
            continue;
        }
        summary.push(format!("{addr}: {}", actions.join("+")));
        let destroys = actions.contains(&"delete");
        if addr == replace {
            replaces_target = destroys && actions.contains(&"create");
        } else if destroys && !may_replace.contains(&addr) {
            forbidden.push(addr.to_string());
        }
    }
    if !forbidden.is_empty() {
        return Err(Error::Provider(format!(
            "OpenTofu would destroy {}, which an upgrade must never do. Nothing was changed; check the box's module state by hand.",
            forbidden.join(", ")
        )));
    }
    if !replaces_target {
        return Err(Error::Provider(format!(
            "OpenTofu does not plan to replace {replace}, so the box does not look like it was made by this module. Nothing was changed."
        )));
    }
    Ok(summary)
}

/// Refuse a plan that would create or destroy any of the `protected` resources (the `/work` volume). A delete loses the
/// disk; a create means OpenTofu's state no longer holds the disk the box really has, and applying it would make a new,
/// EMPTY one while the real volume sits orphaned. Either way nothing may be applied.
pub fn check_protected(plan_json: &str, protected: &[&str]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|_| Error::Provider("OpenTofu's plan could not be read".into()))?;
    let changes = v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut hit = Vec::new();
    for c in changes {
        let Some(addr) = c.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        if !protected.contains(&addr) {
            continue;
        }
        let actions: Vec<&str> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if actions.contains(&"delete") || actions.contains(&"create") {
            hit.push(format!("{addr}: {}", actions.join("+")));
        }
    }
    if hit.is_empty() {
        Ok(())
    } else {
        Err(Error::Provider(format!(
            "OpenTofu would delete or create the /work disk ({}). Nothing was changed. The disk is kept; its OpenTofu state does not match it, so check the box's module state by hand (it may need an import) before trying again.",
            hit.join("; ")
        )))
    }
}

/// What a plan's `resource_changes` say about FINISHING an interrupted upgrade: `create` (the machine) is created and
/// nothing at all is destroyed; the only other resources that may be created are in `may_create` (its attachment).
/// Pure, so it is tested on fixture JSON.
pub fn check_finish_plan(
    plan_json: &str,
    create: &str,
    may_create: &[&str],
) -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|_| Error::Provider("OpenTofu's plan could not be read".into()))?;
    let changes = v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut summary = Vec::new();
    let mut creates_target = false;
    let mut forbidden = Vec::new();
    for c in changes {
        let Some(addr) = c.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let actions: Vec<&str> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if actions.is_empty() || actions == ["no-op"] || actions == ["read"] {
            continue;
        }
        summary.push(format!("{addr}: {}", actions.join("+")));
        if actions.contains(&"delete") {
            forbidden.push(addr.to_string());
        } else if addr == create {
            creates_target = actions == ["create"];
        } else if actions.contains(&"create") && !may_create.contains(&addr) {
            forbidden.push(addr.to_string());
        }
    }
    if !forbidden.is_empty() {
        return Err(Error::Provider(format!(
            "OpenTofu would destroy or newly create {}, which finishing an upgrade must never do. Nothing was changed; check the box's module state by hand.",
            forbidden.join(", ")
        )));
    }
    if !creates_target {
        return Err(Error::Provider(format!(
            "OpenTofu does not plan to create {create} on its own, so the box does not look like an interrupted upgrade. Nothing was changed."
        )));
    }
    Ok(summary)
}

/// What a plan that changes a box in place may do: no resource is replaced, and only the listed ones are created or
/// destroyed. Everything else may only be updated (tags, a policy document). The `/work` volume is never touched beyond
/// an update. Pure, so it is tested on fixture JSON.
pub fn check_inplace_plan(
    plan_json: &str,
    may_create: &[&str],
    may_delete: &[&str],
    protected: &[&str],
) -> Result<Vec<String>> {
    check_inplace_plan_for(plan_json, may_create, may_delete, protected, FleetTag::Any)
}

/// What a plan may do with the role's `ozbox-fleet` tag, the principal tag the key's policy trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FleetTag<'a> {
    /// It may appear or go on any resource, with any value (a pure check of a plan fixture).
    Any,
    /// It may exist only on a role (`aws_iam_role.*`), and where the plan gives it a value, that value is the fleet this change is
    /// for: `Some(name)`, or `None` for a step that gives no role a fleet at all (it may then only be taken away).
    Is(Option<&'a str>),
}

/// [`check_inplace_plan`] told which fleet the change is for, so a drifted module cannot hand a box's role another fleet's name
/// (on main that tag selects the managed fleet-key policy and the key's `ozbox-fleet` condition).
pub fn check_inplace_plan_for(
    plan_json: &str,
    may_create: &[&str],
    may_delete: &[&str],
    protected: &[&str],
    fleet: FleetTag<'_>,
) -> Result<Vec<String>> {
    let mut summary = Vec::new();
    let mut forbidden = Vec::new();
    for (addr, actions) in plan_actions(plan_json)? {
        summary.push(format!("{addr}: {}", actions.join("+")));
        let creates = actions.iter().any(|a| a == "create");
        let deletes = actions.iter().any(|a| a == "delete");
        let replaced = creates && deletes;
        // Only the plain actions are understood. Anything else (OpenTofu's `forget`, from a `removed` block, or an action a
        // later version adds) is neither a create, a delete nor an update, so none of the lists below would see it: refused.
        let understood = matches!(
            actions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["create"] | ["delete"] | ["update"] | ["create", "delete"] | ["delete", "create"]
        );
        let bad = !understood
            || replaced
            || protected.contains(&addr.as_str()) && (creates || deletes)
            || (creates && !may_create.contains(&addr.as_str()))
            || (deletes && !may_delete.contains(&addr.as_str()));
        if bad {
            forbidden.push(addr);
        }
    }
    if !forbidden.is_empty() {
        return Err(Error::Provider(format!(
            "OpenTofu would replace, destroy or newly create {}, which this change must never do. Nothing was changed; check the box's module state by hand.",
            forbidden.join(", ")
        )));
    }
    // An UPDATE is not harmless either: a stale spec or a module that moved on could change anything about the machine in
    // place (its instance type, the metadata options the box needs to read its own tags, API stop protection, a security
    // group, another role's policy). So this is an ALLOWLIST, not a list of what is known to be bad: an update may change
    // tags, and the policy named by the one role-policy attachment this change creates or takes back, and nothing else.
    let drifted = in_place_attribute_changes(plan_json, may_create, may_delete, fleet);
    if !drifted.is_empty() {
        return Err(Error::Provider(format!(
            "OpenTofu would change {} in place, which this change must never do (it may change tags and the role's fleet-key attachment only). Nothing was changed; check that the box's configuration matches the module.",
            drifted.join(", ")
        )));
    }
    Ok(summary)
}

/// The tag maps. They carry authorisation (`ozbox-managed` is the Systems Manager target condition, `ozbox-fleet` the role's
/// principal tag), so they are compared KEY BY KEY against [`IN_PLACE_TAG_KEYS`], never as a whole.
const IN_PLACE_TAGS: &[&str] = &["tags", "tags_all"];
/// The tag keys this change manages: the pending and the committed label and the fleet name label (they ride on every taggable
/// resource of the module), and the fleet tag the role gets with the key grant (added or taken away, never rewritten to another
/// fleet). Every other key, `ozbox-managed` first, may not change.
pub const IN_PLACE_TAG_KEYS: &[&str] = &[
    "ozbox-secrets-adopt",
    "ozbox-secrets-key",
    "ozbox-secrets-fleet",
    "ozbox-fleet",
];
/// The one of those a role carries; it may appear or go, never change from one fleet to another.
const FLEET_TAG: &str = "ozbox-fleet";
/// And, on the role's managed-policy attachment this change creates or takes back, the policy it names (`policy_arn`: the daily
/// operator role may attach the account's fleet-key policy, and is denied `iam:PutRolePolicy`, so nothing inline is ever planned).
const IN_PLACE_POLICY: &str = "policy_arn";

/// `address.attribute` for every attribute an update in the plan would change that is not on the allowlist (see
/// [`check_inplace_plan`]). An attribute whose new value is not known until apply counts as changed. Pure.
fn in_place_attribute_changes(
    plan_json: &str,
    may_create: &[&str],
    may_delete: &[&str],
    fleet: FleetTag<'_>,
) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(plan_json) else {
        // a plan that cannot be read is never "nothing changed"
        return vec!["the plan".into()];
    };
    let mut out = Vec::new();
    for c in v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let actions: Vec<&str> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        // only an update is looked at here: creates and deletes are the lists above's business
        if actions != ["update"] {
            continue;
        }
        let Some(addr) = c.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let (Some(before), Some(after)) = (
            c.pointer("/change/before").and_then(|b| b.as_object()),
            c.pointer("/change/after").and_then(|b| b.as_object()),
        ) else {
            out.push(format!("{addr} (its change could not be read)"));
            continue;
        };
        let policy_ok = may_create.contains(&addr) || may_delete.contains(&addr);
        let allowed = |k: &str| policy_ok && k == IN_PLACE_POLICY;
        let mut changed: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for k in before.keys().chain(after.keys()) {
            if before.get(k) != after.get(k) {
                changed.insert(k);
            }
        }
        // a value only known after apply is a change this plan cannot vouch for
        if let Some(unknown) = c
            .pointer("/change/after_unknown")
            .and_then(|u| u.as_object())
        {
            for (k, u) in unknown {
                if u.as_bool() == Some(true)
                    || u.as_object().is_some_and(|o| !o.is_empty())
                    || u.as_array().is_some_and(|a| !a.is_empty())
                {
                    changed.insert(k);
                }
            }
        }
        for k in changed {
            if IN_PLACE_TAGS.contains(&k) {
                for key in changed_tag_keys(c, k, addr, fleet) {
                    out.push(format!("{addr}.{k}[{key}]"));
                }
            } else if !allowed(k) {
                out.push(format!("{addr}.{k}"));
            }
        }
    }
    out
}

/// Whether the plan's new value for the fleet tag (`None`: taken away) is one the change may make, on this resource. Only a role
/// carries the tag, and the value is the fleet the change is for.
fn fleet_tag_ok(addr: &str, after: Option<&serde_json::Value>, fleet: FleetTag<'_>) -> bool {
    match fleet {
        FleetTag::Any => true,
        FleetTag::Is(want) => match after {
            None => true,
            Some(v) => {
                addr.starts_with("aws_iam_role.") && v.as_str().is_some() && v.as_str() == want
            }
        },
    }
}

/// The tag keys a plan changes on one resource that [`IN_PLACE_TAG_KEYS`] does not allow, in `tags` or `tags_all`: a key added,
/// removed or given another value, a key whose value is only known after apply, or a whole map that is. A map that is not an
/// object counts as empty on one side only when it is null. Pure.
fn changed_tag_keys(
    change: &serde_json::Value,
    attr: &str,
    addr: &str,
    fleet: FleetTag<'_>,
) -> Vec<String> {
    let side = |which: &str| -> Option<serde_json::Map<String, serde_json::Value>> {
        match change.pointer(&format!("/change/{which}/{attr}")) {
            None | Some(serde_json::Value::Null) => Some(serde_json::Map::new()),
            Some(serde_json::Value::Object(o)) => Some(o.clone()),
            Some(_) => None,
        }
    };
    let (Some(before), Some(after)) = (side("before"), side("after")) else {
        return vec!["(not a map)".into()];
    };
    let mut bad = std::collections::BTreeSet::new();
    let keys: std::collections::BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    for k in keys {
        let (b, a) = (before.get(k), after.get(k));
        if b == a {
            continue;
        }
        let allowed = IN_PLACE_TAG_KEYS.contains(&k.as_str())
            // the fleet tag may appear or go, never be rewritten
            && !(k == FLEET_TAG && b.is_some() && a.is_some())
            && (k != FLEET_TAG || fleet_tag_ok(addr, a, fleet));
        if !allowed {
            bad.insert(k.clone());
        }
    }
    match change.pointer(&format!("/change/after_unknown/{attr}")) {
        // `tags_all` is computed from `tags` and the provider's default tags; its known keys were compared above, and a
        // whole-map "known after apply" there says nothing more than the tags it follows
        Some(serde_json::Value::Bool(true)) if attr == "tags" => {
            bad.insert("(unknown until apply)".into());
        }
        Some(serde_json::Value::Object(o)) => {
            for (k, u) in o {
                if u.as_bool() == Some(true) && !IN_PLACE_TAG_KEYS.contains(&k.as_str()) {
                    bad.insert(k.clone());
                }
            }
        }
        _ => {}
    }
    bad.into_iter().collect()
}

/// The non-trivial actions of every resource in a plan, as `(address, actions)`. Pure.
fn plan_actions(plan_json: &str) -> Result<Vec<(String, Vec<String>)>> {
    let v: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|_| Error::Provider("OpenTofu's plan could not be read".into()))?;
    let changes = v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let mut out = Vec::new();
    for c in changes {
        let Some(addr) = c.get("address").and_then(|a| a.as_str()) else {
            continue;
        };
        let actions: Vec<String> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if actions.is_empty() || actions == ["no-op"] || actions == ["read"] {
            continue;
        }
        out.push((addr.to_string(), actions));
    }
    Ok(out)
}

/// The read-only preview of a `/work` restore (`plan -replace=<volume>` with the snapshot): the volume must be
/// replaced, only the resources in `may_replace` may be replaced with it, and nothing else may change at all. In
/// particular the machine must not be touched: if it would be replaced, the restore is refused before anything is
/// stopped, detached or removed from the state. Pure, so it is tested on fixture JSON.
pub fn check_restore_preview(
    plan_json: &str,
    volume: &str,
    may_replace: &[&str],
) -> Result<Vec<String>> {
    let mut summary = Vec::new();
    let mut replaces_volume = false;
    let mut other = Vec::new();
    for (addr, actions) in plan_actions(plan_json)? {
        summary.push(format!("{addr}: {}", actions.join("+")));
        let replaced =
            actions.iter().any(|a| a == "delete") && actions.iter().any(|a| a == "create");
        if addr == volume {
            replaces_volume = replaced;
        } else if !(may_replace.contains(&addr.as_str()) && replaced) {
            other.push(addr);
        }
    }
    if !other.is_empty() {
        return Err(Error::Provider(format!(
            "restoring /work would also change {}, which a restore must never do. Nothing was changed; check the box's module state by hand.",
            other.join(", ")
        )));
    }
    if !replaces_volume {
        return Err(Error::Provider(format!(
            "OpenTofu does not plan to replace {volume}, so the box does not look like it was made by this module. Nothing was changed."
        )));
    }
    Ok(summary)
}

/// The plan that puts the restored volume in place, after the old one was taken out of the state: it may create the
/// resources in `create` (and nothing else), and destroy and change nothing at all. Pure, so it is tested on fixture
/// JSON.
pub fn check_restore_apply(plan_json: &str, create: &[&str]) -> Result<Vec<String>> {
    let mut summary = Vec::new();
    let mut forbidden = Vec::new();
    for (addr, actions) in plan_actions(plan_json)? {
        summary.push(format!("{addr}: {}", actions.join("+")));
        if !(actions == ["create"] && create.contains(&addr.as_str())) {
            forbidden.push(addr);
        }
    }
    if forbidden.is_empty() {
        Ok(summary)
    } else {
        Err(Error::Provider(format!(
            "OpenTofu would change {} besides the restored /work disk, which a restore must never do. Nothing was applied.",
            forbidden.join(", ")
        )))
    }
}

/// What importing a box's resources leaves different from what the module's own apply would have written, and so what
/// a first plan would show as a change although nothing in the cloud differs:
///
/// - `aws_instance`: the importer records `user_data` (a hash) where the module sets `user_data_base64`, and does not know
///   `user_data_replace_on_change` (the module sets it `true`).
/// - `aws_volume_attachment`: the importer does not know `stop_instance_before_detaching` (the module sets it `true`).
///
/// Edits a pulled state document and raises its serial so `tofu state push` accepts it. Returns the new document and a
/// sentence per correction (empty when there was nothing to correct, in which case the document is returned untouched).
/// Pure; it never reaches the cloud.
pub fn fix_import_artefacts(state_json: &str) -> Result<(String, Vec<String>)> {
    let mut v: serde_json::Value = serde_json::from_str(state_json)?;
    let mut said: Vec<String> = Vec::new();
    if let Some(resources) = v.get_mut("resources").and_then(|r| r.as_array_mut()) {
        for r in resources {
            let ty = r
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let name = r
                .get("name")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let Some(instances) = r.get_mut("instances").and_then(|i| i.as_array_mut()) else {
                continue;
            };
            for inst in instances {
                let Some(attrs) = inst.get_mut("attributes").and_then(|a| a.as_object_mut()) else {
                    continue;
                };
                match (ty.as_str(), name.as_str()) {
                    ("aws_instance", "box") => {
                        if attrs.get("user_data_replace_on_change")
                            != Some(&serde_json::Value::Bool(true))
                        {
                            attrs.insert("user_data_replace_on_change".into(), true.into());
                            said.push("aws_instance.box: user_data_replace_on_change set to true, as the module sets it".into());
                        }
                        let has_plain = attrs.get("user_data").is_some_and(|u| !u.is_null());
                        if has_plain {
                            attrs.insert("user_data".into(), serde_json::Value::Null);
                            said.push("aws_instance.box: the imported user_data hash cleared; the module sets user_data_base64 (and ignores changes to it)".into());
                        }
                    }
                    ("aws_volume_attachment", "work")
                        if attrs.get("stop_instance_before_detaching")
                            != Some(&serde_json::Value::Bool(true)) =>
                    {
                        attrs.insert("stop_instance_before_detaching".into(), true.into());
                        said.push("aws_volume_attachment.work: stop_instance_before_detaching set to true, as the module sets it".into());
                    }
                    _ => {}
                }
            }
        }
    }
    if said.is_empty() {
        return Ok((state_json.to_string(), said));
    }
    let serial = v.get("serial").and_then(|s| s.as_u64()).unwrap_or(0);
    v["serial"] = serde_json::json!(serial + 1);
    Ok((serde_json::to_string_pretty(&v)?, said))
}

/// The Hetzner counterpart of [`fix_import_artefacts`]: what the importer cannot read back, set to what the module sets.
///
/// - `hcloud_volume_attachment`: the API does not say whether the volume was automounted; the module sets `automount =
///   false`, and the provider replaces the attachment (a detach and attach of `/work`) when the state disagrees.
/// - `hcloud_server`: the switches the API has no field for (`keep_disk`, `delete_protection`, ...) are left unset by the
///   importer; they are put at their defaults only when absent, never over a value the API reported.
///
/// `user_data` is not here: Hetzner cannot return it, so the server module ignores changes to it. Pure.
pub fn fix_import_artefacts_hcloud(state_json: &str) -> Result<(String, Vec<String>)> {
    let mut v: serde_json::Value = serde_json::from_str(state_json)?;
    let mut said: Vec<String> = Vec::new();
    const SERVER_DEFAULTS: [&str; 7] = [
        "keep_disk",
        "allow_deprecated_images",
        "shutdown_before_deletion",
        "ignore_remote_firewall_ids",
        "delete_protection",
        "rebuild_protection",
        "backups",
    ];
    if let Some(resources) = v.get_mut("resources").and_then(|r| r.as_array_mut()) {
        for r in resources {
            let ty = r
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let name = r
                .get("name")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let Some(instances) = r.get_mut("instances").and_then(|i| i.as_array_mut()) else {
                continue;
            };
            for inst in instances {
                let Some(attrs) = inst.get_mut("attributes").and_then(|a| a.as_object_mut()) else {
                    continue;
                };
                match (ty.as_str(), name.as_str()) {
                    ("hcloud_volume_attachment", "work")
                        if attrs.get("automount") != Some(&serde_json::Value::Bool(false)) =>
                    {
                        attrs.insert("automount".into(), false.into());
                        said.push("hcloud_volume_attachment.work: automount set to false, as the module sets it".into());
                    }
                    ("hcloud_server", "box") => {
                        let mut set = Vec::new();
                        for k in SERVER_DEFAULTS {
                            if attrs.get(k).is_none_or(|x| x.is_null()) {
                                attrs.insert(k.into(), false.into());
                                set.push(k);
                            }
                        }
                        if !set.is_empty() {
                            said.push(format!(
                                "hcloud_server.box: {} put at their defaults (the API does not report them)",
                                set.join(", ")
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if said.is_empty() {
        return Ok((state_json.to_string(), said));
    }
    let serial = v.get("serial").and_then(|s| s.as_u64()).unwrap_or(0);
    v["serial"] = serde_json::json!(serial + 1);
    Ok((serde_json::to_string_pretty(&v)?, said))
}

/// The plan that finishes an adoption must change nothing: every resource `no-op` (or only read), or at most an in-place
/// update whose ONLY differences are tags. Anything else means the imported state does not match the module, and the
/// adoption is refused. Returns a line for each tag-only update (what it will change on the next apply). Pure.
pub fn check_adopt_plan(plan_json: &str) -> Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(plan_json)?;
    let mut tag_only = Vec::new();
    let mut bad = Vec::new();
    for rc in v
        .get("resource_changes")
        .and_then(|r| r.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let addr = rc.get("address").and_then(|a| a.as_str()).unwrap_or("?");
        let change = &rc["change"];
        let actions: Vec<&str> = change
            .get("actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        match actions.as_slice() {
            [] | ["no-op"] | ["read"] => {}
            ["update"] => {
                let (b, a) = (&change["before"], &change["after"]);
                let keys: std::collections::BTreeSet<&String> = b
                    .as_object()
                    .into_iter()
                    .flatten()
                    .chain(a.as_object().into_iter().flatten())
                    .map(|(k, _)| k)
                    .collect();
                let differs: Vec<&&String> = keys
                    .iter()
                    .filter(|k| b.get(k.as_str()) != a.get(k.as_str()))
                    .collect();
                if !differs.is_empty()
                    && differs
                        .iter()
                        .all(|k| matches!(k.as_str(), "tags" | "tags_all" | "labels"))
                {
                    tag_only.push(format!("{addr}: tags only"));
                } else {
                    let names: Vec<String> = differs.iter().map(|k| k.to_string()).collect();
                    bad.push(format!("{addr} would change {}", names.join(", ")));
                }
            }
            other => bad.push(format!("{addr} would {}", other.join(" and "))),
        }
    }
    if bad.is_empty() {
        Ok(tag_only)
    } else {
        Err(Error::Provider(format!(
            "after importing, OpenTofu would still change: {}. Nothing in the cloud was touched, and the imported state was taken back out.",
            bad.join("; ")
        )))
    }
}

/// The value of an attribute in `tofu state show` output (`  id = "vol-0abc"`). Pure.
pub fn state_attribute(shown: &str, key: &str) -> Option<String> {
    shown.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

#[derive(Clone)]
pub struct TofuModule {
    runner: Arc<dyn CommandRunner>,
    dir: PathBuf,
    state: Option<StateLayout>,
    s3: Option<S3State>,
    /// Resource types this identity cannot apply (a plan that changes one is refused before anything is stopped).
    deny_types: Vec<String>,
}

/// Refuse a plan that creates, changes or destroys a resource of one of the `types`. A box must never be stopped by a plan that
/// cannot finish: the daily role is denied some IAM actions on purpose (it cannot create or change a policy), so a plan that
/// needs one fails after the box is already stopped, and fails the same way when run again.
pub fn check_applicable(plan_json: &str, types: &[String]) -> Result<()> {
    if types.is_empty() {
        return Ok(());
    }
    let v: serde_json::Value = serde_json::from_str(plan_json)
        .map_err(|_| Error::Provider("OpenTofu's plan could not be read".into()))?;
    let mut hit = Vec::new();
    for c in v
        .get("resource_changes")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let ty = c.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let actions: Vec<&str> = c
            .pointer("/change/actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if types.iter().any(|t| t == ty)
            && !(actions.is_empty() || actions == ["no-op"] || actions == ["read"])
        {
            if let Some(a) = c.get("address").and_then(|a| a.as_str()) {
                hit.push(a.to_string());
            }
        }
    }
    if hit.is_empty() {
        return Ok(());
    }
    Err(Error::Provider(format!(
        "OpenTofu would change {}, which needs permissions your daily role does not have on purpose (it cannot create or change an IAM policy). Nothing was stopped or changed. Policies a box needs are made once by `ozbox init`, with the setup identity, and the box only attaches them: run `ozbox init`, or see infra/README.md for what an administrator must run once.",
        hit.join(", ")
    )))
}

/// A box module's state kept in the encrypted, versioned bucket `ozbox init` makes, instead of a local file (ADR 0033).
///
/// One OpenTofu workspace per box, as with the local backend: the object is
/// `ozbox/boxes/<module>/<box>/terraform.tfstate` in `bucket`, and the lock is OpenTofu's native S3 lock file
/// (`use_lockfile`, OpenTofu 1.10 or newer; no table to own or pay for), the same choice the network module already
/// makes. Credentials are the caller's own, like every other call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3State {
    pub bucket: String,
    pub region: String,
    /// A customer-managed key for the objects; `None` uses the bucket's default encryption.
    pub kms_key_id: Option<String>,
}

impl S3State {
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            kms_key_id: None,
        }
    }

    /// Plain names only: these become `-backend-config` arguments, so nothing that could carry a second argument.
    pub fn validate(&self) -> Result<()> {
        let bucket_ok = (3..=63).contains(&self.bucket.len())
            && self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && !self.bucket.starts_with(['-', '.'])
            && !self.bucket.ends_with(['-', '.']);
        let region_ok = (6..=20).contains(&self.region.len())
            && self
                .region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        let kms_ok = self.kms_key_id.as_deref().is_none_or(|k| {
            !k.is_empty()
                && k.len() <= 2048
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_/:.".contains(&b))
        });
        if bucket_ok && region_ok && kms_ok {
            Ok(())
        } else {
            Err(Error::Config(
                "the state bucket, its region or its key is not a plain name (lowercase letters, digits, dashes)".into(),
            ))
        }
    }

    /// Where a box's state object is, for messages and tests.
    pub fn remote_key(module: &str, box_name: &BoxName) -> String {
        format!("{}/{box_name}/terraform.tfstate", Self::prefix(module))
    }

    fn prefix(module: &str) -> String {
        format!("ozbox/boxes/{module}")
    }

    fn backend_config(&self, module: &str) -> Vec<String> {
        let mut a = vec![
            format!("-backend-config=bucket={}", self.bucket),
            "-backend-config=key=terraform.tfstate".to_string(),
            format!("-backend-config=region={}", self.region),
            format!(
                "-backend-config=workspace_key_prefix={}",
                Self::prefix(module)
            ),
            "-backend-config=encrypt=true".to_string(),
            "-backend-config=use_lockfile=true".to_string(),
        ];
        if let Some(k) = &self.kms_key_id {
            a.push(format!("-backend-config=kms_key_id={k}"));
        }
        a
    }
}

/// Where a box module's OpenTofu state lives, apart from the module's source checkout: removing, moving or re-cloning the
/// checkout (a git worktree, a new release) can never take a box's state with it.
///
/// ```text
/// <state root>/<module name>/workspaces/<box>/terraform.tfstate   one workspace per box
/// <state root>/<module name>/data/                                  OpenTofu's own working data (.terraform)
/// <state root>/<module name>/backups/                               copies taken before and after state surgery
/// ```
///
/// The module declares an empty `backend "local" {}`; the paths are given to `tofu init` as `-backend-config`.
#[derive(Debug, Clone)]
pub struct StateLayout {
    root: PathBuf,
}

/// The default state root: `$OZBOX_TOFU_STATE_DIR`, else `$XDG_STATE_HOME/ozbox/tofu`, else `~/.local/state/ozbox/tofu`.
pub fn default_state_root(home: Option<&Path>) -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("OZBOX_TOFU_STATE_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d).join("ozbox/tofu"));
    }
    home.map(|h| h.join(".local/state/ozbox/tofu"))
}

impl StateLayout {
    pub fn new(state_root: &Path, module_dir: &Path) -> Self {
        let name = module_dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "module".into());
        Self {
            root: state_root.join(name),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }

    pub fn workspace_dir(&self) -> PathBuf {
        self.root.join("workspaces")
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    /// OpenTofu's working data while the state is in the bucket (apart from `data/`, so switching never confuses either).
    pub fn data_dir_s3(&self) -> PathBuf {
        self.root.join("data-s3")
    }

    /// The generated copy of the module that carries the bucket backend (the real module is never written to).
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    fn module_name(&self) -> String {
        self.root
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "module".into())
    }

    pub fn state_file(&self, box_name: &BoxName) -> PathBuf {
        self.workspace_dir()
            .join(box_name.as_str())
            .join("terraform.tfstate")
    }

    fn default_state(&self) -> PathBuf {
        self.root.join("default.tfstate")
    }

    /// Copy what an older version left inside the module checkout (`terraform.tfstate.d/<box>/terraform.tfstate`, and the
    /// default workspace's `terraform.tfstate`) into this layout. **Copy, verify, never delete**: the old files stay where
    /// they were, with a note beside them saying where the state lives now. A workspace that already has state here is
    /// left alone (the new copy is the live one). Returns the workspaces copied.
    pub fn migrate_legacy(&self, module_dir: &Path) -> Result<Vec<String>> {
        let mut moved = Vec::new();
        let old_ws = module_dir.join("terraform.tfstate.d");
        if let Ok(rd) = std::fs::read_dir(&old_ws) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let src = e.path().join("terraform.tfstate");
                if BoxName::new(&name).is_err() || !src.is_file() {
                    continue;
                }
                let dest = self.workspace_dir().join(&name).join("terraform.tfstate");
                if dest.exists() {
                    continue;
                }
                copy_verified(&src, &dest)?;
                moved.push(name);
            }
        }
        let old_default = module_dir.join("terraform.tfstate");
        if old_default.is_file()
            && std::fs::metadata(&old_default)
                .map(|m| m.len())
                .unwrap_or(0)
                > 0
            && !self.default_state().exists()
        {
            copy_verified(&old_default, &self.default_state())?;
        }
        if !moved.is_empty() && old_ws.is_dir() {
            let note = format!(
                "Oz Box copied the OpenTofu state of {} to {}.\nThat copy is the live one. These files were left as they were and are no longer used; keep them until you are sure.\n",
                moved.join(", "),
                self.workspace_dir().display()
            );
            let _ = std::fs::write(old_ws.join("MOVED-BY-OZBOX.txt"), note);
        }
        Ok(moved)
    }

    /// A timestamped copy of a box's state (before and after state surgery). Returns where it went; `None` when the box
    /// has no state yet.
    pub fn backup(&self, box_name: &BoxName, label: &str) -> Result<Option<PathBuf>> {
        let src = self.state_file(box_name);
        if !src.is_file() {
            return Ok(None);
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dest = self
            .backups_dir()
            .join(format!("{box_name}-{secs}-{label}.tfstate"));
        copy_verified(&src, &dest)?;
        Ok(Some(dest))
    }
}

const LOCAL_BACKEND: &str = "backend \"local\" {}";
const S3_BACKEND: &str = "backend \"s3\" {}";

/// What `ozbox state migrate` did for one box.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MigrateReport {
    #[serde(rename = "box")]
    pub box_name: String,
    pub serial: u64,
    pub resources: usize,
    pub remote_key: String,
    pub backup: Option<String>,
    /// The bucket already held exactly this state (an earlier run got that far).
    pub already_there: bool,
}

/// `(major, minor)` from `tofu version -json` (or the older `OpenTofu v1.9.1` text). `(0, 0)` when unreadable.
pub fn parse_tofu_version(stdout: &str) -> (u32, u32) {
    let v = serde_json::from_str::<serde_json::Value>(stdout)
        .ok()
        .and_then(|v| {
            v.get("terraform_version")
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .or_else(|| {
            stdout
                .split_whitespace()
                .find_map(|w| w.strip_prefix('v').map(str::to_string))
        })
        .unwrap_or_default();
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// What identifies a state: who it belongs to (lineage), how far it has been written (serial), and what is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    pub lineage: String,
    pub serial: u64,
    pub resources: usize,
    body: serde_json::Value,
}

impl StateSummary {
    pub fn of(state_json: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(state_json)?;
        Ok(Self {
            lineage: v
                .get("lineage")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
            serial: v.get("serial").and_then(|x| x.as_u64()).unwrap_or(0),
            resources: v
                .get("resources")
                .and_then(|r| r.as_array())
                .map_or(0, Vec::len),
            body: serde_json::json!({
                "resources": v.get("resources").cloned().unwrap_or_default(),
                "outputs": v.get("outputs").cloned().unwrap_or_default(),
            }),
        })
    }
}

/// Why the bucket's copy of a box's state must not become the live one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchProblem {
    /// The bucket holds no state for the box.
    Missing,
    /// The bucket holds another state: another lineage, or the same write number with other content.
    Different,
    /// The bucket's copy is older: the box was changed here after it was copied.
    Stale,
}

/// Whether the bucket's copy may become the live state of a box whose state on this computer is `local`. It may when it is
/// the same state, or the same lineage written further on (the box was changed through the bucket since, by design). Pure.
pub fn bucket_copy_problem(
    local: &StateSummary,
    bucket: Option<&StateSummary>,
) -> Option<SwitchProblem> {
    let Some(b) = bucket else {
        return Some(SwitchProblem::Missing);
    };
    if b.lineage != local.lineage || (b.serial == local.serial && b != local) {
        return Some(SwitchProblem::Different);
    }
    if b.serial < local.serial {
        return Some(SwitchProblem::Stale);
    }
    None
}

/// `tofu state pull` of a workspace with no state prints nothing, or a state with no resources and serial 0.
fn state_is_empty(json: &str) -> bool {
    json.trim().is_empty()
        || StateSummary::of(json).is_ok_and(|s| s.resources == 0 && s.serial == 0)
}

/// The plan after a state was copied must change nothing at all: every resource `no-op` (or only read). Stricter than
/// [`check_adopt_plan`], which tolerates tags. Pure.
pub fn check_noop_plan(plan_json: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(plan_json)?;
    let mut bad = Vec::new();
    for rc in v
        .get("resource_changes")
        .and_then(|r| r.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let addr = rc.get("address").and_then(|a| a.as_str()).unwrap_or("?");
        let actions: Vec<&str> = rc["change"]
            .get("actions")
            .and_then(|a| a.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if !matches!(actions.as_slice(), [] | ["no-op"] | ["read"]) {
            bad.push(format!("{addr} would {}", actions.join(" and ")));
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(Error::Provider(format!(
            "after the copy, OpenTofu would still change: {}.",
            bad.join("; ")
        )))
    }
}

fn write_private(dest: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = dest.with_extension("tmp-write");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn write_if_changed(dest: &Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(dest).is_ok_and(|b| b == bytes) {
        return Ok(());
    }
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = dest.with_extension("tmp-write");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Copy a folder's files (recursively), writing only what differs. Small folders only: the box module's cloud-init scripts.
fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let (from, to) = (e.path(), dest.join(e.file_name()));
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else if from.is_file() {
            write_if_changed(&to, &std::fs::read(&from)?)?;
        }
    }
    Ok(())
}

/// Copy a file with owner-only permissions, then read both back and compare. An error leaves the source untouched.
fn copy_verified(src: &Path, dest: &Path) -> Result<()> {
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let bytes = std::fs::read(src)?;
    let tmp = dest.with_extension("tmp-copy");
    std::fs::write(&tmp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    if std::fs::read(&tmp)? != bytes {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Provider(format!(
            "copying {} did not verify; nothing was moved",
            src.display()
        )));
    }
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

impl TofuModule {
    pub fn new(runner: Arc<dyn CommandRunner>, dir: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            dir: dir.into(),
            state: None,
            s3: None,
            deny_types: Vec::new(),
        }
    }

    /// Resource types this identity cannot apply: a replace or finish plan that changes one is refused before anything is
    /// stopped ([`check_applicable`]).
    pub fn with_unappliable_types(mut self, types: &[&str]) -> Self {
        self.deny_types = types.iter().map(|t| (*t).to_string()).collect();
        self
    }

    /// Keep this module's state in the bucket (see [`S3State`]). Needs [`with_state_root`](Self::with_state_root) too: the
    /// generated module copy, OpenTofu's working data and the backups live there.
    pub fn with_s3_state(mut self, s3: S3State) -> Self {
        self.s3 = Some(s3);
        self
    }

    /// Whether this module's state is in the bucket.
    pub fn uses_s3(&self) -> bool {
        self.s3.is_some()
    }

    /// The directory OpenTofu runs in: the module itself, or its generated copy when the state is in the bucket.
    fn exec_dir(&self) -> PathBuf {
        match (&self.s3, &self.state) {
            (Some(_), Some(l)) => l.run_dir().join("infra/tofu/modules").join(l.module_name()),
            _ => self.dir.clone(),
        }
    }

    /// Keep this module's state under `state_root` (see [`StateLayout`]) instead of inside the module's directory.
    pub fn with_state_root(mut self, state_root: impl AsRef<Path>) -> Self {
        self.state = Some(StateLayout::new(state_root.as_ref(), &self.dir));
        self
    }

    /// Where the state lives, when it is kept apart from the module.
    pub fn state_layout(&self) -> Option<&StateLayout> {
        self.state.as_ref()
    }

    fn tofu(&self, args: &[&str]) -> CommandSpec {
        let mut c = CommandSpec::new("tofu")
            .arg(format!("-chdir={}", self.exec_dir().display()))
            .args(args.iter().copied());
        if let Some(l) = &self.state {
            let data = if self.s3.is_some() {
                l.data_dir_s3()
            } else {
                l.data_dir()
            };
            c = c.env("TF_DATA_DIR", data.display().to_string());
        }
        c
    }

    /// Initialised, for the calls that do not run `init` themselves: only needed when the state is kept apart, because
    /// its working data directory is then ours and may not have been initialised yet.
    fn ready(&self) -> Result<()> {
        if self.state.is_some() {
            self.init()?;
        }
        Ok(())
    }

    /// `tofu init`, pointing the local backend at the state directory when there is one. `-reconfigure` because the
    /// backend settings are ours to set every time; the state itself was copied by [`StateLayout::migrate_legacy`].
    fn init(&self) -> Result<()> {
        let mut args = vec!["init".to_string(), "-input=false".to_string()];
        if self.state.is_some() {
            self.set_aside_stale_data()?;
        }
        if let Some(s3) = &self.s3 {
            let l = self.state.as_ref().ok_or_else(|| {
                Error::Config("state in the bucket needs the state directory too".into())
            })?;
            s3.validate()?;
            self.require_native_lock()?;
            self.prepare_run_dir(l)?;
            std::fs::create_dir_all(l.data_dir_s3())?;
            args.push("-reconfigure".into());
            args.extend(s3.backend_config(&l.module_name()));
        } else if let Some(l) = &self.state {
            if let Err(e) = l.migrate_legacy(&self.dir) {
                return Err(Error::Provider(format!(
                    "could not move this box's OpenTofu state out of the module folder: {e}"
                )));
            }
            std::fs::create_dir_all(l.data_dir())?;
            std::fs::create_dir_all(l.workspace_dir())?;
            args.push("-reconfigure".into());
            args.push(format!(
                "-backend-config=path={}",
                l.default_state().display()
            ));
            args.push(format!(
                "-backend-config=workspace_dir={}",
                l.workspace_dir().display()
            ));
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        self.runner.run_ok(&self.tofu(&a))?;
        Ok(())
    }

    /// The native S3 lock file needs OpenTofu 1.10 or newer. Refused here, in words, rather than as an unknown-argument error.
    fn require_native_lock(&self) -> Result<()> {
        let out = self
            .runner
            .run_ok(&CommandSpec::new("tofu").args(["version", "-json"]))?;
        let (major, minor) = parse_tofu_version(&out.stdout);
        if (major, minor) < (1, 10) {
            return Err(Error::Config(format!(
                "keeping state in the bucket needs OpenTofu 1.10 or newer (this is {major}.{minor}); update OpenTofu, or keep the state on this computer"
            )));
        }
        Ok(())
    }

    /// Write the module, as OpenTofu runs it when the state is in the bucket: a copy of the module's files with its
    /// `backend "local" {}` made `backend "s3" {}`, and the cloud-init folder the module reads beside it, so every resource
    /// address is exactly what it is with the local backend. Only files that differ are written, and files the module
    /// no longer has are removed, so two runs at once see a whole copy. The real module folder is never written to.
    fn prepare_run_dir(&self, l: &StateLayout) -> Result<()> {
        let dest = self.exec_dir();
        std::fs::create_dir_all(&dest)?;
        let mut kept: Vec<String> = Vec::new();
        let mut swapped = false;
        for e in std::fs::read_dir(&self.dir)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let wanted = name.ends_with(".tf") || name == ".terraform.lock.hcl";
            if !wanted || !e.path().is_file() {
                continue;
            }
            let mut text = std::fs::read_to_string(e.path())?;
            if name.ends_with(".tf") && text.contains(LOCAL_BACKEND) {
                text = text.replace(LOCAL_BACKEND, S3_BACKEND);
                swapped = true;
            }
            write_if_changed(&dest.join(&name), text.as_bytes())?;
            kept.push(name);
        }
        if !swapped {
            return Err(Error::Provider(format!(
                "{} declares no empty local backend, so it cannot be run against the bucket",
                self.dir.display()
            )));
        }
        for e in std::fs::read_dir(&dest)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().is_file() && !kept.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        let cloud_init = self.dir.join("../../../cloud-init");
        if cloud_init.is_dir() {
            copy_tree(&cloud_init, &l.run_dir().join("infra/cloud-init"))?;
        }
        Ok(())
    }

    /// A private copy of the box's state, before and after state surgery. Local state is copied; state in the bucket is
    /// pulled. `None` when the box has no state yet.
    pub fn backup(&self, box_name: &BoxName, label: &str) -> Result<Option<PathBuf>> {
        let Some(l) = &self.state else {
            return Ok(None);
        };
        if self.s3.is_none() {
            return l.backup(box_name, label);
        }
        if !self.has_workspace(box_name)? {
            return Ok(None);
        }
        let json = self.state_pull(box_name)?;
        if state_is_empty(&json) {
            return Ok(None);
        }
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dest = l
            .backups_dir()
            .join(format!("{box_name}-{secs}-{label}.tfstate"));
        write_private(&dest, json.as_bytes())?;
        Ok(Some(dest))
    }

    /// Where the box's state object is in the bucket (`None` when the state is not kept there).
    pub fn remote_key(&self, box_name: &BoxName) -> Option<String> {
        let (_, l) = self.s3.as_ref().zip(self.state.as_ref())?;
        Some(S3State::remote_key(&l.module_name(), box_name))
    }

    /// An install from before the state was kept apart (ADR 0027) leaves a `.terraform/` in the module folder (provider cache
    /// and an `environment` file naming the old workspace). Beside the state now kept elsewhere it makes a non-interactive
    /// `init` stop with "Error asking for state migration action: input is disabled". The folder is moved aside whole, never
    /// deleted, with a note, and OpenTofu starts from its own data directory.
    fn set_aside_stale_data(&self) -> Result<()> {
        let stale = self.dir.join(".terraform");
        if !stale.is_dir() {
            return Ok(());
        }
        let mut to = self.dir.join(".terraform.moved-by-ozbox");
        let mut n = 1;
        while to.exists() {
            n += 1;
            to = self.dir.join(format!(".terraform.moved-by-ozbox-{n}"));
        }
        std::fs::rename(&stale, &to)?;
        let _ = std::fs::write(
            self.dir.join("MOVED-BY-OZBOX-data.txt"),
            "Oz Box moved the old .terraform folder of this module aside (it is no longer used; OpenTofu's working data is in Oz Box's own state directory). Delete it when you are sure.\n",
        );
        Ok(())
    }

    /// The boxes that have a workspace here (in the bucket when the state is there). Read-only; `default` is not a box.
    pub fn workspaces(&self) -> Result<Vec<String>> {
        self.init()?;
        let out = self.runner.run_ok(&self.tofu(&["workspace", "list"]))?;
        Ok(out
            .stdout
            .lines()
            .map(|l| l.trim().trim_start_matches('*').trim().to_string())
            .filter(|n| BoxName::new(n).is_ok())
            .collect())
    }

    /// What the local state of a box holds (`None` when it has none), without running OpenTofu.
    pub fn local_state_summary(&self, box_name: &BoxName) -> Result<Option<StateSummary>> {
        let Some(l) = &self.state else {
            return Ok(None);
        };
        let _ = l.migrate_legacy(&self.dir);
        match std::fs::read_to_string(l.state_file(box_name)) {
            Ok(t) => Ok(Some(StateSummary::of(&t)?)),
            Err(_) => Ok(None),
        }
    }

    /// What the bucket holds for a box (`None` when it has no workspace there, or an empty one). Read-only apart from
    /// selecting the workspace.
    pub fn bucket_state_summary(&self, box_name: &BoxName) -> Result<Option<StateSummary>> {
        if !self.workspaces()?.iter().any(|w| w == box_name.as_str()) {
            return Ok(None);
        }
        let s = self.state_pull(box_name)?;
        if state_is_empty(&s) {
            return Ok(None);
        }
        Ok(Some(StateSummary::of(&s)?))
    }

    /// The boxes whose state is in the local state directory, for `ozbox state migrate --all`.
    pub fn local_boxes(&self) -> Vec<String> {
        let Some(l) = &self.state else {
            return Vec::new();
        };
        let _ = l.migrate_legacy(&self.dir);
        let mut v: Vec<String> = std::fs::read_dir(l.workspace_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("terraform.tfstate").is_file())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| BoxName::new(n).is_ok())
            .collect();
        v.sort();
        v
    }

    /// Copy a box's local state into the bucket (this module must have been built with [`with_s3_state`](Self::with_s3_state)).
    /// Copy, never move: the local files stay where they are. In order: read the local state; make (or select) the box's
    /// workspace in the bucket; refuse if it already holds a *different* state; push; read it back and compare lineage,
    /// serial and resources; plan against the bucket and require that nothing would change. A failure at any step leaves
    /// the local state exactly as it was, and says so.
    pub fn migrate_local_to_s3(&self, vars: &ModuleVars) -> Result<MigrateReport> {
        let (Some(s3), Some(l)) = (&self.s3, &self.state) else {
            return Err(Error::Config(
                "migrating needs the state bucket and the state directory to be set".into(),
            ));
        };
        let name = &vars.box_name;
        let remote = S3State::remote_key(&l.module_name(), name);
        let _ = l.migrate_legacy(&self.dir);
        let local_file = l.state_file(name);
        let local = std::fs::read_to_string(&local_file).map_err(|_| {
            Error::Provider(format!(
                "{name} has no OpenTofu state on this computer to copy. If it is already in the bucket there is nothing to do; if neither has it, `ozbox adopt {name}` rebuilds it."
            ))
        })?;
        let want = StateSummary::of(&local)?;
        if want.resources == 0 {
            return Err(Error::Provider(format!(
                "the state of {name} on this computer holds no resources, so there is nothing to copy"
            )));
        }
        let backup = l
            .backup(name, "migrate-before")?
            .map(|p| p.display().to_string());
        self.workspace_create(name)?;
        let present = self.state_pull(name)?;
        let mut already = false;
        let stale = !state_is_empty(&present)
            && {
                let p = StateSummary::of(&present)?;
                // an earlier copy of this same state, left behind by a change made here since: brought up to date
                if p == want {
                    already = true;
                    false
                } else if p.lineage == want.lineage && p.serial < want.serial {
                    true
                } else {
                    return Err(Error::Provider(format!(
                    "{name} already has a different state in the bucket (s3://{}/{remote}). Nothing was copied and nothing was changed; decide which one is right before going on.",
                    s3.bucket
                )));
                }
            };
        if state_is_empty(&present) || stale {
            self.state_push(name, &local)?;
            let back = self.state_pull(name)?;
            if StateSummary::of(&back)? != want {
                return Err(Error::Provider(format!(
                    "the copy of {name} in the bucket did not read back the same, so it was not trusted. The state on this computer is untouched and stays in use."
                )));
            }
        }
        let shown = self.plan_show(vars)?;
        if let Err(e) = check_noop_plan(&shown) {
            return Err(Error::Provider(format!(
                "{e} The state on this computer is untouched and stays in use; the copy in the bucket was left (it can be removed by deleting s3://{}/{remote}).",
                s3.bucket
            )));
        }
        let note = format!(
            "Oz Box copied the OpenTofu state of {name} to s3://{}/{remote}.\nThat copy is the live one once the configuration says `state_backend = \"s3\"`. This file was left as it was and is no longer used then; keep it until you are sure.\n",
            s3.bucket
        );
        let _ = std::fs::write(local_file.with_file_name("MIGRATED-TO-S3.txt"), note);
        Ok(MigrateReport {
            box_name: name.to_string(),
            serial: want.serial,
            resources: want.resources,
            remote_key: remote,
            backup,
            already_there: already,
        })
    }

    /// The `-var` arguments for `vars`, exactly as they are passed to tofu.
    pub fn var_args(vars: &ModuleVars) -> Vec<String> {
        let mut a = vec![
            "-var".to_string(),
            format!("box_name={}", vars.box_name),
            "-var".into(),
            format!("machine_type={}", vars.machine_type),
            "-var".into(),
            format!("work_disk_gb={}", vars.work_disk_gb),
            "-var".into(),
            format!("image_id={}", vars.image_id),
        ];
        if let Some(r) = &vars.region {
            a.push("-var".into());
            a.push(format!("region={r}"));
        }
        a.push("-var".into());
        a.push(format!("labels={}", hcl_map(&vars.labels)));
        if let Some(s) = &vars.work_snapshot_id {
            a.push("-var".into());
            a.push(format!("work_snapshot_id={s}"));
        }
        for (k, v) in &vars.extra {
            a.push("-var".into());
            a.push(format!("{k}={v}"));
        }
        a
    }

    /// init, select (or create) the box's workspace, apply, and read the outputs.
    pub fn apply(&self, vars: &ModuleVars) -> Result<ModuleOutputs> {
        self.init()?;
        self.runner.run_ok(&self.tofu(&[
            "workspace",
            "select",
            "-or-create",
            vars.box_name.as_str(),
        ]))?;
        self.runner.run_ok(
            &self
                .tofu(&["apply", "-auto-approve", "-input=false"])
                .args(Self::var_args(vars)),
        )?;
        let out = self.runner.run_ok(&self.tofu(&["output", "-json"]))?;
        parse_outputs(&out.stdout)
    }

    /// `init`, select the EXISTING workspace of a box, run `plan -out` (with `-replace=<replace>` when given) into a
    /// private file, and return the plan with what OpenTofu says it contains. A box this module never made is not
    /// touched: its workspace must already exist.
    fn plan_to_file(
        &self,
        vars: &ModuleVars,
        replace: Option<&str>,
    ) -> Result<(ReplacePlan, String)> {
        self.init()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", vars.box_name.as_str()]))
            .map_err(|_| {
                if self.s3.is_some() {
                    let local = self
                        .state
                        .as_ref()
                        .is_some_and(|l| l.state_file(&vars.box_name).is_file());
                    return Error::Provider(if local {
                        format!(
                            "box {0} has its OpenTofu state on this computer but not in the bucket the configuration points at. `ozbox state migrate {0}` copies it there (it keeps the local copy).",
                            vars.box_name
                        )
                    } else {
                        format!(
                            "no OpenTofu state for box {0} in the bucket. If the box exists in your cloud account, `ozbox adopt {0}` rebuilds the state from its resources (it changes nothing in the cloud).",
                            vars.box_name
                        )
                    });
                }
                Error::Provider(format!(
                    "no OpenTofu state for box {} on this computer, so it cannot be rebuilt from here. If the box exists in your cloud account, `ozbox adopt {}` rebuilds the state from its resources (it changes nothing in the cloud).",
                    vars.box_name,
                    vars.box_name
                ))
            })?;
        let file = std::env::temp_dir().join(format!(
            "ozbox-{}-{}-{}.tfplan",
            vars.box_name,
            std::process::id(),
            PLAN_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let file_arg = file.display().to_string();
        let plan = ReplacePlan {
            file,
            summary: Vec::new(),
        };
        let mut args = vec![
            "plan".to_string(),
            "-input=false".to_string(),
            format!("-out={file_arg}"),
        ];
        if let Some(r) = replace {
            args.push(format!("-replace={r}"));
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.runner
            .run_ok(&self.tofu(&args).args(Self::var_args(vars)))?;
        let shown = self
            .runner
            .run_ok(&self.tofu(&["show", "-json", &file_arg]))?;
        Ok((plan, shown.stdout))
    }

    /// Plan (read-only) the replacement of one resource of an EXISTING box, with the plan written to a private file,
    /// and refuse unless the plan replaces `replace`, destroys nothing outside `may_replace`, and neither deletes nor
    /// creates any `protected` resource. The workspace must already exist.
    pub fn plan_replace(
        &self,
        vars: &ModuleVars,
        replace: &str,
        may_replace: &[&str],
        protected: &[&str],
    ) -> Result<ReplacePlan> {
        let (mut plan, shown) = self.plan_to_file(vars, Some(replace))?;
        check_applicable(&shown, &self.deny_types)?;
        check_protected(&shown, protected)?;
        plan.summary = check_replace_plan(&shown, replace, may_replace)?;
        Ok(plan)
    }

    /// Plan (read-only) the creation of the machine of a box whose machine is gone (an interrupted replacement),
    /// with no `-replace`: refuse unless the plan creates `create` and destroys nothing at all, creates nothing
    /// outside `may_create`, and neither deletes nor creates any `protected` resource.
    pub fn plan_finish(
        &self,
        vars: &ModuleVars,
        create: &str,
        may_create: &[&str],
        protected: &[&str],
    ) -> Result<ReplacePlan> {
        let (mut plan, shown) = self.plan_to_file(vars, None)?;
        check_applicable(&shown, &self.deny_types)?;
        check_protected(&shown, protected)?;
        plan.summary = check_finish_plan(&shown, create, may_create)?;
        Ok(plan)
    }

    /// Plan (read-only) a change to a box that replaces nothing: refuse unless it only updates resources in place and
    /// creates or destroys at most the ones named. Apply the result with [`TofuModule::apply_replace`].
    pub fn plan_in_place(
        &self,
        vars: &ModuleVars,
        may_create: &[&str],
        may_delete: &[&str],
        protected: &[&str],
        fleet: FleetTag<'_>,
    ) -> Result<ReplacePlan> {
        let (mut plan, shown) = self.plan_to_file(vars, None)?;
        // the same refusal as every other plan: a resource type the operator role cannot apply fails before anything is touched
        check_applicable(&shown, &self.deny_types)?;
        plan.summary = check_inplace_plan_for(&shown, may_create, may_delete, protected, fleet)?;
        Ok(plan)
    }

    /// Apply a plan made by [`TofuModule::plan_replace`] or [`TofuModule::plan_finish`] and read the outputs.
    pub fn apply_replace(&self, plan: &ReplacePlan) -> Result<ModuleOutputs> {
        self.runner.run_ok(&self.tofu(&[
            "apply",
            "-input=false",
            &plan.file.display().to_string(),
        ]))?;
        let out = self.runner.run_ok(&self.tofu(&["output", "-json"]))?;
        parse_outputs(&out.stdout)
    }

    /// Plan, read-only, replacing `volume` with the snapshot in `vars`, and refuse unless only the volume (and what
    /// is in `may_replace`) changes. The plan is never applied: its file is removed.
    pub fn preview_restore(
        &self,
        vars: &ModuleVars,
        volume: &str,
        may_replace: &[&str],
    ) -> Result<Vec<String>> {
        let (_plan, shown) = self.plan_to_file(vars, Some(volume))?;
        check_restore_preview(&shown, volume, may_replace)
    }

    /// Plan with no `-replace`, for after the old volume left the state, and refuse unless it only creates the
    /// resources in `create`.
    pub fn plan_restore(&self, vars: &ModuleVars, create: &[&str]) -> Result<ReplacePlan> {
        let (mut plan, shown) = self.plan_to_file(vars, None)?;
        plan.summary = check_restore_apply(&shown, create)?;
        Ok(plan)
    }

    /// The addresses in the box's state. The workspace must exist.
    pub fn state_list(&self, box_name: &BoxName) -> Result<Vec<String>> {
        self.init()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", box_name.as_str()]))?;
        let out = self.runner.run_ok(&self.tofu(&["state", "list"]))?;
        Ok(out
            .stdout
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// One attribute of one resource in the box's state (`tofu state show`), `None` when absent.
    pub fn state_attribute(
        &self,
        box_name: &BoxName,
        address: &str,
        key: &str,
    ) -> Result<Option<String>> {
        self.ready()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", box_name.as_str()]))?;
        let out = self
            .runner
            .run_ok(&self.tofu(&["state", "show", "-no-color", address]))?;
        Ok(state_attribute(&out.stdout, key))
    }

    /// Forget resources in the box's state WITHOUT touching what they are in the cloud.
    pub fn state_rm(&self, box_name: &BoxName, addresses: &[&str]) -> Result<()> {
        self.ready()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", box_name.as_str()]))?;
        let mut args = vec!["state", "rm"];
        args.extend_from_slice(addresses);
        self.runner.run_ok(&self.tofu(&args))?;
        Ok(())
    }

    /// Put an existing cloud resource back in the box's state.
    pub fn state_import(&self, vars: &ModuleVars, address: &str, id: &str) -> Result<()> {
        self.ready()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", vars.box_name.as_str()]))?;
        self.runner.run_ok(
            &self
                .tofu(&["import", "-input=false"])
                .args(Self::var_args(vars))
                .arg(address)
                .arg(id),
        )?;
        Ok(())
    }

    /// Create the box's (empty) workspace if it does not exist, and select it.
    pub fn workspace_create(&self, box_name: &BoxName) -> Result<()> {
        self.init()?;
        self.runner.run_ok(&self.tofu(&[
            "workspace",
            "select",
            "-or-create",
            box_name.as_str(),
        ]))?;
        Ok(())
    }

    /// The box's state as JSON (`tofu state pull`). The workspace must exist.
    pub fn state_pull(&self, box_name: &BoxName) -> Result<String> {
        self.ready()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", box_name.as_str()]))?;
        Ok(self.runner.run_ok(&self.tofu(&["state", "pull"]))?.stdout)
    }

    /// Replace the box's state with `json` (`tofu state push`, read from standard input). OpenTofu refuses a state whose
    /// serial is older than the current one, so a caller edits a pulled state and raises its serial.
    pub fn state_push(&self, box_name: &BoxName, json: &str) -> Result<()> {
        self.ready()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", box_name.as_str()]))?;
        self.runner.run_ok(
            &self
                .tofu(&["state", "push", "-"])
                .stdin(json.as_bytes().to_vec()),
        )?;
        Ok(())
    }

    /// Plan against the box's state with no `-replace`, write nothing but a private plan file, and return it as JSON.
    /// Read-only: nothing is applied.
    pub fn plan_show(&self, vars: &ModuleVars) -> Result<String> {
        let (plan, shown) = self.plan_to_file(vars, None)?;
        let _ = std::fs::remove_file(&plan.file);
        Ok(shown)
    }

    /// Whether this computer holds the OpenTofu workspace (the state) of the box. Read-only.
    pub fn has_workspace(&self, box_name: &BoxName) -> Result<bool> {
        self.init()?;
        let out = self.runner.run_ok(&self.tofu(&["workspace", "list"]))?;
        Ok(out
            .stdout
            .lines()
            .any(|l| l.trim().trim_start_matches('*').trim() == box_name.as_str()))
    }

    /// Destroy the box's resources, then drop its (now empty) workspace.
    pub fn destroy(&self, vars: &ModuleVars) -> Result<()> {
        self.init()?;
        self.runner
            .run_ok(&self.tofu(&["workspace", "select", vars.box_name.as_str()]))?;
        self.runner.run_ok(
            &self
                .tofu(&["destroy", "-auto-approve", "-input=false"])
                .args(Self::var_args(vars)),
        )?;
        // Housekeeping only: the box is already gone, so a failure here must not read as a failed destroy.
        let _ = self
            .runner
            .run(&self.tofu(&["workspace", "select", "default"]));
        let _ = self
            .runner
            .run(&self.tofu(&["workspace", "delete", vars.box_name.as_str()]));
        Ok(())
    }
}

fn parse_outputs(stdout: &str) -> Result<ModuleOutputs> {
    let v: serde_json::Value = serde_json::from_str(stdout)?;
    let get = |k: &str| -> Option<String> {
        v.get(k)
            .and_then(|o| o.get("value"))
            .and_then(|x| x.as_str())
            .map(str::to_string)
    };
    let machine_id = get("machine_id").ok_or_else(|| {
        Error::Provider("the box module did not return a machine_id output".into())
    })?;
    Ok(ModuleOutputs {
        machine_id,
        work_volume_id: get("work_volume_id"),
        machine_type: get("machine_type"),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn a_plan_that_needs_what_the_identity_cannot_do_is_refused_before_anything_is_stopped() {
        let plan = |ty: &str, actions: &str| {
            format!(
                r#"{{"resource_changes":[{{"address":"aws_instance.box","type":"aws_instance","change":{{"actions":["delete","create"]}}}},{{"address":"{ty}.x[0]","type":"{ty}","change":{{"actions":[{actions}]}}}}]}}"#
            )
        };
        let deny = vec![
            "aws_iam_role_policy".to_string(),
            "aws_iam_policy".to_string(),
        ];
        // creating, changing or destroying one is refused, with the address and what to do
        for a in [
            r#""create""#,
            r#""update""#,
            r#""delete""#,
            r#""delete","create""#,
        ] {
            let e = check_applicable(&plan("aws_iam_role_policy", a), &deny)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("aws_iam_role_policy.x[0]") && e.contains("Nothing was stopped"),
                "{e}"
            );
        }
        // an unchanged one, a read, another type and no list at all pass
        assert!(check_applicable(&plan("aws_iam_role_policy", r#""no-op""#), &deny).is_ok());
        assert!(check_applicable(&plan("aws_iam_role_policy", r#""read""#), &deny).is_ok());
        assert!(check_applicable(
            &plan("aws_iam_role_policy_attachment", r#""create""#),
            &deny
        )
        .is_ok());
        assert!(check_applicable(&plan("aws_iam_role_policy", r#""create""#), &[]).is_ok());
        assert!(check_applicable("not json", &deny).is_err());
    }

    use super::*;
    use crate::{Output, RecordingRunner};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn vars() -> Result<ModuleVars> {
        let mut labels = BTreeMap::new();
        labels.insert("purpose".to_string(), "a \"q\" ${x}".to_string());
        Ok(ModuleVars {
            box_name: BoxName::new("main")?,
            machine_type: "ccx33".into(),
            work_disk_gb: 200,
            image_id: "img-1".into(),
            region: Some("fsn1".into()),
            labels,
            work_snapshot_id: None,
            extra: BTreeMap::new(),
        })
    }

    #[test]
    fn apply_runs_the_contract_sequence_as_argv() -> TestResult {
        let r = Arc::new(RecordingRunner::new());
        for _ in 0..3 {
            r.reply(Output {
                status: Some(0),
                ..Output::default()
            });
        }
        r.reply(Output {
            status: Some(0),
            stdout: r#"{"machine_id":{"value":"42"},"work_volume_id":{"value":"7"},"machine_type":{"value":"ccx33"}}"#.into(),
            stderr: String::new(),
        });
        let m = TofuModule::new(r.clone(), "infra/tofu/modules/x-box");
        let out = m.apply(&vars()?)?;
        assert_eq!(out.machine_id, "42");
        assert_eq!(out.work_volume_id.as_deref(), Some("7"));
        let calls = r.calls();
        assert_eq!(calls.len(), 4);
        assert!(calls.iter().all(|c| c.program == "tofu"));
        assert_eq!(
            calls[1].args,
            [
                "-chdir=infra/tofu/modules/x-box",
                "workspace",
                "select",
                "-or-create",
                "main"
            ]
        );
        let apply = &calls[2].args;
        assert!(apply.contains(&"box_name=main".to_string()));
        assert!(apply.contains(&"region=fsn1".to_string()));
        assert!(!apply.iter().any(|a| a.starts_with("work_snapshot_id")));
        assert!(apply.contains(&r#"labels={"purpose"="a \"q\" $${x}"}"#.to_string()));
        assert_eq!(
            calls[3].args,
            ["-chdir=infra/tofu/modules/x-box", "output", "-json"]
        );
        Ok(())
    }

    const PLAN_OK: &str = r#"{"resource_changes":[
        {"address":"aws_instance.box","change":{"actions":["delete","create"]}},
        {"address":"aws_volume_attachment.work","change":{"actions":["delete","create"]}},
        {"address":"aws_ebs_volume.work","change":{"actions":["update"]}},
        {"address":"aws_security_group.box","change":{"actions":["no-op"]}}]}"#;

    #[test]
    fn a_replace_plan_may_replace_the_machine_and_its_attachment_only() -> TestResult {
        let ok = check_replace_plan(PLAN_OK, "aws_instance.box", &["aws_volume_attachment.work"])?;
        assert_eq!(ok.len(), 3, "no-ops are not listed: {ok:?}");
        // The volume replaced: refused, naming it.
        let bad = PLAN_OK.replace(
            r#"{"address":"aws_ebs_volume.work","change":{"actions":["update"]}}"#,
            r#"{"address":"aws_ebs_volume.work","change":{"actions":["delete","create"]}}"#,
        );
        match check_replace_plan(&bad, "aws_instance.box", &["aws_volume_attachment.work"]) {
            Err(Error::Provider(m)) => assert!(m.contains("aws_ebs_volume.work"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // Create-before-destroy order counts as a replacement too.
        let cbd = PLAN_OK.replacen(r#"["delete","create"]"#, r#"["create","delete"]"#, 1);
        assert!(
            check_replace_plan(&cbd, "aws_instance.box", &["aws_volume_attachment.work"]).is_ok()
        );
        Ok(())
    }

    const PLAN_GRANT: &str = r#"{"resource_changes":[
        {"address":"aws_iam_role_policy_attachment.fleet_key[0]","change":{"actions":["create"]}},
        {"address":"aws_iam_role.box","change":{"actions":["update"],"before":{"tags":{"ozbox-secrets-adopt":"1"}},"after":{"tags":{"ozbox-secrets-adopt":"2"}}}},
        {"address":"aws_instance.box","change":{"actions":["update"],"before":{"tags":{"ozbox-secrets-adopt":"1"}},"after":{"tags":{"ozbox-secrets-adopt":"2"}}}},
        {"address":"aws_ebs_volume.work","change":{"actions":["update"],"before":{"tags":{"ozbox-secrets-adopt":"1"}},"after":{"tags":{"ozbox-secrets-adopt":"2"}}}},
        {"address":"aws_security_group.box","change":{"actions":["no-op"]}}]}"#;

    #[test]
    fn an_in_place_plan_may_update_and_create_only_what_it_names() -> TestResult {
        let create = ["aws_iam_role_policy_attachment.fleet_key[0]"];
        let protected = ["aws_ebs_volume.work", "aws_instance.box"];
        let ok = check_inplace_plan(PLAN_GRANT, &create, &[], &protected)?;
        assert_eq!(ok.len(), 4, "no-ops are not listed: {ok:?}");
        // a creation nobody named is refused
        assert!(check_inplace_plan(PLAN_GRANT, &[], &[], &protected).is_err());
        // a replacement is never in place, whatever is allowed to be created or destroyed
        let replaced = PLAN_GRANT.replace(
            r#"{"address":"aws_instance.box","change":{"actions":["update"],"before":{"tags":{"ozbox-secrets-adopt":"1"}},"after":{"tags":{"ozbox-secrets-adopt":"2"}}}}"#,
            r#"{"address":"aws_instance.box","change":{"actions":["delete","create"]}}"#,
        );
        match check_inplace_plan(&replaced, &create, &["aws_instance.box"], &[]) {
            Err(Error::Provider(m)) => assert!(m.contains("aws_instance.box"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // a destroy is refused unless named (taking the grant back is the one destroy the cancel makes)
        let revoke = r#"{"resource_changes":[
            {"address":"aws_iam_role_policy_attachment.fleet_key[0]","change":{"actions":["delete"]}}]}"#;
        assert!(check_inplace_plan(revoke, &[], &[], &protected).is_err());
        assert!(check_inplace_plan(revoke, &[], &create, &protected).is_ok());
        // the /work volume is never created or destroyed, even when someone names it by mistake
        let vol = r#"{"resource_changes":[
            {"address":"aws_ebs_volume.work","change":{"actions":["delete"]}}]}"#;
        assert!(check_inplace_plan(vol, &[], &["aws_ebs_volume.work"], &protected).is_err());
        assert!(check_inplace_plan("not json", &[], &[], &[]).is_err());
        Ok(())
    }

    /// L6: an update is allowed to change tags, not the machine. A stale spec or a module that moved on must be refused.
    #[test]
    fn an_in_place_update_that_changes_the_machine_is_refused() {
        let tags_only = r#"{"resource_changes":[
            {"address":"aws_instance.box","change":{"actions":["update"],
             "before":{"instance_type":"m7i.xlarge","tags":{"ozbox-secrets-adopt":"1"},"tags_all":{"ozbox-secrets-adopt":"1"}},
             "after":{"instance_type":"m7i.xlarge","tags":{"ozbox-secrets-adopt":"2"},"tags_all":{"ozbox-secrets-adopt":"2"}}}}]}"#;
        assert!(check_inplace_plan(tags_only, &[], &[], &[]).is_ok());
        for (key, was, now) in [
            ("instance_type", r#""m7i.xlarge""#, r#""m7i.2xlarge""#),
            ("ami", r#""ami-1""#, r#""ami-2""#),
            ("iops", "3000", "16000"),
            ("size", "100", "200"),
        ] {
            let plan = format!(
                r#"{{"resource_changes":[{{"address":"aws_instance.box","change":{{"actions":["update"],"before":{{"{key}":{was}}},"after":{{"{key}":{now}}}}}}}]}}"#
            );
            match check_inplace_plan(&plan, &[], &[], &[]) {
                Err(Error::Provider(m)) => {
                    assert!(m.contains(&format!("aws_instance.box.{key}")), "{m}")
                }
                other => panic!("{key}: expected a refusal, got {other:?}"),
            }
        }
        // the role's fleet-key attachment (its policy_arn) is allowed to change
        let policy = r#"{"resource_changes":[
            {"address":"aws_iam_role_policy_attachment.fleet_key[0]","change":{"actions":["update"],
             "before":{"policy_arn":"a"},"after":{"policy_arn":"b"}}}]}"#;
        assert!(check_inplace_plan(
            policy,
            &["aws_iam_role_policy_attachment.fleet_key[0]"],
            &[],
            &[]
        )
        .is_ok());
        // but only that one, which this change names; another role policy is not its business
        assert!(check_inplace_plan(policy, &[], &[], &[]).is_err());
        assert!(check_inplace_plan(policy, &["aws_iam_role_policy.other"], &[], &[]).is_err());
    }

    /// N4: the guard is an ALLOWLIST. Anything an update changes that is not a tag (or the named policy) is refused, whether or
    /// not anyone thought of it: the metadata options the box needs to read its own tags, API stop protection, monitoring, a
    /// security group's rules, another role's policy, an attribute only known after apply.
    #[test]
    fn an_in_place_update_may_change_tags_and_the_named_policy_and_nothing_else() {
        let one = |addr: &str, before: &str, after: &str, unknown: &str| {
            format!(
                r#"{{"resource_changes":[{{"address":"{addr}","change":{{"actions":["update"],"before":{before},"after":{after},"after_unknown":{unknown}}}}}]}}"#
            )
        };
        let create = ["aws_iam_role_policy_attachment.fleet_key[0]"];
        for (addr, key, was, now) in [
            (
                "aws_instance.box",
                "metadata_options",
                r#"[{"instance_metadata_tags":"enabled"}]"#,
                r#"[{"instance_metadata_tags":"disabled"}]"#,
            ),
            ("aws_instance.box", "disable_api_stop", "true", "false"),
            ("aws_instance.box", "monitoring", "false", "true"),
            (
                "aws_instance.box",
                "associate_public_ip_address",
                "false",
                "true",
            ),
            ("aws_ebs_volume.work", "final_snapshot", "false", "true"),
            (
                "aws_security_group.box",
                "ingress",
                "[]",
                r#"[{"from_port":22}]"#,
            ),
            (
                "aws_iam_role_policy_attachment.fleet_key[0]",
                "role",
                r#""a""#,
                r#""b""#,
            ),
            ("aws_iam_role.box", "assume_role_policy", r#""a""#, r#""b""#),
            (
                "aws_iam_role_policy.box_secrets[0]",
                "policy",
                r#""a""#,
                r#""b""#,
            ),
        ] {
            let plan = one(
                addr,
                &format!("{{\"{key}\":{was}}}"),
                &format!("{{\"{key}\":{now}}}"),
                "{}",
            );
            match check_inplace_plan(&plan, &create, &[], &[]) {
                Err(Error::Provider(m)) => assert!(m.contains(&format!("{addr}.{key}")), "{m}"),
                other => panic!("{addr}.{key}: expected a refusal, got {other:?}"),
            }
        }
        // an attribute added or removed counts, and so does one only known after apply
        for (before, after, unknown) in [
            ("{}", r#"{"monitoring":true}"#, "{}"),
            (r#"{"monitoring":true}"#, "{}", "{}"),
            ("{}", "{}", r#"{"private_ip":true}"#),
            ("{}", "{}", r#"{"root_block_device":[{"volume_id":true}]}"#),
        ] {
            let plan = one("aws_instance.box", before, after, unknown);
            assert!(
                check_inplace_plan(&plan, &create, &[], &[]).is_err(),
                "{plan}"
            );
        }
        // tags may change, including the ones computed from them
        let ok = one(
            "aws_instance.box",
            r#"{"tags":{"ozbox-secrets-adopt":"1"},"tags_all":{"ozbox-secrets-adopt":"1"}}"#,
            r#"{"tags":{"ozbox-secrets-adopt":"2"},"tags_all":{"ozbox-secrets-adopt":"2"}}"#,
            r#"{"tags_all":true}"#,
        );
        assert!(check_inplace_plan(&ok, &create, &[], &[]).is_ok());
        // R5: tags are compared key by key. Only the keys this change manages may change, and `ozbox-managed` (the Systems Manager
        // target condition), the role's fleet tag rewritten to another fleet, and any other key may not.
        for (before, after, why) in [
            (
                r#"{"tags":{"ozbox-managed":"true"}}"#,
                r#"{"tags":{"ozbox-managed":"false"}}"#,
                "managed flipped",
            ),
            (
                r#"{"tags":{"ozbox-managed":"true"}}"#,
                r#"{"tags":{}}"#,
                "managed removed",
            ),
            (
                r#"{"tags":{}}"#,
                r#"{"tags":{"ozbox-managed":"true"}}"#,
                "managed added",
            ),
            (
                r#"{"tags":{"ozbox-fleet":"dev"}}"#,
                r#"{"tags":{"ozbox-fleet":"prod"}}"#,
                "fleet rewritten",
            ),
            (
                r#"{"tags":{"team":"a"}}"#,
                r#"{"tags":{"team":"b"}}"#,
                "another key",
            ),
            (
                r#"{"tags_all":{"x":"1"}}"#,
                r#"{"tags_all":{"x":"2"}}"#,
                "tags_all too",
            ),
            (r#"{"tags":"a"}"#, r#"{"tags":{}}"#, "not a map"),
        ] {
            let plan = one("aws_instance.box", before, after, "{}");
            assert!(
                check_inplace_plan(&plan, &create, &[], &[]).is_err(),
                "{why}: {plan}"
            );
        }
        for (before, after, why) in [
            (
                r#"{"tags":{}}"#,
                r#"{"tags":{"ozbox-secrets-adopt":"arn"}}"#,
                "adopt label added",
            ),
            (
                r#"{"tags":{"ozbox-secrets-adopt":"arn"}}"#,
                r#"{"tags":{"ozbox-secrets-key":"arn"}}"#,
                "label swapped",
            ),
            (
                r#"{"tags":{"ozbox-secrets-key":"arn"}}"#,
                r#"{"tags":{}}"#,
                "label removed",
            ),
            (
                r#"{"tags":{"ozbox-managed":"true"}}"#,
                r#"{"tags":{"ozbox-managed":"true","ozbox-fleet":"dev"}}"#,
                "fleet added",
            ),
            (
                r#"{"tags":null}"#,
                r#"{"tags":{"ozbox-fleet":"dev"}}"#,
                "null to a map",
            ),
        ] {
            let plan = one("aws_iam_role.box", before, after, "{}");
            assert!(
                check_inplace_plan(&plan, &create, &[], &[]).is_ok(),
                "{why}: {plan}"
            );
        }
        // S7: told which fleet the change is for, the role's fleet tag may take only that value, and only a role carries it
        let fleet = |addr: &str, before: &str, after: &str, want: FleetTag<'_>| {
            check_inplace_plan_for(&one(addr, before, after, "{}"), &create, &[], &[], want).is_ok()
        };
        let none = r#"{"tags":{}}"#;
        let dev = r#"{"tags":{"ozbox-fleet":"dev"}}"#;
        let other = r#"{"tags":{"ozbox-fleet":"other"}}"#;
        assert!(fleet(
            "aws_iam_role.box",
            none,
            dev,
            FleetTag::Is(Some("dev"))
        ));
        assert!(
            !fleet("aws_iam_role.box", none, other, FleetTag::Is(Some("dev"))),
            "another fleet's name"
        );
        assert!(
            !fleet("aws_instance.box", none, dev, FleetTag::Is(Some("dev"))),
            "not on a machine"
        );
        assert!(
            !fleet("aws_iam_role.box", none, dev, FleetTag::Is(None)),
            "no fleet is asked for"
        );
        // taking it away is always fine (a cancel), and Any keeps the pure check unchanged
        assert!(fleet("aws_iam_role.box", dev, none, FleetTag::Is(None)));
        assert!(fleet("aws_iam_role.box", none, other, FleetTag::Any));
        // a key known only after apply is a change nobody can vouch for
        let plan = one(
            "aws_instance.box",
            r#"{"tags":{}}"#,
            r#"{"tags":{}}"#,
            r#"{"tags":{"ozbox-managed":true}}"#,
        );
        assert!(check_inplace_plan(&plan, &create, &[], &[]).is_err());
        // R5: an action that is not create, delete or update (OpenTofu's `forget`) is never in place
        for acts in [
            r#"["forget"]"#,
            r#"["update","forget"]"#,
            r#"["noop"]"#,
            r#"["move"]"#,
        ] {
            let plan = format!(
                r#"{{"resource_changes":[{{"address":"aws_instance.box","change":{{"actions":{acts}}}}}]}}"#
            );
            match check_inplace_plan(&plan, &create, &[], &[]) {
                Err(Error::Provider(m)) => assert!(m.contains("aws_instance.box"), "{m}"),
                other => panic!("{acts}: expected a refusal, got {other:?}"),
            }
        }
        // a plan whose change cannot be read is never "nothing changed"
        let unreadable = r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["update"]}}]}"#;
        assert!(check_inplace_plan(unreadable, &create, &[], &[]).is_err());
    }

    #[test]
    fn a_plan_that_does_not_replace_the_machine_is_refused() {
        let none = r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["no-op"]}}]}"#;
        assert!(check_replace_plan(none, "aws_instance.box", &[]).is_err());
        assert!(check_replace_plan("{}", "aws_instance.box", &[]).is_err());
        assert!(check_replace_plan("not json", "aws_instance.box", &[]).is_err());
    }

    const PLAN_FINISH: &str = r#"{"resource_changes":[
        {"address":"aws_instance.box","change":{"actions":["create"]}},
        {"address":"aws_volume_attachment.work","change":{"actions":["create"]}},
        {"address":"aws_ebs_volume.work","change":{"actions":["no-op"]}},
        {"address":"aws_security_group.box","change":{"actions":["no-op"]}}]}"#;

    #[test]
    fn finishing_an_upgrade_creates_the_machine_and_its_attachment_and_destroys_nothing(
    ) -> TestResult {
        let ok = check_finish_plan(
            PLAN_FINISH,
            "aws_instance.box",
            &["aws_volume_attachment.work"],
        )?;
        assert_eq!(ok.len(), 2, "{ok:?}");
        check_protected(PLAN_FINISH, &["aws_ebs_volume.work"])?;
        // a tags-only update of the volume is fine
        let upd = PLAN_FINISH.replace(
            r#""address":"aws_ebs_volume.work","change":{"actions":["no-op"]}"#,
            r#""address":"aws_ebs_volume.work","change":{"actions":["update"]}"#,
        );
        check_protected(&upd, &["aws_ebs_volume.work"])?;
        check_finish_plan(&upd, "aws_instance.box", &["aws_volume_attachment.work"])?;
        Ok(())
    }

    #[test]
    fn the_work_volume_is_never_deleted_replaced_or_newly_created() {
        for actions in [r#"["delete"]"#, r#"["delete","create"]"#, r#"["create"]"#] {
            let bad = PLAN_FINISH.replace(
                r#""address":"aws_ebs_volume.work","change":{"actions":["no-op"]}"#,
                &format!(r#""address":"aws_ebs_volume.work","change":{{"actions":{actions}}}"#),
            );
            match check_protected(&bad, &["aws_ebs_volume.work"]) {
                Err(Error::Provider(m)) => assert!(m.contains("aws_ebs_volume.work"), "{m}"),
                other => panic!("{actions}: expected a refusal, got {other:?}"),
            }
            // and the same plan is refused as a replacement
            assert!(check_protected(
                &PLAN_OK.replace(
                    r#""address":"aws_ebs_volume.work","change":{"actions":["update"]}"#,
                    &format!(r#""address":"aws_ebs_volume.work","change":{{"actions":{actions}}}"#),
                ),
                &["aws_ebs_volume.work"]
            )
            .is_err());
        }
    }

    #[test]
    fn a_finish_plan_that_destroys_or_creates_anything_else_is_refused() {
        let destroys = PLAN_FINISH.replace(
            r#""address":"aws_security_group.box","change":{"actions":["no-op"]}"#,
            r#""address":"aws_security_group.box","change":{"actions":["delete","create"]}"#,
        );
        assert!(check_finish_plan(
            &destroys,
            "aws_instance.box",
            &["aws_volume_attachment.work"]
        )
        .is_err());
        let extra = PLAN_FINISH.replace(
            r#""address":"aws_security_group.box","change":{"actions":["no-op"]}"#,
            r#""address":"aws_iam_role.box","change":{"actions":["create"]}"#,
        );
        assert!(
            check_finish_plan(&extra, "aws_instance.box", &["aws_volume_attachment.work"]).is_err()
        );
        // a machine that is REPLACED (still in state) is not "finishing"
        assert!(
            check_finish_plan(PLAN_OK, "aws_instance.box", &["aws_volume_attachment.work"])
                .is_err()
        );
        assert!(check_finish_plan("not json", "aws_instance.box", &[]).is_err());
    }

    const RESTORE_PREVIEW: &str = r#"{"resource_changes":[
        {"address":"aws_instance.box","change":{"actions":["no-op"]}},
        {"address":"aws_volume_attachment.work","change":{"actions":["delete","create"]}},
        {"address":"aws_ebs_volume.work","change":{"actions":["delete","create"]}}]}"#;

    #[test]
    fn a_restore_preview_replaces_the_volume_and_its_attachment_and_never_the_machine() -> TestResult
    {
        let ok = check_restore_preview(
            RESTORE_PREVIEW,
            "aws_ebs_volume.work",
            &["aws_volume_attachment.work"],
        )?;
        assert_eq!(ok.len(), 2, "{ok:?}");
        // The machine would be replaced (its user data changed): refused, naming it.
        let machine = RESTORE_PREVIEW.replace(
            r#"{"address":"aws_instance.box","change":{"actions":["no-op"]}}"#,
            r#"{"address":"aws_instance.box","change":{"actions":["delete","create"]}}"#,
        );
        match check_restore_preview(
            &machine,
            "aws_ebs_volume.work",
            &["aws_volume_attachment.work"],
        ) {
            Err(Error::Provider(m)) => assert!(m.contains("aws_instance.box"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // An in-place change to the machine is also more than a restore may do.
        let update = machine.replace(r#"["delete","create"]"#, r#"["update"]"#);
        assert!(update.contains(r#"["update"]"#));
        assert!(check_restore_preview(&update, "aws_ebs_volume.work", &[]).is_err());
        // A plan that leaves the volume alone is not a restore.
        let none = r#"{"resource_changes":[{"address":"aws_ebs_volume.work","change":{"actions":["no-op"]}}]}"#;
        assert!(check_restore_preview(none, "aws_ebs_volume.work", &[]).is_err());
        Ok(())
    }

    #[test]
    fn the_plan_that_applies_a_restore_creates_the_volume_and_attachment_and_nothing_else(
    ) -> TestResult {
        let create = ["aws_ebs_volume.work", "aws_volume_attachment.work"];
        let ok = r#"{"resource_changes":[
            {"address":"aws_instance.box","change":{"actions":["no-op"]}},
            {"address":"aws_volume_attachment.work","change":{"actions":["create"]}},
            {"address":"aws_ebs_volume.work","change":{"actions":["create"]}}]}"#;
        assert_eq!(check_restore_apply(ok, &create)?.len(), 2);
        // A resumed restore may have only the attachment left to create.
        let resumed = r#"{"resource_changes":[{"address":"aws_volume_attachment.work","change":{"actions":["create"]}}]}"#;
        assert!(check_restore_apply(resumed, &create).is_ok());
        for bad in [
            ["aws_instance.box", r#"["delete","create"]"#],
            ["aws_instance.box", r#"["update"]"#],
            ["aws_security_group.box", r#"["create"]"#],
            ["aws_ebs_volume.work", r#"["delete","create"]"#],
            ["aws_ebs_volume.work", r#"["update"]"#],
        ] {
            let plan = format!(
                r#"{{"resource_changes":[{{"address":"{}","change":{{"actions":{}}}}}]}}"#,
                bad[0], bad[1]
            );
            match check_restore_apply(&plan, &create) {
                Err(Error::Provider(m)) => assert!(m.contains(bad[0]), "{m}"),
                other => panic!("{bad:?}: expected a refusal, got {other:?}"),
            }
        }
        Ok(())
    }

    #[test]
    fn an_attribute_is_read_from_state_show_output() {
        let shown = "# aws_ebs_volume.work:\nresource \"aws_ebs_volume\" \"work\" {\n    id                   = \"vol-0abc\"\n    size                 = 200\n}\n";
        assert_eq!(state_attribute(shown, "id").as_deref(), Some("vol-0abc"));
        assert_eq!(state_attribute(shown, "size").as_deref(), Some("200"));
        assert_eq!(state_attribute(shown, "nope"), None);
    }

    #[test]
    fn missing_machine_id_is_an_error() {
        assert!(parse_outputs("{}").is_err());
    }

    // ----- state kept apart from the module checkout -----

    fn legacy_module(dir: &Path, boxes: &[(&str, &str)]) -> PathBuf {
        let m = dir.join("modules/aws-box");
        for (name, text) in boxes {
            let d = m.join("terraform.tfstate.d").join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("terraform.tfstate"), text).unwrap();
        }
        std::fs::create_dir_all(&m).unwrap();
        m
    }

    #[test]
    fn state_kept_apart_points_the_local_backend_and_the_data_dir_at_the_state_root() -> TestResult
    {
        let d = tempfile::tempdir()?;
        let module = legacy_module(d.path(), &[]);
        let r = Arc::new(RecordingRunner::new());
        r.reply(Output {
            status: Some(0),
            ..Output::default()
        });
        let m = TofuModule::new(r.clone(), &module).with_state_root(d.path().join("state"));
        let _ = m.has_workspace(&BoxName::new("main")?);
        let calls = r.calls();
        let init = &calls[0];
        let root = d.path().join("state/aws-box");
        assert!(init.args.contains(&"-reconfigure".to_string()));
        assert!(init.args.contains(&format!(
            "-backend-config=workspace_dir={}",
            root.join("workspaces").display()
        )));
        assert_eq!(
            init.env.get("TF_DATA_DIR").map(String::as_str),
            Some(root.join("data").to_str().unwrap_or_default())
        );
        Ok(())
    }

    #[test]
    fn an_old_checkout_state_is_copied_verified_and_left_in_place_with_a_note() -> TestResult {
        let d = tempfile::tempdir()?;
        let module = legacy_module(
            d.path(),
            &[("main", "{\"serial\":7}"), ("exp-1", "{\"serial\":2}")],
        );
        let layout = StateLayout::new(&d.path().join("state"), &module);
        let mut moved = layout.migrate_legacy(&module)?;
        moved.sort();
        assert_eq!(moved, ["exp-1", "main"]);
        let main = BoxName::new("main")?;
        assert_eq!(
            std::fs::read_to_string(layout.state_file(&main))?,
            "{\"serial\":7}"
        );
        // never deleted, and the old folder says where the live copy is
        assert!(module
            .join("terraform.tfstate.d/main/terraform.tfstate")
            .is_file());
        assert!(
            std::fs::read_to_string(module.join("terraform.tfstate.d/MOVED-BY-OZBOX.txt"))?
                .contains("live one")
        );
        // a second run changes nothing; a newer live copy is never overwritten by the old one
        std::fs::write(layout.state_file(&main), "{\"serial\":9}")?;
        assert!(layout.migrate_legacy(&module)?.is_empty());
        assert_eq!(
            std::fs::read_to_string(layout.state_file(&main))?,
            "{\"serial\":9}"
        );
        Ok(())
    }

    #[test]
    fn removing_the_module_folder_cannot_remove_a_boxs_state() -> TestResult {
        let d = tempfile::tempdir()?;
        let module = legacy_module(d.path(), &[("main", "{\"serial\":7}")]);
        let layout = StateLayout::new(&d.path().join("state"), &module);
        layout.migrate_legacy(&module)?;
        // a worktree removed, a checkout deleted: the whole module directory goes
        std::fs::remove_dir_all(&module)?;
        let main = BoxName::new("main")?;
        assert_eq!(
            std::fs::read_to_string(layout.state_file(&main))?,
            "{\"serial\":7}"
        );
        assert!(!layout.state_file(&main).starts_with(&module));
        Ok(())
    }

    #[test]
    fn a_backup_is_a_verified_private_copy_and_a_box_without_state_has_none() -> TestResult {
        let d = tempfile::tempdir()?;
        let module = legacy_module(d.path(), &[("main", "{\"serial\":7}")]);
        let layout = StateLayout::new(&d.path().join("state"), &module);
        layout.migrate_legacy(&module)?;
        let b = layout.backup(&BoxName::new("main")?, "before")?;
        let b = b.ok_or("no backup")?;
        assert_eq!(std::fs::read_to_string(&b)?, "{\"serial\":7}");
        assert!(b.starts_with(layout.backups_dir()));
        assert!(layout.backup(&BoxName::new("other")?, "before")?.is_none());
        Ok(())
    }

    #[test]
    fn the_default_state_root_is_under_the_home_state_dir_and_overridable() {
        // only the pure fallback is asserted: the environment is the test runner's
        if std::env::var_os("OZBOX_TOFU_STATE_DIR").is_none()
            && std::env::var_os("XDG_STATE_HOME").is_none()
        {
            assert_eq!(
                default_state_root(Some(Path::new("/home/u"))),
                Some(PathBuf::from("/home/u/.local/state/ozbox/tofu"))
            );
        }
    }

    #[test]
    fn import_artefacts_are_corrected_in_the_state_document_and_the_serial_rises() -> TestResult {
        let state = r#"{"version":4,"serial":3,"resources":[
          {"type":"aws_instance","name":"box","instances":[{"attributes":{"id":"i-1","user_data":"abc","user_data_base64":null,"user_data_replace_on_change":false}}]},
          {"type":"aws_volume_attachment","name":"work","instances":[{"attributes":{"id":"vai-1","stop_instance_before_detaching":null}}]},
          {"type":"aws_ebs_volume","name":"work","instances":[{"attributes":{"id":"vol-1"}}]}]}"#;
        let (out, said) = fix_import_artefacts(state)?;
        assert_eq!(said.len(), 3, "{said:?}");
        let v: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(v["serial"], 4);
        let inst = &v["resources"][0]["instances"][0]["attributes"];
        assert_eq!(inst["user_data_replace_on_change"], true);
        assert!(inst["user_data"].is_null());
        assert_eq!(
            v["resources"][1]["instances"][0]["attributes"]["stop_instance_before_detaching"],
            true
        );
        assert_eq!(
            v["resources"][2]["instances"][0]["attributes"]["id"], "vol-1",
            "other resources untouched"
        );
        // a state with nothing to correct comes back byte for byte, serial unchanged
        let (again, said2) = fix_import_artefacts(&out)?;
        assert!(said2.is_empty() && again == out);
        Ok(())
    }

    #[test]
    fn an_adoption_plan_must_be_no_op_or_tag_only() -> TestResult {
        let ok = r#"{"resource_changes":[
          {"address":"aws_instance.box","change":{"actions":["no-op"]}},
          {"address":"aws_ebs_volume.work","change":{"actions":["update"],
            "before":{"size":200,"tags":{"a":"1"},"tags_all":{"a":"1"}},"after":{"size":200,"tags":{"a":"1","ozbox-managed":"true"},"tags_all":{"a":"1","ozbox-managed":"true"}}}}]}"#;
        assert_eq!(check_adopt_plan(ok)?, ["aws_ebs_volume.work: tags only"]);
        let more = ok.replace(
            r#""size":200,"tags":{"a":"1"},"tags_all""#,
            r#""size":100,"tags":{"a":"1"},"tags_all""#,
        );
        match check_adopt_plan(&more) {
            Err(Error::Provider(m)) => {
                assert!(m.contains("aws_ebs_volume.work would change size"), "{m}")
            }
            other => panic!("expected a refusal: {other:?}"),
        }
        let replace = r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["delete","create"]}}]}"#;
        assert!(check_adopt_plan(replace).is_err());
        assert!(check_adopt_plan(r#"{"resource_changes":[]}"#)?.is_empty());
        Ok(())
    }

    // ----- state in the bucket -----

    /// A tofu that keeps one remote state per workspace in memory: `state pull` answers it, `state push` replaces it.
    struct FakeBucketTofu {
        calls: std::sync::Mutex<Vec<CommandSpec>>,
        remote: std::sync::Mutex<String>,
        plan: String,
        version: String,
        corrupt_push: bool,
    }

    impl FakeBucketTofu {
        fn new(plan: &str) -> Arc<Self> {
            Arc::new(Self {
                calls: std::sync::Mutex::new(Vec::new()),
                remote: std::sync::Mutex::new(String::new()),
                plan: plan.to_string(),
                version: r#"{"terraform_version":"1.10.3"}"#.into(),
                corrupt_push: false,
            })
        }
        fn log(&self) -> Vec<CommandSpec> {
            self.calls.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    impl CommandRunner for FakeBucketTofu {
        fn run(&self, cmd: &CommandSpec) -> Result<Output> {
            if let Ok(mut c) = self.calls.lock() {
                c.push(cmd.clone());
            }
            let has = |w: &str| cmd.args.iter().any(|a| a == w);
            let mut out = Output {
                status: Some(0),
                ..Output::default()
            };
            if has("version") {
                out.stdout = self.version.clone();
            } else if has("state") && has("pull") {
                out.stdout = self.remote.lock().map(|r| r.clone()).unwrap_or_default();
            } else if has("state") && has("push") {
                let body =
                    String::from_utf8_lossy(cmd.stdin.as_deref().unwrap_or_default()).to_string();
                let body = if self.corrupt_push {
                    body.replace("\"serial\": 7", "\"serial\": 8")
                } else {
                    body
                };
                if let Ok(mut r) = self.remote.lock() {
                    *r = body;
                }
            } else if has("workspace") && has("list") {
                out.stdout = "* default\n  main\n".into();
            } else if has("show") {
                out.stdout = self.plan.clone();
            }
            Ok(out)
        }
    }

    const NOOP: &str =
        r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["no-op"]}}]}"#;
    const LOCAL_STATE: &str = r#"{"version":4,"serial":7,"lineage":"abc","outputs":{},"resources":[{"type":"aws_instance","name":"box","instances":[]}]}"#;

    /// `<d>/infra/tofu/modules/aws-box` (a local backend, a main file, a stray file) and `<d>/infra/cloud-init`.
    fn real_module(d: &Path) -> PathBuf {
        let m = d.join("infra/tofu/modules/aws-box");
        std::fs::create_dir_all(&m).unwrap();
        std::fs::write(
            m.join("versions.tf"),
            "terraform {\n  backend \"local\" {}\n}\n",
        )
        .unwrap();
        std::fs::write(m.join("main.tf"), "# main\n").unwrap();
        std::fs::write(m.join("notes.txt"), "not terraform").unwrap();
        let c = d.join("infra/cloud-init/scripts");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(d.join("infra/cloud-init/box.yaml.tftpl"), "#cloud-config\n").unwrap();
        std::fs::write(c.join("a.sh"), "echo a\n").unwrap();
        m
    }

    fn s3_module(r: Arc<FakeBucketTofu>, d: &Path) -> TofuModule {
        let module = real_module(d);
        TofuModule::new(r, &module)
            .with_state_root(d.join("state"))
            .with_s3_state(S3State::new(
                "ozbox-tfstate-123456789012-us-east-1",
                "us-east-1",
            ))
    }

    #[test]
    fn bucket_state_runs_a_generated_copy_with_an_s3_backend_and_never_writes_the_real_module(
    ) -> TestResult {
        let d = tempfile::tempdir()?;
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r.clone(), d.path());
        let real = d.path().join("infra/tofu/modules/aws-box");
        let before = std::fs::read_to_string(real.join("versions.tf"))?;
        assert!(m.has_workspace(&BoxName::new("main")?)?);
        // the real module is untouched
        assert_eq!(std::fs::read_to_string(real.join("versions.tf"))?, before);
        assert!(!real.join(".terraform").exists());
        // the copy carries the s3 backend, the other .tf files, and the cloud-init folder at the depth the module reads it
        let run = d.path().join("state/aws-box/run/infra");
        let copy = run.join("tofu/modules/aws-box");
        let versions = std::fs::read_to_string(copy.join("versions.tf"))?;
        assert!(versions.contains("backend \"s3\" {}") && !versions.contains("backend \"local\""));
        assert!(copy.join("main.tf").is_file() && !copy.join("notes.txt").exists());
        assert!(run.join("cloud-init/box.yaml.tftpl").is_file());
        assert!(run.join("cloud-init/scripts/a.sh").is_file());
        // init gets the bucket, the prefix, native locking and encryption, and its own data dir; tofu runs in the copy
        let log = r.log();
        let init = log
            .iter()
            .find(|c| c.args.iter().any(|a| a == "init"))
            .ok_or("no init")?;
        let joined = init.args.join(" ");
        for want in [
            "-chdir=",
            "/run/infra/tofu/modules/aws-box",
            "-reconfigure",
            "-backend-config=bucket=ozbox-tfstate-123456789012-us-east-1",
            "-backend-config=key=terraform.tfstate",
            "-backend-config=region=us-east-1",
            "-backend-config=workspace_key_prefix=ozbox/boxes/aws-box",
            "-backend-config=encrypt=true",
            "-backend-config=use_lockfile=true",
        ] {
            assert!(joined.contains(want), "missing {want} in {joined}");
        }
        assert_eq!(
            init.env.get("TF_DATA_DIR").map(String::as_str),
            d.path().join("state/aws-box/data-s3").to_str()
        );
        Ok(())
    }

    #[test]
    fn a_module_without_a_local_backend_cannot_be_run_against_the_bucket() -> TestResult {
        let d = tempfile::tempdir()?;
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r, d.path());
        std::fs::write(
            d.path().join("infra/tofu/modules/aws-box/versions.tf"),
            "terraform {}\n",
        )?;
        let e = m
            .has_workspace(&BoxName::new("main")?)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no empty local backend"), "{e}");
        Ok(())
    }

    #[test]
    fn the_bucket_needs_a_new_enough_tofu_and_plain_names() -> TestResult {
        let d = tempfile::tempdir()?;
        let old = Arc::new(FakeBucketTofu {
            version: r#"{"terraform_version":"1.9.5"}"#.into(),
            ..Arc::try_unwrap(FakeBucketTofu::new(NOOP)).map_err(|_| "arc")?
        });
        let m = s3_module(old, d.path());
        let e = m
            .has_workspace(&BoxName::new("main")?)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("1.10") && e.contains("keep the state on this computer"),
            "{e}"
        );
        assert_eq!(parse_tofu_version("OpenTofu v1.8.2\non linux"), (1, 8));
        assert_eq!(parse_tofu_version("garbage"), (0, 0));
        for bad in ["UPPER", "a b", "x;y", "-lead", "ab"] {
            assert!(S3State::new(bad, "us-east-1").validate().is_err(), "{bad}");
        }
        assert!(S3State::new("ozbox-tfstate-1-us-east-1", "us east")
            .validate()
            .is_err());
        let mut k = S3State::new("ozbox-tfstate-1-us-east-1", "us-east-1");
        k.kms_key_id = Some("alias/x y".into());
        assert!(k.validate().is_err());
        k.kms_key_id = Some("arn:aws:kms:us-east-1:123456789012:key/abc".into());
        assert!(k.validate().is_ok());
        assert!(k.backend_config("aws-box").contains(
            &"-backend-config=kms_key_id=arn:aws:kms:us-east-1:123456789012:key/abc".to_string()
        ));
        Ok(())
    }

    fn put_local(d: &Path, name: &str, text: &str) {
        let f = d
            .join("state/aws-box/workspaces")
            .join(name)
            .join("terraform.tfstate");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, text).unwrap();
    }

    #[test]
    fn migrating_copies_verifies_plans_clean_and_keeps_the_local_copy() -> TestResult {
        let d = tempfile::tempdir()?;
        put_local(d.path(), "main", LOCAL_STATE);
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r.clone(), d.path());
        assert_eq!(m.local_boxes(), ["main"]);
        let rep = m.migrate_local_to_s3(&vars()?)?;
        assert_eq!(
            (rep.serial, rep.resources, rep.already_there),
            (7, 1, false)
        );
        assert_eq!(rep.remote_key, "ozbox/boxes/aws-box/main/terraform.tfstate");
        // the bucket holds it, the local file is still there with a note beside it, and a backup was taken first
        assert_eq!(r.remote.lock().map_err(|_| "lock")?.as_str(), LOCAL_STATE);
        let local = d.path().join("state/aws-box/workspaces/main");
        assert_eq!(
            std::fs::read_to_string(local.join("terraform.tfstate"))?,
            LOCAL_STATE
        );
        assert!(std::fs::read_to_string(local.join("MIGRATED-TO-S3.txt"))?.contains("live one"));
        assert!(std::fs::read_to_string(rep.backup.ok_or("no backup")?)? == LOCAL_STATE);
        // the order that makes it safe: push, then read back, then plan
        let words: Vec<String> = r
            .log()
            .iter()
            .filter(|c| {
                c.args
                    .iter()
                    .any(|a| matches!(a.as_str(), "push" | "pull" | "plan" | "show"))
            })
            .map(|c| {
                c.args
                    .iter()
                    .find(|a| matches!(a.as_str(), "push" | "pull" | "plan" | "show"))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(words, ["pull", "push", "pull", "plan", "show"]);
        // a second run finds the same state there and only verifies
        let again = m.migrate_local_to_s3(&vars()?)?;
        assert!(again.already_there);
        Ok(())
    }

    #[test]
    fn the_bucket_copy_may_become_live_only_if_it_is_the_same_state_or_further_on() -> TestResult {
        let local = StateSummary::of(LOCAL_STATE)?;
        let same = StateSummary::of(LOCAL_STATE)?;
        let newer = StateSummary::of(&LOCAL_STATE.replace("\"serial\":7", "\"serial\":9"))?;
        let older = StateSummary::of(&LOCAL_STATE.replace("\"serial\":7", "\"serial\":3"))?;
        let other = StateSummary::of(&LOCAL_STATE.replace("\"abc\"", "\"zzz\""))?;
        let forked = StateSummary::of(&LOCAL_STATE.replace("\"name\":\"box\"", "\"name\":\"b2\""))?;
        assert_eq!(bucket_copy_problem(&local, Some(&same)), None);
        assert_eq!(bucket_copy_problem(&local, Some(&newer)), None);
        assert_eq!(
            bucket_copy_problem(&local, Some(&older)),
            Some(SwitchProblem::Stale)
        );
        assert_eq!(
            bucket_copy_problem(&local, Some(&other)),
            Some(SwitchProblem::Different)
        );
        assert_eq!(
            bucket_copy_problem(&local, Some(&forked)),
            Some(SwitchProblem::Different)
        );
        assert_eq!(
            bucket_copy_problem(&local, None),
            Some(SwitchProblem::Missing)
        );
        Ok(())
    }

    #[test]
    fn an_older_copy_of_the_same_state_in_the_bucket_is_brought_up_to_date() -> TestResult {
        let d = tempfile::tempdir()?;
        put_local(d.path(), "main", LOCAL_STATE);
        let r = FakeBucketTofu::new(NOOP);
        *r.remote.lock().map_err(|_| "lock")? = LOCAL_STATE.replace("\"serial\":7", "\"serial\":3");
        let m = s3_module(r.clone(), d.path());
        let rep = m.migrate_local_to_s3(&vars()?)?;
        assert!(!rep.already_there);
        assert_eq!(r.remote.lock().map_err(|_| "lock")?.as_str(), LOCAL_STATE);
        // a newer one in the bucket is another matter: never overwritten from here
        *r.remote.lock().map_err(|_| "lock")? = LOCAL_STATE.replace("\"serial\":7", "\"serial\":9");
        let e = m.migrate_local_to_s3(&vars()?).unwrap_err().to_string();
        assert!(e.contains("already has a different state"), "{e}");
        Ok(())
    }

    #[test]
    fn what_the_bucket_holds_for_a_box_is_read_back_and_none_when_it_has_none() -> TestResult {
        let d = tempfile::tempdir()?;
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r.clone(), d.path());
        let main = BoxName::new("main")?;
        assert_eq!(m.bucket_state_summary(&main)?, None, "an empty workspace");
        *r.remote.lock().map_err(|_| "lock")? = LOCAL_STATE.into();
        assert_eq!(m.bucket_state_summary(&main)?.map(|s| s.serial), Some(7));
        assert_eq!(
            m.bucket_state_summary(&BoxName::new("dev")?)?,
            None,
            "no workspace"
        );
        Ok(())
    }

    #[test]
    fn migrating_refuses_a_different_state_already_in_the_bucket_and_changes_nothing() -> TestResult
    {
        let d = tempfile::tempdir()?;
        put_local(d.path(), "main", LOCAL_STATE);
        let r = FakeBucketTofu::new(NOOP);
        *r.remote.lock().map_err(|_| "lock")? = LOCAL_STATE.replace("\"abc\"", "\"other\"");
        let m = s3_module(r.clone(), d.path());
        let e = m.migrate_local_to_s3(&vars()?).unwrap_err().to_string();
        assert!(e.contains("already has a different state"), "{e}");
        assert!(!r.log().iter().any(|c| c.args.iter().any(|a| a == "push")));
        Ok(())
    }

    #[test]
    fn a_copy_that_does_not_read_back_the_same_is_not_trusted() -> TestResult {
        let d = tempfile::tempdir()?;
        put_local(
            d.path(),
            "main",
            LOCAL_STATE
                .replace("\"serial\":7", "\"serial\": 7")
                .as_str(),
        );
        let mut fake = Arc::try_unwrap(FakeBucketTofu::new(NOOP)).map_err(|_| "arc")?;
        fake.corrupt_push = true;
        let m = s3_module(Arc::new(fake), d.path());
        let e = m.migrate_local_to_s3(&vars()?).unwrap_err().to_string();
        assert!(
            e.contains("did not read back the same") && e.contains("untouched"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn a_plan_that_would_change_something_after_the_copy_fails_the_migration_and_says_the_local_state_stays(
    ) -> TestResult {
        let d = tempfile::tempdir()?;
        put_local(d.path(), "main", LOCAL_STATE);
        let r = FakeBucketTofu::new(
            r#"{"resource_changes":[{"address":"aws_instance.box","change":{"actions":["update"]}}]}"#,
        );
        let m = s3_module(r, d.path());
        let e = m.migrate_local_to_s3(&vars()?).unwrap_err().to_string();
        assert!(
            e.contains("aws_instance.box would update") && e.contains("stays in use"),
            "{e}"
        );
        assert!(!d
            .path()
            .join("state/aws-box/workspaces/main/MIGRATED-TO-S3.txt")
            .exists());
        Ok(())
    }

    #[test]
    fn a_box_with_no_local_state_or_an_empty_one_is_not_migrated() -> TestResult {
        let d = tempfile::tempdir()?;
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r, d.path());
        assert!(m
            .migrate_local_to_s3(&vars()?)
            .unwrap_err()
            .to_string()
            .contains("no OpenTofu state on this computer"));
        put_local(
            d.path(),
            "main",
            r#"{"serial":3,"lineage":"x","resources":[]}"#,
        );
        assert!(m
            .migrate_local_to_s3(&vars()?)
            .unwrap_err()
            .to_string()
            .contains("no resources"));
        Ok(())
    }

    #[test]
    fn a_backup_from_the_bucket_is_a_pulled_private_copy_and_a_box_without_state_has_none(
    ) -> TestResult {
        let d = tempfile::tempdir()?;
        let r = FakeBucketTofu::new(NOOP);
        let m = s3_module(r.clone(), d.path());
        assert!(m.backup(&BoxName::new("main")?, "before")?.is_none());
        *r.remote.lock().map_err(|_| "lock")? = LOCAL_STATE.to_string();
        let b = m.backup(&BoxName::new("main")?, "before")?.ok_or("none")?;
        assert_eq!(std::fs::read_to_string(&b)?, LOCAL_STATE);
        assert!(b.starts_with(d.path().join("state/aws-box/backups")));
        // a workspace that does not exist yet has nothing to back up, and is not created by asking
        assert!(m.backup(&BoxName::new("other")?, "before")?.is_none());
        assert!(!r.log().iter().any(
            |c| c.args.iter().any(|a| a == "-or-create") && c.args.iter().any(|a| a == "other")
        ));
        Ok(())
    }

    #[test]
    fn a_missing_workspace_in_the_bucket_points_at_migrate_when_the_state_is_local() -> TestResult {
        let d = tempfile::tempdir()?;
        put_local(d.path(), "main", LOCAL_STATE);
        let r = Arc::new(FailSelect(FakeBucketTofu::new(NOOP)));
        let module = real_module(d.path());
        let m = TofuModule::new(r, &module)
            .with_state_root(d.path().join("state"))
            .with_s3_state(S3State::new("ozbox-tfstate-1-us-east-1", "us-east-1"));
        let e = m.plan_show(&vars()?).unwrap_err().to_string();
        assert!(e.contains("ozbox state migrate main"), "{e}");
        Ok(())
    }

    /// Like the bucket fake, but selecting a workspace that was not made fails.
    struct FailSelect(Arc<FakeBucketTofu>);
    impl CommandRunner for FailSelect {
        fn run(&self, cmd: &CommandSpec) -> Result<Output> {
            let sel = cmd.args.iter().any(|a| a == "select")
                && !cmd.args.iter().any(|a| a == "-or-create");
            if sel {
                return Ok(Output {
                    status: Some(1),
                    ..Output::default()
                });
            }
            self.0.run(cmd)
        }
    }

    #[test]
    fn the_noop_check_is_stricter_than_the_adoption_check() {
        assert!(check_noop_plan(NOOP).is_ok());
        assert!(check_noop_plan(r#"{"resource_changes":[]}"#).is_ok());
        let tags = r#"{"resource_changes":[{"address":"a.b","change":{"actions":["update"],"before":{"tags":{"a":"1"}},"after":{"tags":{"a":"2"}}}}]}"#;
        assert!(check_adopt_plan(tags).is_ok());
        assert!(check_noop_plan(tags).is_err());
    }

    #[test]
    fn hetzner_import_artefacts_are_set_to_what_the_module_sets_and_never_over_a_reported_value(
    ) -> TestResult {
        let imported = r#"{"version":4,"serial":2,"resources":[
          {"type":"hcloud_volume_attachment","name":"work","instances":[{"attributes":{"volume_id":7}}]},
          {"type":"hcloud_server","name":"box","instances":[{"attributes":{"delete_protection":true,"keep_disk":null}}]}]}"#;
        let (fixed, said) = fix_import_artefacts_hcloud(imported)?;
        assert_eq!(said.len(), 2);
        let v: serde_json::Value = serde_json::from_str(&fixed)?;
        assert_eq!(v["serial"], 3);
        assert_eq!(
            v["resources"][0]["instances"][0]["attributes"]["automount"],
            false
        );
        let srv = &v["resources"][1]["instances"][0]["attributes"];
        assert_eq!(srv["delete_protection"], true, "a reported value is kept");
        assert_eq!(srv["keep_disk"], false);
        assert_eq!(srv["backups"], false);
        // already right: untouched and the serial is not raised
        let (again, none) = fix_import_artefacts_hcloud(&fixed)?;
        assert!(none.is_empty() && again == fixed);
        // a label-only update is acceptable on Hetzner, a rename is not
        let lbl = r#"{"resource_changes":[{"address":"hcloud_server.box","change":{"actions":["update"],"before":{"labels":{"a":"1"}},"after":{"labels":{"a":"2"}}}}]}"#;
        assert_eq!(check_adopt_plan(lbl)?, ["hcloud_server.box: tags only"]);
        let rename = r#"{"resource_changes":[{"address":"hcloud_server.box","change":{"actions":["update"],"before":{"name":"a"},"after":{"name":"b"}}}]}"#;
        assert!(check_adopt_plan(rename).is_err());
        Ok(())
    }

    #[test]
    fn an_old_module_local_dot_terraform_is_moved_aside_so_a_non_interactive_init_cannot_stall(
    ) -> TestResult {
        let d = tempfile::tempdir()?;
        let module = legacy_module(d.path(), &[("main", "{\"serial\":7}")]);
        std::fs::create_dir_all(module.join(".terraform/providers"))?;
        std::fs::write(module.join(".terraform/environment"), "main")?;
        let r = Arc::new(RecordingRunner::new());
        let m = TofuModule::new(r.clone(), &module).with_state_root(d.path().join("state"));
        let _ = m.has_workspace(&BoxName::new("main")?)?;
        assert!(!module.join(".terraform").exists());
        assert_eq!(
            std::fs::read_to_string(module.join(".terraform.moved-by-ozbox/environment"))?,
            "main"
        );
        assert!(module.join("MOVED-BY-OZBOX-data.txt").is_file());
        let init = &r.calls()[0];
        assert!(
            init.args.contains(&"-input=false".to_string())
                && init.args.contains(&"-reconfigure".to_string())
        );
        assert!(init.env.contains_key("TF_DATA_DIR"));
        // the copied state is where it should be, and a second init finds nothing more to move
        assert!(d
            .path()
            .join("state/aws-box/workspaces/main/terraform.tfstate")
            .is_file());
        let _ = m.has_workspace(&BoxName::new("main")?)?;
        assert!(!module.join(".terraform.moved-by-ozbox-2").exists());
        Ok(())
    }
}
