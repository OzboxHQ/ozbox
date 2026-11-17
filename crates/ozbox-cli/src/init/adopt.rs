//! Adopting what is already there, so a step never plans to re-create it (ADR 0053).
//!
//! Every OpenTofu step of `ozbox init` keeps its state in the encrypted state bucket, and on a fresh bucket that state starts
//! empty. On an account set up by an earlier version (or by hand) the resources a step would make may already exist, and an
//! apply would then fail "already exists" or, worse, make a second copy. So before a step is planned this module looks, by the
//! names and tags Oz Box itself uses, for what the step would create, and writes OpenTofu `import` blocks next to the step's
//! root module. The plan then shows "Adopt existing ..." beside the real remaining difference.
//!
//! Rules this module keeps:
//!
//! * **Reality is read first, read-only.** One `tofu state list`, then AWS reads (`list-aliases`, `list-resource-tags`,
//!   `describe-document`, `get-policy`) only for the addresses the state does not already hold.
//! * **Only what Oz Box made is adopted.** The resource must carry `ozbox-managed=true`. A look-alike without it is refused with
//!   the reason, and nothing is changed.
//! * **A lookup that cannot answer stops the step.** Only the service's own "not found" answer means absent; a denied or
//!   unreadable answer is never taken as absent (that would plan a create that fails, or a second copy).
//! * **Never a silent replacement.** A plan that would replace or destroy an adopted resource is refused at plan time, so no
//!   apply command exists for it. A difference that can be made in place (a key policy, a document's content) is shown as a change.
//! * **Nothing is applied here.** This writes one scratch file (`adopt.tf`) beside the generated root and reads.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ozbox_core::{Change, CommandSpec, Risk};
use serde_json::Value;

use super::{Finding, Init, Res, Target};
use crate::messages::t;

/// The file of `import` blocks, written beside the step's generated `main.tf`.
pub(super) const ADOPT_FILE: &str = "adopt.tf";

/// What one pass has already asked KMS, so a key and its alias cost one listing and one tag read.
#[derive(Debug, Default)]
struct KmsCache {
    aliases: BTreeMap<String, Option<String>>,
    tagged: BTreeSet<String>,
}

/// How one resource a step would create is looked for in the account.
#[derive(Debug, Clone)]
pub(super) enum Find {
    /// The KMS key behind `alias`; when the alias is absent, the key the config already records (`secrets_key_arn`).
    KmsKey {
        alias: String,
        recorded_arn: Option<String>,
    },
    /// The KMS alias itself (imported by its name).
    KmsAlias { alias: String },
    /// A Systems Manager document, by name.
    SsmDocument { name: String },
    /// A customer-managed IAM policy, by name.
    IamPolicy { name: String },
}

/// One resource a step's module would create: its address in the generated root, and how to find it.
#[derive(Debug, Clone)]
pub(super) struct Adoptable {
    pub address: String,
    pub what: &'static str,
    pub find: Find,
}

/// A resource found in the account, to be imported at `address`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Adopted {
    pub address: String,
    pub what: &'static str,
    pub id: String,
}

impl Adopted {
    pub(super) fn change(&self) -> Change {
        Change::new(
            "adopt.import",
            t(
                "init.net_import",
                &[
                    ("what", self.what),
                    ("address", &self.address),
                    ("id", &self.id),
                ],
            ),
            Risk::Low,
        )
    }
}

/// Characters an AWS id, name or ARN may hold. Anything else is refused before it can reach a generated file.
fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 512
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:/.+=@".contains(&b))
}

/// Whether a list of `{<key_field>: .., <value_field>: ..}` tags holds `ozbox-managed=true`.
fn has_managed_tag(tags: &Value, key_field: &str, value_field: &str) -> bool {
    tags.as_array().is_some_and(|a| {
        a.iter().any(|t| {
            t.get(key_field).and_then(Value::as_str) == Some("ozbox-managed")
                && t.get(value_field).and_then(Value::as_str) == Some("true")
        })
    })
}

fn lookup_failed(what: &str, name: &str, why: &str) -> Finding {
    let why: String = why
        .lines()
        .find(|l| l.contains("rror"))
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect();
    Finding::new(
        "adopt_lookup_failed",
        t(
            "init.adopt_lookup_failed",
            &[("what", what), ("name", name), ("why", &why)],
        ),
    )
}

fn untagged(what: &str, name: &str, denied: bool) -> Finding {
    let key = if denied {
        "init.adopt_untagged_denied"
    } else {
        "init.adopt_untagged"
    };
    Finding::new("adopt_untagged", t(key, &[("what", what), ("name", name)]))
        .with_fix(t("init.adopt_untagged_fix", &[]))
}

impl Init<'_> {
    /// Addresses the step's state already holds. A backend with no state yet is empty, not an error.
    pub(super) fn state_addresses(&self, target: &Target, chdir: &str) -> Res<BTreeSet<String>> {
        let cmd = self.tofu_env(
            target,
            CommandSpec::new("tofu").args([
                chdir.to_string(),
                "state".into(),
                "list".into(),
                "-no-color".into(),
            ]),
        );
        let out = self.exec(&cmd)?;
        match out.status {
            Some(0) => Ok(out
                .stdout
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()),
            _ if out.stderr.contains("No state file was found") => Ok(BTreeSet::new()),
            _ => Err(lookup_failed("the step's state", "", &out.stderr)),
        }
    }

    /// Look in the account for each adoptable the state does not hold. Returns what to import; refuses a look-alike.
    pub(super) fn find_adoptions(
        &self,
        target: &Target,
        account: &str,
        adoptables: &[Adoptable],
        in_state: &BTreeSet<String>,
    ) -> Res<Vec<Adopted>> {
        let region = target.region_or_err()?.to_string();
        let mut kms = KmsCache::default();
        let mut found = Vec::new();
        for a in adoptables.iter().filter(|a| !in_state.contains(&a.address)) {
            let id = match &a.find {
                Find::KmsAlias { alias } => {
                    let Some(key_id) = self.alias_target(target, alias, &mut kms)? else {
                        continue;
                    };
                    self.require_key_tagged(target, a.what, alias, &key_id, &mut kms, false)?;
                    Some(alias.clone())
                }
                Find::KmsKey {
                    alias,
                    recorded_arn,
                } => self.find_key(
                    target,
                    account,
                    &region,
                    a.what,
                    alias,
                    recorded_arn.as_deref(),
                    &mut kms,
                )?,
                Find::SsmDocument { name } => self.find_document(target, a.what, name)?,
                Find::IamPolicy { name } => self.find_policy(target, account, a.what, name)?,
            };
            if let Some(id) = id {
                if !id_ok(&id) {
                    return Err(lookup_failed(
                        a.what,
                        &a.address,
                        "the id is not a plain id",
                    ));
                }
                found.push(Adopted {
                    address: a.address.clone(),
                    what: a.what,
                    id,
                });
            }
        }
        Ok(found)
    }

    /// The key id an alias points at, `None` when there is no such alias. Asked once per alias.
    fn alias_target(
        &self,
        target: &Target,
        alias: &str,
        cache: &mut KmsCache,
    ) -> Res<Option<String>> {
        if let Some(v) = cache.aliases.get(alias) {
            return Ok(v.clone());
        }
        let out = self.exec(&self.aws(target, &["kms", "list-aliases"]))?;
        if out.status != Some(0) {
            return Err(lookup_failed("the KMS alias", alias, &out.stderr));
        }
        let v: Value = serde_json::from_str(&out.stdout)
            .map_err(|_| lookup_failed("the KMS alias", alias, "the answer was not readable"))?;
        let list = v
            .get("Aliases")
            .and_then(Value::as_array)
            .ok_or_else(|| lookup_failed("the KMS alias", alias, "the answer had no alias list"))?;
        let target_id = list
            .iter()
            .find(|x| x.get("AliasName").and_then(Value::as_str) == Some(alias))
            .map(|x| {
                x.get("TargetKeyId")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        // an alias with no target (not one of ours) is a look-alike we cannot adopt
        let resolved = match target_id {
            None => None,
            Some(Some(k)) => Some(k),
            Some(None) => {
                return Err(lookup_failed(
                    "the KMS alias",
                    alias,
                    "the alias points at no key",
                ))
            }
        };
        cache.aliases.insert(alias.to_string(), resolved.clone());
        Ok(resolved)
    }

    /// Ask for the key's tags. A key without `ozbox-managed=true` is refused. A denied read is the same refusal: the setup
    /// identity may read the tags of keys that carry the tag only, so a key it cannot read is not one Oz Box can confirm.
    fn require_key_tagged(
        &self,
        target: &Target,
        what: &'static str,
        name: &str,
        key: &str,
        cache: &mut KmsCache,
        absent_ok: bool,
    ) -> Res<bool> {
        if cache.tagged.contains(key) {
            return Ok(true);
        }
        let out = self.exec(&self.aws(target, &["kms", "list-resource-tags", "--key-id", key]))?;
        if out.status != Some(0) {
            // a key that is gone is "not there" to a caller that asked about a recorded key, never a failure
            if absent_ok && out.stderr.contains("NotFoundException") {
                return Ok(false);
            }
            if out.stderr.contains("AccessDenied") {
                return Err(untagged(what, name, true));
            }
            return Err(lookup_failed(what, name, &out.stderr));
        }
        let v: Value = serde_json::from_str(&out.stdout)
            .map_err(|_| lookup_failed(what, name, "the answer was not readable"))?;
        if has_managed_tag(v.get("Tags").unwrap_or(&Value::Null), "TagKey", "TagValue") {
            cache.tagged.insert(key.to_string());
            Ok(true)
        } else {
            Err(untagged(what, name, false))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn find_key(
        &self,
        target: &Target,
        account: &str,
        region: &str,
        what: &'static str,
        alias: &str,
        recorded_arn: Option<&str>,
        cache: &mut KmsCache,
    ) -> Res<Option<String>> {
        let key_prefix = format!("arn:aws:kms:{region}:{account}:key/");
        let recorded_id = recorded_arn.and_then(|a| a.strip_prefix(&key_prefix));
        if let Some(key_id) = self.alias_target(target, alias, cache)? {
            // the config and the account must agree on which key is the fleet's
            if let Some(rec) = recorded_id {
                if rec != key_id {
                    return Err(Finding::new(
                        "adopt_mismatch",
                        t("init.adopt_mismatch", &[("alias", alias)]),
                    ));
                }
            }
            self.require_key_tagged(target, what, alias, &key_id, cache, false)?;
            return Ok(Some(key_id));
        }
        // no alias: the key the config records, if it is still there
        let Some(rec) = recorded_id else {
            return Ok(None);
        };
        if !self.require_key_tagged(target, what, rec, rec, cache, true)? {
            return Ok(None);
        }
        Ok(Some(rec.to_string()))
    }

    fn find_document(
        &self,
        target: &Target,
        what: &'static str,
        name: &str,
    ) -> Res<Option<String>> {
        let out = self.exec(&self.aws(target, &["ssm", "describe-document", "--name", name]))?;
        if out.status != Some(0) {
            if out.stderr.contains("InvalidDocument") {
                return Ok(None);
            }
            return Err(lookup_failed(what, name, &out.stderr));
        }
        let v: Value = serde_json::from_str(&out.stdout)
            .map_err(|_| lookup_failed(what, name, "the answer was not readable"))?;
        let tags = v.pointer("/Document/Tags").unwrap_or(&Value::Null);
        if has_managed_tag(tags, "Key", "Value") {
            Ok(Some(name.to_string()))
        } else {
            Err(untagged(what, name, false))
        }
    }

    fn find_policy(
        &self,
        target: &Target,
        account: &str,
        what: &'static str,
        name: &str,
    ) -> Res<Option<String>> {
        let arn = format!("arn:aws:iam::{account}:policy/{name}");
        let out = self.exec(&self.aws(target, &["iam", "get-policy", "--policy-arn", &arn]))?;
        if out.status != Some(0) {
            if out.stderr.contains("NoSuchEntity") {
                return Ok(None);
            }
            return Err(lookup_failed(what, name, &out.stderr));
        }
        let v: Value = serde_json::from_str(&out.stdout)
            .map_err(|_| lookup_failed(what, name, "the answer was not readable"))?;
        let tags = v.pointer("/Policy/Tags").unwrap_or(&Value::Null);
        if has_managed_tag(tags, "Key", "Value") {
            Ok(Some(arn))
        } else {
            Err(untagged(what, name, false))
        }
    }
}

/// Write (or remove) the step's `adopt.tf`. The working directory persists between runs, so a stale file would import
/// something no longer wanted: it is always replaced or removed.
pub(super) fn write_imports(dir: &Path, adopted: &[Adopted]) -> Res<()> {
    let path = dir.join(ADOPT_FILE);
    if adopted.is_empty() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Finding::new("command_failed", e.to_string())),
        };
    }
    let mut text = String::from(
        "# Written by `ozbox init`: resources that already exist and that Oz Box made, adopted into this step's state.\n",
    );
    for a in adopted {
        text.push_str(&format!(
            "\nimport {{\n  to = {}\n  id = \"{}\"\n}}\n",
            a.address, a.id
        ));
    }
    std::fs::write(path, text).map_err(|e| Finding::new("command_failed", e.to_string()))
}

/// Refuse a plan that would replace or destroy something just adopted. `entries` are the plan's (address, verb) lines.
pub(super) fn refuse_replacing(adopted: &[Adopted], entries: &[(String, &'static str)]) -> Res<()> {
    for (addr, verb) in entries {
        if (*verb == "replace" || *verb == "destroy") && adopted.iter().any(|a| &a.address == addr)
        {
            return Err(Finding::new(
                "adopt_replace",
                t("init.adopt_replace", &[("address", addr), ("verb", verb)]),
            )
            .with_fix(t("init.adopt_replace_fix", &[])));
        }
    }
    Ok(())
}
