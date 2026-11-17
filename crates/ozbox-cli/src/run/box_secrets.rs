//! `ozbox box-secrets <box> --backend aws-ssm --path /ozbox/dev --role main`: declare the secrets a box keeps of its own.
//!
//! The declaration is three instance tags (see `box_config`); the box reads them at boot and when told. This shows the
//! change first and applies it only on a yes, like every other change (`--dry-run` stops after the description). It writes
//! the tags with the operator's own credentials and asks the box to read them again; it never reads or writes a secret.
//! What the box may READ is not decided here: the instance role's permission comes from the box's module variables, which
//! stay the source of truth, and the next apply of the module puts the tags back to what those say.

use ozbox_core::{BoxName, BoxState, CommandRunner, CommandSpec, Provider};

use super::{print_json, CliError, Flags, Result};
use crate::box_config::{BoxConfig, TAG_BACKEND, TAG_PATH, TAG_ROLE};
use crate::serve::agent::BoxAgent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Set(BoxConfig),
    Remove,
    /// Flags that do not say what to do.
    Incomplete,
}

impl Change {
    pub fn from_flags(
        backend: Option<String>,
        path: Option<String>,
        role: Option<String>,
        remove: bool,
    ) -> Self {
        match (remove, backend, path, role) {
            (true, None, None, None) => Self::Remove,
            (false, Some(backend), Some(path), Some(role)) => Self::Set(BoxConfig {
                backend,
                path,
                role,
                region: String::new(),
            }),
            _ => Self::Incomplete,
        }
    }
}

/// The plan, in words: what will be written and what is not decided here.
pub fn describe(name: &str, c: &Change) -> String {
    match c {
        Change::Set(c) => format!(
            "On {name}: declare that it keeps its own secrets in {} under {}/{} (instance tags {TAG_BACKEND}, {TAG_PATH}, {TAG_ROLE}), then have the box read them. \
             No secret is read or written. The box can read them only if its module grants it: set box_secrets_backend = \"{}\", box_secrets_prefix = \"{}\" and box_role = \"{}\" on the box's module.",
            c.backend, c.path, c.role, c.backend, c.path, c.role
        ),
        Change::Remove => format!(
            "On {name}: remove its secrets declaration (the three instance tags), then have the box read them again. It keeps no secrets of its own afterwards; what it already holds in memory goes at the next restart of its secrets service."
        ),
        Change::Incomplete => String::new(),
    }
}

/// The `aws ec2` calls for a change. Plain words only: every value was validated.
pub fn aws_calls(region: &str, instance: &str, c: &Change) -> Vec<Vec<String>> {
    let base = |sub: &str| {
        vec![
            "ec2".to_string(),
            sub.to_string(),
            "--region".to_string(),
            region.to_string(),
            "--resources".to_string(),
            instance.to_string(),
        ]
    };
    match c {
        Change::Set(c) => {
            let mut a = base("create-tags");
            a.push("--tags".into());
            for (k, v) in [
                (TAG_BACKEND, &c.backend),
                (TAG_PATH, &c.path),
                (TAG_ROLE, &c.role),
            ] {
                a.push(format!("Key={k},Value={v}"));
            }
            vec![a]
        }
        Change::Remove => {
            let mut a = base("delete-tags");
            a.push("--tags".into());
            for k in [TAG_BACKEND, TAG_PATH, TAG_ROLE] {
                a.push(format!("Key={k}"));
            }
            vec![a]
        }
        Change::Incomplete => vec![],
    }
}

/// What only a provider with no instance tags needs: the vault's address and mount, and the approval a box with a second
/// factor wants for the change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extras {
    pub vault_addr: Option<String>,
    pub mount: Option<String>,
    pub approval: Option<String>,
}

fn word_ok(s: &str, extra: &[u8]) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// `/ozbox/dev` as `ozbox..dev`: the root helper's request holds plain words only, so `/` is written as `..` (a path never
/// holds `..` itself, and no segment may start or end with a dot, so the reading is one way only).
pub fn encode_path(path: &str) -> std::result::Result<String, String> {
    let rest = path.strip_prefix('/').ok_or("the path must start with /")?;
    let segs: Vec<&str> = rest.split('/').collect();
    if segs
        .iter()
        .any(|s| s.is_empty() || s.starts_with('.') || s.ends_with('.') || s.contains(".."))
    {
        return Err("on this provider a path segment may not start or end with a dot".into());
    }
    Ok(segs.join(".."))
}

/// The root helper's request for a box with no instance tags (Hetzner): the declaration is the settings file the loader reads.
pub fn hetzner_request(c: &Change, x: &Extras) -> std::result::Result<String, String> {
    let appr = x
        .approval
        .as_deref()
        .filter(|a| !a.is_empty())
        .unwrap_or("-");
    if !word_ok(appr, b"-") {
        return Err("the approval code has characters that are not allowed".into());
    }
    match c {
        Change::Set(b) => {
            if b.backend != "openbao" {
                return Err("on this provider the backend must be openbao: a Hetzner box has no cloud role to read Parameter Store with".into());
            }
            let addr = match x.vault_addr.as_deref() {
                None => "-".to_string(),
                Some(a) => {
                    let ok = a.strip_prefix("https://").is_some_and(|h| {
                        let (host, port) =
                            h.split_once(':').map_or((h, None), |(h, p)| (h, Some(p)));
                        !host.is_empty()
                            && host.len() <= 80
                            && host.bytes().all(|b| {
                                b.is_ascii_lowercase()
                                    || b.is_ascii_digit()
                                    || b == b'-'
                                    || b == b'.'
                            })
                            && !host.starts_with(['-', '.'])
                            && !host.ends_with(['-', '.'])
                            && port.is_none_or(|p| {
                                (2..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit())
                            })
                    });
                    if !ok {
                        return Err(
                            "the vault address must be https://host or https://host:port".into(),
                        );
                    }
                    ozbox_core::audit::hex(a.as_bytes())
                }
            };
            let mount = x.mount.as_deref().unwrap_or("secret");
            if !word_ok(mount, b"-_") || mount.len() > 32 {
                return Err("the mount must be letters, digits, dashes and underscores".into());
            }
            Ok(format!(
                "write-box-secrets {appr} openbao {} {} {addr} {mount}",
                b.role,
                encode_path(&b.path)?
            ))
        }
        Change::Remove => Ok(format!("clear-box-secrets {appr}")),
        Change::Incomplete => Err("say --backend, --path and --role together, or --remove".into()),
    }
}

/// What an approval for a Hetzner declaration must name as its environment: `d-` and the first 16 hex digits of the sha256
/// of the request's words after the approval (backend, role, path, address, mount). The box computes the same, so an approval
/// for one declaration cannot be spent on another (a different vault address above all). `None` for a removal.
pub fn hetzner_binding(request: &str) -> Option<String> {
    let words: Vec<&str> = request.split(' ').collect();
    match words.as_slice() {
        ["write-box-secrets", _appr, rest @ ..] if rest.len() == 5 => {
            let d = ring::digest::digest(&ring::digest::SHA256, rest.join(" ").as_bytes());
            Some(format!("d-{}", &ozbox_core::audit::hex(d.as_ref())[..16]))
        }
        _ => None,
    }
}

pub(super) fn command(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    runner: &dyn CommandRunner,
    name: BoxName,
    change: Change,
    extras: Extras,
    f: &Flags,
) -> Result<()> {
    if let Change::Set(c) = &change {
        c.validate().map_err(CliError::Msg)?;
    }
    if change == Change::Incomplete {
        return Err(CliError::Msg(
            "say --backend, --path and --role together, or --remove".into(),
        ));
    }
    let rec = p
        .get(&name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    if rec.provider == "hcloud" {
        return hetzner(agent, runner, &rec, &name, &change, &extras, f);
    }
    if rec.provider != "aws" {
        return Err(CliError::Msg(
            "the declaration is written as instance tags on AWS and as a settings file on Hetzner; on another provider place /etc/ozbox/box-secrets.env on the box".into(),
        ));
    }
    let (Some(instance), Some(region)) = (rec.provider_id.clone(), rec.spec.region.clone()) else {
        return Err(CliError::Msg(
            "this box has no machine to tag (it is not created yet, or has no region)".into(),
        ));
    };
    if !f.json {
        println!("{}", describe(name.as_str(), &change));
    }
    if f.dry_run {
        if !f.json {
            println!("Nothing was changed (dry run).");
        }
        return print_result(f, &name, false, true);
    }
    super::admin::ask(f, name.as_str())?;
    for a in aws_calls(&region, &instance, &change) {
        let out = runner
            .run(&CommandSpec::new("aws").args(a))
            .map_err(|_| CliError::Msg("the aws command could not be started".into()))?;
        if out.status != Some(0) {
            // the tool's own words can name an account: say only what failed
            return Err(CliError::Msg(
                "the instance tags could not be written (check your AWS credentials and that the box exists)".into(),
            ));
        }
    }
    // The box reads its tags again, when it is running. A paused box reads them at its next boot.
    if rec.state == BoxState::Running {
        match agent.admin(&rec, "configure-box-secrets") {
            Ok((true, out)) => {
                if !f.json {
                    println!("{out}");
                }
            }
            _ => {
                if !f.json {
                    println!("The tags are written; the box could not be asked to read them now, and will at its next boot.");
                }
            }
        }
    } else if !f.json {
        println!("The tags are written; the box reads them when it next starts.");
    }
    print_result(f, &name, true, false)
}

/// The same plan-then-apply as AWS, for a provider with no instance tags: the root helper writes the loader's settings file
/// on the running box. Nothing is stored in the cloud, so there is nothing to put back at the next apply; the module's
/// variables only matter for a box not yet created.
fn hetzner(
    agent: &dyn BoxAgent,
    runner: &dyn CommandRunner,
    rec: &ozbox_core::BoxRecord,
    name: &BoxName,
    change: &Change,
    extras: &Extras,
    f: &Flags,
) -> Result<()> {
    let request = hetzner_request(change, extras).map_err(CliError::Msg)?;
    if !f.json {
        println!("{}", describe_hetzner(name.as_str(), change));
        if let (Change::Set(_), Some(bind)) = (change, hetzner_binding(&request)) {
            println!(
                "The approval for exactly this declaration (vault address: {}): ozbox secrets approve --box {name} --scope box-secrets --project declaration --env {bind}",
                extras.vault_addr.as_deref().unwrap_or("none"),
            );
        }
    }
    if f.dry_run {
        if !f.json {
            println!("Nothing was changed (dry run).");
        }
        return print_result(f, name, false, true);
    }
    if rec.state != BoxState::Running {
        return Err(CliError::Msg(
            "the settings file is written on the running box: start it first".into(),
        ));
    }
    super::admin::ask(f, name.as_str())?;
    let mut answer = agent.admin(rec, &request);
    // B4-27: the box needs an approval and none was given. Nothing was changed; file a request for exactly this declaration,
    // wait while it is approved in the dashboard, and send the change again with the approved request (`req-<id>`).
    if let (Ok((false, out)), None) = (&answer, extras.approval.as_deref()) {
        if crate::approval_flow::needs_approval(out) {
            if let Some(word) = request_for_declaration(runner, name, change, extras, &request)? {
                let x = Extras {
                    approval: Some(word),
                    ..extras.clone()
                };
                let again = hetzner_request(change, &x).map_err(CliError::Msg)?;
                answer = agent.admin(rec, &again);
            }
        }
    }
    match answer {
        Ok((true, out)) => {
            if !f.json {
                println!("{out}");
            }
        }
        Ok((false, out)) => {
            return Err(CliError::Msg(
                out.lines()
                    .next()
                    .unwrap_or("the box refused the change")
                    .chars()
                    .take(300)
                    .collect(),
            ))
        }
        Err(_) => {
            return Err(CliError::Msg(
                "the box could not be asked to write its settings".into(),
            ))
        }
    }
    print_result(f, name, true, false)
}

/// File a `box-secrets` request for exactly this declaration over the box's sealed route and wait for the dashboard to approve
/// it (only the dashboard approves the box's own secrets). `Ok(None)` when the box cannot spend one, so the refusal stands and
/// says how to get a code.
fn request_for_declaration(
    runner: &dyn CommandRunner,
    name: &BoxName,
    change: &Change,
    extras: &Extras,
    request: &str,
) -> Result<Option<String>> {
    let mut call = |v: &serde_json::Value| {
        crate::workload_cli::ssh_receive(runner, name.as_str(), v)
            .map(|r| r["result"].clone())
            .map_err(|e| e.to_string())
    };
    if !crate::approval_flow::box_files(&mut call, "box-secrets") {
        return Ok(None);
    }
    let bind = hetzner_binding(request).unwrap_or_default();
    let subject =
        ozbox_core::approval_subject::gate_subject("box-secrets", "declaration", &bind, "")
            .map_err(|e| CliError::Msg(e.0))?;
    let what = match change {
        Change::Remove => crate::messages::t(
            "approval.flow_box_secrets_remove_what",
            &[("box", name.as_str())],
        ),
        _ => crate::messages::t(
            "approval.flow_box_secrets_what",
            &[
                ("box", name.as_str()),
                ("address", extras.vault_addr.as_deref().unwrap_or("none")),
            ],
        ),
    };
    let ok = crate::workload_cli::request_and_wait(
        runner,
        name.as_str(),
        &serde_json::json!({"op": "areq_file", "subject": subject}),
        "box-secrets",
        false,
        &what,
        crate::approval_flow::MAX_WAIT_MINUTES,
    )?;
    Ok(Some(ozbox_core::approval_subject::request_word(&ok.id)))
}

/// The plan for a box with no instance tags, in words.
pub fn describe_hetzner(name: &str, c: &Change) -> String {
    match c {
        Change::Set(c) => format!(
            "On {name}: write /etc/ozbox/box-secrets.env so it keeps its own secrets in {} under {}/{} (the file holds names and an address, never a secret), then have the box read them. \
             The vault token is not set here: place it on the box with `ozbox admin {name} -- place-bao-token`. A box with a second factor needs a fresh approval: without --approval this command files a request and waits while you approve it in the dashboard (Approvals).",
            c.backend, c.path, c.role
        ),
        Change::Remove => format!(
            "On {name}: remove the settings file this command wrote, so it keeps no secrets of its own after the next restart of its secrets service."
        ),
        Change::Incomplete => String::new(),
    }
}

fn print_result(f: &Flags, name: &BoxName, applied: bool, dry_run: bool) -> Result<()> {
    if f.json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            #[serde(rename = "box")]
            box_name: &'a str,
            applied: bool,
            dry_run: bool,
        }
        return print_json(&Out {
            box_name: name.as_str(),
            applied,
            dry_run,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn set() -> Change {
        Change::from_flags(
            Some("aws-ssm".into()),
            Some("/ozbox/dev".into()),
            Some("main".into()),
            false,
        )
    }

    #[test]
    fn the_flags_make_one_unambiguous_change() {
        assert!(matches!(set(), Change::Set(_)));
        assert_eq!(Change::from_flags(None, None, None, true), Change::Remove);
        assert_eq!(
            Change::from_flags(Some("aws-ssm".into()), None, None, false),
            Change::Incomplete
        );
        assert_eq!(
            Change::from_flags(None, None, None, false),
            Change::Incomplete
        );
    }

    #[test]
    fn the_plan_names_the_tags_the_scope_and_what_is_not_decided_here() {
        let d = describe("main", &set());
        assert!(
            d.contains("/ozbox/dev/main")
                && d.contains(TAG_ROLE)
                && d.contains("box_secrets_prefix")
        );
        assert!(d.contains("No secret is read or written"));
    }

    #[test]
    fn the_aws_calls_write_or_delete_exactly_three_tags_on_the_one_instance() {
        let c = aws_calls("us-east-1", "i-0abc", &set());
        assert_eq!(c.len(), 1);
        let j = c[0].join(" ");
        assert!(j.starts_with("ec2 create-tags --region us-east-1 --resources i-0abc --tags"));
        assert!(
            j.contains("Key=ozbox-secrets-backend,Value=aws-ssm")
                && j.contains("Key=ozbox-secrets-path,Value=/ozbox/dev")
                && j.contains("Key=ozbox-box-role,Value=main")
        );
        let r = aws_calls("us-east-1", "i-0abc", &Change::Remove)[0].join(" ");
        assert!(r.contains("delete-tags") && !r.contains("Value="));
        assert!(aws_calls("r", "i", &Change::Incomplete).is_empty());
    }

    #[test]
    fn a_box_with_no_instance_tags_gets_the_settings_file_through_the_root_helper() {
        let x = Extras {
            vault_addr: Some("https://vault.example.com:8200".into()),
            mount: None,
            approval: None,
        };
        let c = Change::from_flags(
            Some("openbao".into()),
            Some("/ozbox/dev".into()),
            Some("main".into()),
            false,
        );
        let r = hetzner_request(&c, &x).unwrap();
        assert_eq!(
            r,
            format!(
                "write-box-secrets - openbao main ozbox..dev {} secret",
                ozbox_core::audit::hex(b"https://vault.example.com:8200")
            )
        );
        assert!(
            r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)),
            "the helper takes plain words only"
        );
        assert!(r.len() < 512);
        // an approval rides along; removal needs one too
        let a = Extras {
            approval: Some("ABCD-EFGH-JKLM-NPQR".into()),
            ..Extras::default()
        };
        assert!(hetzner_request(&c, &a)
            .unwrap()
            .starts_with("write-box-secrets ABCD-EFGH-JKLM-NPQR openbao"));
        assert_eq!(
            hetzner_request(&Change::Remove, &a).unwrap(),
            "clear-box-secrets ABCD-EFGH-JKLM-NPQR"
        );
    }

    /// The box (ozbox-box-secrets.sh) computes the same value; `box_scripts.rs` pins it on that side.
    #[test]
    fn an_approval_for_a_hetzner_declaration_is_bound_to_its_address() {
        let set = Change::Set(BoxConfig {
            backend: "openbao".into(),
            path: "/ozbox/dev".into(),
            role: "main".into(),
            region: String::new(),
        });
        let x = |addr: &str| Extras {
            vault_addr: Some(addr.into()),
            mount: None,
            approval: Some("abcd-efgh".into()),
        };
        let r = hetzner_request(&set, &x("https://vault.example.com:8200")).unwrap();
        assert_eq!(hetzner_binding(&r).as_deref(), Some("d-7805e83e21b45add"));
        // the approval code is not part of it, and another address is another binding
        let other = hetzner_request(&set, &x("https://evil.example.com")).unwrap();
        assert_ne!(hetzner_binding(&other), hetzner_binding(&r));
        assert_eq!(hetzner_binding("clear-box-secrets -"), None);
        // an approved request's word (B4-27) rides where the code went, and the binding does not change with it
        let word = ozbox_core::approval_subject::request_word("abcdefghijklmnopqrstuvwxyz");
        let by_request = hetzner_request(
            &set,
            &Extras {
                approval: Some(word.clone()),
                ..x("https://vault.example.com:8200")
            },
        )
        .unwrap();
        assert!(by_request.starts_with(&format!("write-box-secrets {word} ")));
        assert_eq!(hetzner_binding(&by_request), hetzner_binding(&r));
    }

    #[test]
    fn the_hetzner_request_refuses_what_the_helper_would_and_a_backend_it_cannot_read() {
        let ok = |p: &str| {
            hetzner_request(
                &Change::from_flags(
                    Some("openbao".into()),
                    Some(p.into()),
                    Some("main".into()),
                    false,
                ),
                &Extras::default(),
            )
        };
        assert!(ok("/a/b").is_ok() && ok("/v1.2/x").is_ok());
        for bad in ["a/b", "/a/.hidden", "/a./b", "/a//b", "/a/../b"] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        let ssm = Change::from_flags(
            Some("aws-ssm".into()),
            Some("/a".into()),
            Some("main".into()),
            false,
        );
        assert!(hetzner_request(&ssm, &Extras::default())
            .unwrap_err()
            .contains("openbao"));
        let c = Change::from_flags(
            Some("openbao".into()),
            Some("/a".into()),
            Some("main".into()),
            false,
        );
        for addr in [
            "http://x.example.com",
            "https://",
            "https://a b",
            "https://x.example.com/path",
            "https://x:1",
        ] {
            let x = Extras {
                vault_addr: Some(addr.into()),
                ..Extras::default()
            };
            assert!(hetzner_request(&c, &x).is_err(), "{addr}");
        }
        let x = Extras {
            approval: Some("a b".into()),
            ..Extras::default()
        };
        assert!(hetzner_request(&c, &x).is_err());
    }

    #[test]
    fn the_path_encoding_reads_back_one_way_only() {
        assert_eq!(encode_path("/ozbox/dev").unwrap(), "ozbox..dev");
        assert_eq!(encode_path("/v1.2").unwrap(), "v1.2");
        assert!(encode_path("/a/./b").is_err());
    }
}
