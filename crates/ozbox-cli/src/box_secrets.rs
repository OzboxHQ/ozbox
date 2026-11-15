//! A box's own secrets, loaded into memory at boot and kept fresh (ADR 0023, item 5). The keys a box needs to work on a
//! project (Staging Supabase, Stripe test keys, the end-to-end accounts) live in the provider's secret store (AWS
//! Parameter Store first, OpenBao for a box that is not on AWS), scoped to this box's role by path. A small unit pulls them
//! as the secrets user and hands them to the secrets service, which keeps them in a store on tmpfs (sealed under the same
//! key-encryption key as the rest, never on a disk) and offers them exactly the way it offers an imported `.env`: a command
//! with a declaration receives the names it is allowed, an agent never reads one, and they are scanned for in a commit.
//!
//! One interface, [`Backend`]. A parameter's name is `<prefix>/<role>/<project>/<env>/<NAME>`; only that shape, only this
//! box's role, and only a non-production environment are taken. Anything that looks like production is skipped and counted,
//! the same rule as an import.

use ozbox_core::{CommandRunner, CommandSpec};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::workload::live_reason;

/// Environments a box's own keys may belong to. Production is never one of them.
pub const ENVS: &[&str] = &["dev", "development", "staging", "test", "e2e"];

/// One value the provider holds, by its path under the role.
pub struct Param {
    /// The full path the provider uses, only for telling a person which one was skipped.
    pub path: String,
    pub value: Zeroizing<String>,
}

pub trait Backend {
    fn label(&self) -> &'static str;
    /// Every parameter under `root` (recursively), values decrypted.
    fn fetch(&self, root: &str) -> Result<Vec<Param>, String>;
}

/// AWS Systems Manager Parameter Store, through the `aws` command (no SDK: ADR 0008). The instance role is the credential;
/// its policy reads the role's path and nothing else.
pub struct AwsSsm<'a> {
    pub runner: &'a dyn CommandRunner,
    pub region: String,
}

impl Backend for AwsSsm<'_> {
    fn label(&self) -> &'static str {
        "AWS Parameter Store"
    }
    fn fetch(&self, root: &str) -> Result<Vec<Param>, String> {
        let mut args = vec![
            "ssm".to_string(),
            "get-parameters-by-path".into(),
            "--path".into(),
            root.to_string(),
            "--recursive".into(),
            "--with-decryption".into(),
            "--output".into(),
            "json".into(),
        ];
        if !self.region.is_empty() {
            args.push("--region".into());
            args.push(self.region.clone());
        }
        let out = self
            .runner
            .run(&CommandSpec::new("aws").args(args))
            .map_err(|_| "the aws command could not be started".to_string())?;
        if out.status != Some(0) {
            // the tool's own words can name an account or a path: say only what failed
            return Err(
                "the parameter store could not be read (check the box's role and the path)".into(),
            );
        }
        let v: Value = serde_json::from_str(&out.stdout)
            .map_err(|_| "the parameter store answered badly".to_string())?;
        Ok(v["Parameters"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        Some(Param {
                            path: p["Name"].as_str()?.to_string(),
                            value: Zeroizing::new(p["Value"].as_str()?.to_string()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// OpenBao (a self-hosted vault), through the `bao` command and the environment it reads (`BAO_ADDR`, a token the unit
/// supplies). The role's keys are one secret per project and environment holding `NAME=value` pairs, at
/// `<mount>/<root>/<project>/<env>`.
pub struct OpenBao<'a> {
    pub runner: &'a dyn CommandRunner,
    pub mount: String,
}

impl Backend for OpenBao<'_> {
    fn label(&self) -> &'static str {
        "OpenBao"
    }
    fn fetch(&self, root: &str) -> Result<Vec<Param>, String> {
        let root = root.trim_matches('/');
        let list = self
            .runner
            .run(&CommandSpec::new("bao").args([
                "kv",
                "list",
                "-format=json",
                &format!("-mount={}", self.mount),
                root,
            ]))
            .map_err(|_| "the bao command could not be started".to_string())?;
        if list.status != Some(0) {
            return Err("the vault could not be read (check the box's token and the path)".into());
        }
        let mut out = Vec::new();
        let projects: Vec<String> = serde_json::from_str(&list.stdout).unwrap_or_default();
        for p in projects {
            let p = p.trim_end_matches('/');
            let envs = self
                .runner
                .run(&CommandSpec::new("bao").args([
                    "kv",
                    "list",
                    "-format=json",
                    &format!("-mount={}", self.mount),
                    &format!("{root}/{p}"),
                ]))
                .map_err(|_| "the bao command could not be started".to_string())?;
            let envs: Vec<String> = serde_json::from_str(&envs.stdout).unwrap_or_default();
            for e in envs {
                let e = e.trim_end_matches('/');
                let got = self
                    .runner
                    .run(&CommandSpec::new("bao").args([
                        "kv",
                        "get",
                        "-format=json",
                        &format!("-mount={}", self.mount),
                        &format!("{root}/{p}/{e}"),
                    ]))
                    .map_err(|_| "the bao command could not be started".to_string())?;
                if got.status != Some(0) {
                    continue;
                }
                let v: Value = serde_json::from_str(&got.stdout).unwrap_or(Value::Null);
                if let Some(map) = v["data"]["data"].as_object() {
                    for (k, val) in map {
                        if let Some(s) = val.as_str() {
                            out.push(Param {
                                path: format!("{root}/{p}/{e}/{k}"),
                                value: Zeroizing::new(s.to_string()),
                            });
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

/// A value ready for the service: where it belongs and what it is.
pub struct Item {
    pub project: String,
    pub env: String,
    pub name: String,
    pub value: Zeroizing<String>,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// Not of the shape `<root>/<project>/<env>/<NAME>`, or an invalid name.
    pub malformed: usize,
    /// An environment that is not one of [`ENVS`], or a value that looks live.
    pub production_looking: usize,
}

/// Turn a provider's parameters under `root` into items. Pure, so it is tested without a provider.
pub fn plan(root: &str, params: Vec<Param>) -> (Vec<Item>, Skipped) {
    let root = root.trim_end_matches('/');
    let mut items = Vec::new();
    let mut skipped = Skipped::default();
    for p in params {
        let Some(rest) = p.path.strip_prefix(root).and_then(|r| r.strip_prefix('/')) else {
            skipped.malformed += 1;
            continue;
        };
        let parts: Vec<&str> = rest.split('/').collect();
        let [project, env, name] = parts[..] else {
            skipped.malformed += 1;
            continue;
        };
        if crate::secrets_enc::workload_name(project, env, name).is_err() {
            skipped.malformed += 1;
            continue;
        }
        if !ENVS.contains(&env) || live_reason(name, &p.value, env).is_some() {
            skipped.production_looking += 1;
            continue;
        }
        items.push(Item {
            project: project.to_string(),
            env: env.to_string(),
            name: name.to_string(),
            value: p.value,
        });
    }
    (items, skipped)
}

/// A box role: the path segment this box reads. Lowercase letters, digits and dashes.
pub fn role_ok(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 32
        && role
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The path this box reads: `<prefix>/<role>`.
pub fn root_for(prefix: &str, role: &str) -> Result<String, String> {
    if !role_ok(role) || !prefix.starts_with('/') || prefix.contains("..") || prefix.contains("//")
    {
        return Err("the box's secret path or role is not valid".into());
    }
    Ok(format!("{}/{role}", prefix.trim_end_matches('/')))
}

/// Replace the in-memory store's workload secrets with `items`: new and changed values are set, anything no longer in the
/// provider is removed (a revoked key stops being offered at the next refresh). Returns how many are now held.
pub fn replace_memory(
    mem: &crate::secrets_enc::EncryptedSecrets,
    role: &str,
    items: &[Item],
) -> Result<usize, crate::secrets::SecretError> {
    use crate::secrets::SecretStore;
    use crate::secrets_enc::{workload_name, Meta};
    let mut keep = std::collections::BTreeSet::new();
    for it in items {
        let full = workload_name(&it.project, &it.env, &it.name)?;
        if mem.get(&full)?.as_deref() != Some(it.value.as_str()) {
            mem.set_with_meta(
                &full,
                &it.value,
                Meta {
                    owner: format!("box-secrets:{role}"),
                    production: false,
                    ..Default::default()
                },
            )?;
        }
        keep.insert(full);
    }
    for n in mem.names("workload.")? {
        if !keep.contains(&n) {
            mem.delete(&n)?;
        }
    }
    Ok(keep.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    const SENTINEL: &str = "SENTINEL-box-secret-0123456789abcdef";

    fn param(path: &str, v: &str) -> Param {
        Param {
            path: path.into(),
            value: Zeroizing::new(v.into()),
        }
    }

    #[test]
    fn only_this_roles_staging_style_keys_are_taken_and_production_looking_ones_are_counted_and_dropped(
    ) {
        let (items, sk) = plan(
            "/ozbox/dev/main",
            vec![
                param(
                    "/ozbox/dev/main/app/staging/SUPABASE_URL",
                    "https://x.example.com",
                ),
                param("/ozbox/dev/main/app/test/STRIPE_KEY", SENTINEL),
                param("/ozbox/dev/main/app/production/DB_URL", "postgres://x"),
                param("/ozbox/dev/main/app/staging/STRIPE_LIVE_KEY", "abc"),
                param(
                    "/ozbox/dev/main/app/staging/OTHER",
                    &format!("sk_{}_abcdef123456", "live"),
                ),
                param("/ozbox/dev/main/app/staging", "short path"),
                param("/ozbox/dev/main/app/staging/bad-name", "x"),
                param("/ozbox/dev/other/app/staging/K", "another role"),
            ],
        );
        let got: Vec<String> = items
            .iter()
            .map(|i| format!("{}/{}/{}", i.project, i.env, i.name))
            .collect();
        assert_eq!(got, ["app/staging/SUPABASE_URL", "app/test/STRIPE_KEY"]);
        assert_eq!(
            sk,
            Skipped {
                malformed: 3,
                production_looking: 3
            }
        );
    }

    #[test]
    fn the_path_and_role_are_checked() {
        assert_eq!(root_for("/ozbox/dev", "main").unwrap(), "/ozbox/dev/main");
        for (p, r) in [
            ("ozbox", "main"),
            ("/a/../b", "main"),
            ("/a", "Main"),
            ("/a", ""),
            ("/a//b", "m"),
        ] {
            assert!(root_for(p, r).is_err(), "{p} {r}");
        }
    }

    #[test]
    fn the_parameter_store_is_read_through_the_aws_command_and_a_failure_names_no_path() {
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: format!(
                "{{\"Parameters\":[{{\"Name\":\"/r/a/staging/K\",\"Value\":\"{SENTINEL}\"}}]}}"
            ),
            stderr: String::new(),
        });
        let b = AwsSsm {
            runner: &r,
            region: "us-east-1".into(),
        };
        let p = b.fetch("/r").unwrap();
        assert_eq!(p[0].path, "/r/a/staging/K");
        let c = &r.calls()[0];
        let joined = c.args.join(" ");
        assert!(
            joined.contains("get-parameters-by-path")
                && joined.contains("--with-decryption")
                && !joined.contains(SENTINEL)
        );
        r.reply(Output {
            status: Some(255),
            stdout: String::new(),
            stderr: "AccessDenied for arn:aws:ssm:secret-path".into(),
        });
        let e = b.fetch("/r").err().unwrap();
        assert!(!e.contains("arn") && !e.contains("secret-path"));
    }

    #[test]
    fn openbao_pairs_become_parameters() {
        let r = RecordingRunner::new();
        let ok = |s: &str| Output {
            status: Some(0),
            stdout: s.into(),
            stderr: String::new(),
        };
        r.reply(ok("[\"app/\"]"));
        r.reply(ok("[\"staging\"]"));
        r.reply(ok(&format!(
            "{{\"data\":{{\"data\":{{\"K\":\"{SENTINEL}\"}}}}}}"
        )));
        let b = OpenBao {
            runner: &r,
            mount: "secret".into(),
        };
        let p = b.fetch("ozbox/main").unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].path, "ozbox/main/app/staging/K");
    }

    #[test]
    fn the_memory_store_follows_the_provider_and_holds_no_plaintext() {
        use crate::secrets::SecretStore;
        use crate::secrets_enc::{KeyProvider, LocalKekProvider};
        use std::sync::Arc;
        let d = tempfile::tempdir().unwrap();
        let prov: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let mem =
            crate::secrets_enc::EncryptedSecrets::new(d.path().join("mem.json"), "box-a", prov)
                .unwrap();
        let item = |n: &str, v: &str| Item {
            project: "app".into(),
            env: "staging".into(),
            name: n.into(),
            value: Zeroizing::new(v.into()),
        };
        assert_eq!(
            replace_memory(
                &mem,
                "main",
                &[item("A", SENTINEL), item("B", "two-two-two")]
            )
            .unwrap(),
            2
        );
        assert_eq!(
            mem.get("workload.app.staging.A").unwrap().as_deref(),
            Some(SENTINEL)
        );
        assert!(!std::fs::read_to_string(d.path().join("mem.json"))
            .unwrap()
            .contains(SENTINEL));
        assert!(
            !mem.meta("workload.app.staging.A")
                .unwrap()
                .unwrap()
                .production
        );
        // a key revoked at the provider disappears at the next refresh
        assert_eq!(
            replace_memory(&mem, "main", &[item("A", "rotated-rotated")]).unwrap(),
            1
        );
        assert!(mem.get("workload.app.staging.B").unwrap().is_none());
        assert_eq!(
            mem.get("workload.app.staging.A").unwrap().as_deref(),
            Some("rotated-rotated")
        );
    }
}
