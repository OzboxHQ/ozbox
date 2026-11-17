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

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aws_native::{service_base, valid_region, AwsJson, Failure};
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

/// AWS Systems Manager Parameter Store, called natively (ADR 0008: no SDK, and no `aws` command: the box image does not carry
/// it). The request is AWS JSON (`AmazonSSM.GetParametersByPath`) signed with SigV4 by the box's own role (see
/// [`crate::aws_native`]); its policy reads the role's path and nothing else. A value is in the answer only, zeroized, and
/// never in an argument, a file, a log or an error.
pub struct AwsSsm {
    client: AwsJson,
    region: String,
    /// The service's address, for a test; `None` is the real one for the region.
    base: Option<String>,
}

/// The most pages one read follows (ten parameters each), so a service that never stops answering cannot hold the loader.
const MAX_PAGES: usize = 100;

pub const SSM_DENIED: &str =
    "the parameter store refused this box's role (check the role's policy and the path)";
pub const SSM_UNAVAILABLE: &str = "the parameter store could not be read (check the box's role, the path and that the box can reach the parameter store)";

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ByPathRequest<'a> {
    path: &'a str,
    recursive: bool,
    with_decryption: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_token: Option<&'a str>,
}

#[derive(Deserialize)]
struct ByPathAnswer {
    #[serde(rename = "Parameters", default)]
    parameters: Vec<RawParam>,
    #[serde(rename = "NextToken", default)]
    next_token: Option<String>,
}

#[derive(Deserialize)]
struct RawParam {
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Value", default, deserialize_with = "zeroizing_opt")]
    value: Option<Zeroizing<String>>,
}

fn zeroizing_opt<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|o| o.map(Zeroizing::new))
}

impl AwsSsm {
    /// `region` is the declared one, or empty for the environment's, else this machine's own.
    pub fn new(region: &str) -> Self {
        Self::build(AwsJson::new(), region, None)
    }

    fn build(client: AwsJson, region: &str, base: Option<&str>) -> Self {
        Self {
            client,
            region: region.to_string(),
            base: base.map(str::to_string),
        }
    }
}

impl Backend for AwsSsm {
    fn label(&self) -> &'static str {
        "AWS Parameter Store"
    }
    fn fetch(&self, root: &str) -> Result<Vec<Param>, String> {
        let region = if self.region.is_empty() {
            self.client.region_or_default(None)
        } else if valid_region(&self.region) {
            Some(self.region.clone())
        } else {
            return Err("the box's parameter store region is not valid".into());
        }
        .ok_or_else(|| SSM_UNAVAILABLE.to_string())?;
        let base = self
            .base
            .clone()
            .unwrap_or_else(|| service_base("ssm", &region));
        let mut out = Vec::new();
        let mut token: Option<Zeroizing<String>> = None;
        for _ in 0..MAX_PAGES {
            let body = Zeroizing::new(
                serde_json::to_vec(&ByPathRequest {
                    path: root,
                    recursive: true,
                    with_decryption: true,
                    next_token: token.as_deref().map(String::as_str),
                })
                .map_err(|_| SSM_UNAVAILABLE.to_string())?,
            );
            let answer = self
                .client
                .call(&base, &region, "ssm", "AmazonSSM.GetParametersByPath", body)
                .map_err(|f| match f {
                    Failure::Denied => SSM_DENIED.to_string(),
                    Failure::Unavailable => SSM_UNAVAILABLE.to_string(),
                })?;
            // the parser's own words can quote the text it choked on: say only that it was bad
            let page: ByPathAnswer = serde_json::from_slice(&answer)
                .map_err(|_| "the parameter store answered badly".to_string())?;
            for p in page.parameters {
                if let (Some(path), Some(value)) = (p.name, p.value) {
                    out.push(Param { path, value });
                }
            }
            match page.next_token.filter(|t| !t.is_empty()) {
                Some(t) => token = Some(Zeroizing::new(t)),
                None => return Ok(out),
            }
        }
        Err("the parameter store has more parameters under this path than the box reads".into())
    }
}

/// OpenBao (a self-hosted vault, KV version 2), called natively (see [`crate::openbao`]: no `bao` command, which the box image
/// does not carry). The address and a token come from the environment the unit supplies (`BAO_ADDR`, `BAO_TOKEN`); the token
/// is read at each request and never kept. The role's keys are one secret per project and environment holding `NAME=value`
/// pairs, at `<mount>/<root>/<project>/<env>`. A read is all or nothing: a refusal or an outage part way is an error, never a
/// partial list (which would remove the keys it missed from memory).
pub struct OpenBao {
    pub vault: Option<crate::openbao::Bao>,
    pub mount: String,
}

pub const BAO_DENIED: &str =
    "the vault refused this box's token (check the token's policy and the path)";
pub const BAO_UNAVAILABLE: &str = "the vault could not be read (check the box's token, its address and that the box can reach it)";

fn bao_error(f: crate::openbao::Failure) -> String {
    match f {
        crate::openbao::Failure::Denied => BAO_DENIED.to_string(),
        _ => BAO_UNAVAILABLE.to_string(),
    }
}

impl OpenBao {
    /// The vault the environment names, with the mount given.
    pub fn from_env(mount: String) -> Self {
        Self {
            vault: crate::openbao::Bao::from_env(),
            mount,
        }
    }
}

impl Backend for OpenBao {
    fn label(&self) -> &'static str {
        "OpenBao"
    }
    fn fetch(&self, root: &str) -> Result<Vec<Param>, String> {
        use crate::openbao::plain_segment;
        let vault = self
            .vault
            .as_ref()
            .ok_or_else(|| "the vault address is not set or not https://host[:port]".to_string())?;
        let root = root.trim_matches('/');
        let mut out = Vec::new();
        for p in vault.list(&self.mount, root).map_err(bao_error)? {
            let p = p.trim_end_matches('/');
            if !plain_segment(p) {
                continue;
            }
            for e in vault
                .list(&self.mount, &format!("{root}/{p}"))
                .map_err(bao_error)?
            {
                let e = e.trim_end_matches('/');
                if !plain_segment(e) {
                    continue;
                }
                let Some(fields) = vault
                    .read(&self.mount, &format!("{root}/{p}/{e}"))
                    .map_err(bao_error)?
                else {
                    continue;
                };
                for (k, value) in fields {
                    out.push(Param {
                        path: format!("{root}/{p}/{e}/{k}"),
                        value,
                    });
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
    use serde_json::Value;

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

    use crate::aws_native::fakes::{self, json, seen_of, Fake, Seen};
    use std::sync::{Arc, Mutex};

    type Handler = dyn Fn(usize, &Seen) -> (u16, String) + Send + Sync;

    /// A loopback parameter store: every request is recorded, and `handler(n, request)` says what the n-th one gets.
    struct Ssm {
        base: String,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    fn ssm(handler: Arc<Handler>) -> Ssm {
        let srv = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base = format!("http://{}", srv.server_addr().to_ip().unwrap());
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let log = seen.clone();
        std::thread::spawn(move || {
            for mut r in srv.incoming_requests() {
                let s = seen_of(&mut r);
                let n = {
                    let mut l = log.lock().unwrap();
                    l.push(s.clone());
                    l.len() - 1
                };
                let (code, body) = handler(n, &s);
                let _ = r.respond(json(code, &body));
            }
        });
        Ssm { base, seen }
    }

    fn against(f: &Fake, s: &Ssm, region: &str) -> AwsSsm {
        AwsSsm::build(AwsJson::with_imds(&f.imds), region, Some(&s.base))
    }

    fn page(names: &[(&str, &str)], next: Option<&str>) -> String {
        let ps: Vec<Value> = names
            .iter()
            .map(|(n, v)| serde_json::json!({"Name": n, "Value": v, "Type": "SecureString"}))
            .collect();
        match next {
            Some(t) => serde_json::json!({"Parameters": ps, "NextToken": t}),
            None => serde_json::json!({"Parameters": ps}),
        }
        .to_string()
    }

    #[test]
    fn the_parameter_store_is_called_natively_with_a_signed_request_for_the_path_recursively_decrypted(
    ) {
        let f = Fake::start();
        let s = ssm(Arc::new(|_, _| {
            (200, page(&[("/r/a/staging/K", SENTINEL)], None))
        }));
        let p = against(&f, &s, "us-east-1").fetch("/r").unwrap();
        assert_eq!((p.len(), p[0].path.as_str()), (1, "/r/a/staging/K"));
        assert_eq!(p[0].value.as_str(), SENTINEL);
        let seen = s.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let r = &seen[0];
        assert_eq!(r.method, "POST");
        assert_eq!(
            r.header("x-amz-target"),
            Some("AmazonSSM.GetParametersByPath")
        );
        assert_eq!(r.header("content-type"), Some("application/x-amz-json-1.1"));
        assert_eq!(r.header("x-amz-security-token"), Some(fakes::SESSION_TOKEN));
        let auth = r.header("authorization").unwrap();
        assert!(auth.contains(&format!("Credential={}/", fakes::ACCESS_KEY)));
        assert!(auth.contains("/us-east-1/ssm/aws4_request"), "{auth}");
        let body: Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(body["Path"], "/r");
        assert_eq!(body["Recursive"], true);
        assert_eq!(body["WithDecryption"], true);
        assert!(body.get("NextToken").is_none());
        // the secret key never leaves the signer
        assert!(!format!("{:?}", r.headers).contains(fakes::SECRET_KEY));
    }

    #[test]
    fn three_pages_are_followed_by_their_tokens_and_all_of_them_returned() {
        let f = Fake::start();
        let s = ssm(Arc::new(|n, req| {
            let body: Value = serde_json::from_str(&req.body).unwrap();
            match n {
                0 => {
                    assert!(body.get("NextToken").is_none());
                    (200, page(&[("/r/a/test/A", "one-one-one")], Some("tok-1")))
                }
                1 => {
                    assert_eq!(body["NextToken"], "tok-1");
                    (200, page(&[("/r/a/test/B", "two-two-two")], Some("tok-2")))
                }
                _ => {
                    assert_eq!(body["NextToken"], "tok-2");
                    (200, page(&[("/r/a/test/C", SENTINEL)], None))
                }
            }
        }));
        let p = against(&f, &s, "us-east-1").fetch("/r").unwrap();
        let names: Vec<&str> = p.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(names, ["/r/a/test/A", "/r/a/test/B", "/r/a/test/C"]);
        assert_eq!(s.seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn a_store_that_never_stops_paging_is_cut_off_with_an_error_not_a_partial_read() {
        let f = Fake::start();
        let s = ssm(Arc::new(|_, _| (200, page(&[], Some("again")))));
        let e = against(&f, &s, "us-east-1").fetch("/r").err().unwrap();
        assert!(e.contains("more parameters"), "{e}");
        assert_eq!(s.seen.lock().unwrap().len(), MAX_PAGES);
    }

    #[test]
    fn access_denied_and_unreachable_are_told_apart_and_name_no_path_or_value() {
        let f = Fake::start();
        let denied = ssm(Arc::new(|_, _| {
            (
                400,
                format!(
                    r#"{{"__type":"AccessDeniedException","message":"User: arn:aws:sts::123456789012:assumed-role/x is not authorized to perform ssm:GetParametersByPath on /secret-path {SENTINEL}"}}"#
                ),
            )
        }));
        let e = against(&f, &denied, "us-east-1").fetch("/r").err().unwrap();
        assert_eq!(e, SSM_DENIED);
        for bad in ["arn", "secret-path", "assumed-role", SENTINEL] {
            assert!(!e.contains(bad), "{e}");
        }
        // a throttle and a server error are a reason to try again, never a refusal
        for (code, body) in [
            (400, r#"{"__type":"ThrottlingException"}"#.to_string()),
            (500, format!("boom {SENTINEL}")),
        ] {
            let s = ssm(Arc::new(move |_, _| (code, body.clone())));
            let e = against(&f, &s, "us-east-1").fetch("/r").err().unwrap();
            assert_eq!(e, SSM_UNAVAILABLE);
            assert!(!e.contains(SENTINEL));
        }
        // nothing listens
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let b = AwsSsm::build(AwsJson::with_imds(&f.imds), "us-east-1", Some(&dead));
        assert_eq!(b.fetch("/r").err().unwrap(), SSM_UNAVAILABLE);
        // no metadata service and no environment: no credentials, so unavailable (never denied)
        let s = ssm(Arc::new(|_, _| (200, page(&[], None))));
        let down = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let b = AwsSsm::build(AwsJson::with_imds(&down), "us-east-1", Some(&s.base));
        assert_eq!(b.fetch("/r").err().unwrap(), SSM_UNAVAILABLE);
        assert!(s.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn an_answer_that_is_not_what_the_store_sends_is_one_plain_error_with_no_value_in_it() {
        let f = Fake::start();
        // truncated JSON that carries a value, and a wrong shape that carries one
        for body in [
            format!(r#"{{"Parameters":[{{"Name":"/r/a/test/K","Value":"{SENTINEL}""#),
            format!(r#"{{"Parameters":"{SENTINEL}"}}"#),
        ] {
            let s = ssm(Arc::new(move |_, _| (200, body.clone())));
            let e = against(&f, &s, "us-east-1").fetch("/r").err().unwrap();
            assert_eq!(e, "the parameter store answered badly");
        }
        // an entry with no name or no value is skipped, as before
        let s = ssm(Arc::new(|_, _| {
            (
                200,
                r#"{"Parameters":[{"Name":"/r/a/test/K"},{"Value":"v"},{"Name":"/r/a/test/J","Value":"jjjjjjjj"}]}"#.into(),
            )
        }));
        let p = against(&f, &s, "us-east-1").fetch("/r").unwrap();
        assert_eq!(p.len(), 1);
        // a region that is not one is refused before anything is sent
        let e = against(&f, &s, "US EAST;1").fetch("/r").err().unwrap();
        assert!(e.contains("region"));
    }

    #[test]
    fn the_region_comes_from_the_setting_else_the_machine_and_is_what_the_request_is_signed_for() {
        let f = Fake::start();
        let s = ssm(Arc::new(|_, _| (200, page(&[], None))));
        against(&f, &s, "ap-south-1").fetch("/r").unwrap();
        if std::env::var("AWS_REGION").is_err() && std::env::var("AWS_DEFAULT_REGION").is_err() {
            against(&f, &s, "").fetch("/r").unwrap();
            let seen = s.seen.lock().unwrap();
            assert!(seen[0]
                .header("authorization")
                .unwrap()
                .contains("/ap-south-1/ssm/"));
            // the fake metadata service says eu-west-2
            assert!(seen[1]
                .header("authorization")
                .unwrap()
                .contains("/eu-west-2/ssm/"));
        }
    }

    #[test]
    fn the_parameter_store_works_with_no_aws_command_anywhere() {
        // Run a read in a child process whose PATH holds nothing, so any attempt to start the `aws` command (the defect this
        // replaces) would fail it. The child is this same test binary, asked for one test.
        if std::env::var("OZBOX_SSM_NO_AWS_CHILD").is_ok() {
            let f = Fake::start();
            let s = ssm(Arc::new(|_, _| {
                (200, page(&[("/r/a/test/K", SENTINEL)], None))
            }));
            let p = against(&f, &s, "us-east-1").fetch("/r").unwrap();
            assert_eq!(p[0].value.as_str(), SENTINEL);
            return;
        }
        let empty = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "box_secrets::tests::the_parameter_store_works_with_no_aws_command_anywhere",
                "--nocapture",
            ])
            .env("OZBOX_SSM_NO_AWS_CHILD", "1")
            .env("PATH", empty.path())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    #[test]
    fn the_box_secrets_path_never_starts_a_program() {
        // a guard on the source: a loader that needs a program the image does not carry is the defect. Only the code before
        // the tests, and not a comment, is read; the programs are named by building the needles, so this file passes.
        let src = include_str!("box_secrets.rs");
        let code: String = src
            .split("\n#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // nothing here may run a program: neither `aws` (the parameter store) nor `bao` (the vault)
        for needle in [
            ["CommandSpec::new(", "\"aws\")"].concat(),
            ["CommandSpec::new(", "\"bao\")"].concat(),
            ["program: ", "\"aws\""].concat(),
            ["Command", "::new("].concat(),
            ["Command", "Runner"].concat(),
            ["\"get-parameters", "-by-path\""].concat(),
            ["\"--with", "-decryption\""].concat(),
        ] {
            assert!(!code.contains(&needle), "{needle}");
        }
        assert!(
            !code.contains("runner"),
            "no backend takes a command runner"
        );
    }

    #[test]
    fn openbao_is_read_natively_all_three_levels_and_pairs_become_parameters() {
        let v = crate::openbao::fakes::Vault::start();
        v.put(
            "secret/ozbox/main/app/staging",
            &[("K", SENTINEL), ("J", "jjjjjjjj")],
        );
        v.put("secret/ozbox/main/app/test", &[("T", "tttttttt")]);
        v.put("secret/ozbox/other/app/staging", &[("X", "another role")]);
        let b = OpenBao {
            vault: Some(v.client()),
            mount: "secret".into(),
        };
        let mut p: Vec<(String, String)> = b
            .fetch("ozbox/main")
            .unwrap()
            .into_iter()
            .map(|p| (p.path, p.value.to_string()))
            .collect();
        p.sort();
        assert_eq!(
            p,
            [
                (
                    "ozbox/main/app/staging/J".to_string(),
                    "jjjjjjjj".to_string()
                ),
                ("ozbox/main/app/staging/K".into(), SENTINEL.into()),
                ("ozbox/main/app/test/T".into(), "tttttttt".into()),
            ]
        );
        let seen: Vec<String> = v
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| format!("{} {}", s.method, s.url))
            .collect();
        assert_eq!(seen[0], "GET /v1/secret/metadata/ozbox/main?list=true");
        assert!(seen.iter().all(|s| s.starts_with("GET /v1/secret/")));
        // they plan like any other provider's
        let (items, _) = plan("ozbox/main", b.fetch("ozbox/main").unwrap());
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn a_vault_refusal_or_outage_part_way_is_an_error_never_a_partial_read_and_names_nothing() {
        let v = crate::openbao::fakes::Vault::start();
        v.put("secret/r/app/staging", &[("K", SENTINEL)]);
        let b = OpenBao {
            vault: Some(v.client()),
            mount: "secret".into(),
        };
        *v.force.lock().unwrap() = Some((403, format!("denied {SENTINEL} r/app")));
        let e = b.fetch("r").err().unwrap();
        assert_eq!(e, BAO_DENIED);
        *v.force.lock().unwrap() = Some((503, format!("sealed {SENTINEL}")));
        assert_eq!(b.fetch("r").err().unwrap(), BAO_UNAVAILABLE);
        for e in [BAO_DENIED, BAO_UNAVAILABLE] {
            assert!(!e.contains(SENTINEL) && !e.contains(crate::openbao::fakes::TOKEN));
        }
        // no address configured: said, and nothing sent
        let none = OpenBao {
            vault: None,
            mount: "secret".into(),
        };
        assert!(none.fetch("r").err().unwrap().contains("address"));
    }

    #[test]
    fn openbao_works_with_no_bao_command_anywhere() {
        // A read in a child process whose PATH holds nothing, so any attempt to start the `bao` command (the defect this
        // replaces) would fail it. The child is this same test binary, asked for one test.
        if std::env::var("OZBOX_BAO_NO_PROGRAM_CHILD").is_ok() {
            let v = crate::openbao::fakes::Vault::start();
            v.put("secret/r/app/test", &[("K", SENTINEL)]);
            let b = OpenBao {
                vault: Some(v.client()),
                mount: "secret".into(),
            };
            let p = b.fetch("r").unwrap();
            assert_eq!(p[0].value.as_str(), SENTINEL);
            return;
        }
        let empty = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "box_secrets::tests::openbao_works_with_no_bao_command_anywhere",
                "--nocapture",
            ])
            .env("OZBOX_BAO_NO_PROGRAM_CHILD", "1")
            .env("PATH", empty.path())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
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
