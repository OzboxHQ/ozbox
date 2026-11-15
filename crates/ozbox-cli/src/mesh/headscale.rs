//! The Headscale command line, run where Headscale runs: on this computer, or on the person's own server through `ssh`.
//! Every command is an argv array; every word in it was checked first. A pre-auth key is returned to the caller and kept
//! nowhere here, and no error carries command output (which may hold a key).

use ozbox_core::{CommandRunner, CommandSpec};
use serde_json::Value;

use super::box_tag;

/// The longest a key is valid for. A key is single use, so this is only how long a box has to join.
pub const KEY_TTL: &str = "1h";

pub struct Headscale<'a> {
    runner: &'a dyn CommandRunner,
    /// An SSH host name, or empty for this computer.
    admin_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub online: bool,
    pub tags: Vec<String>,
}

/// What Headscale says about one pre-auth key. Field names follow both of its JSON spellings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub key: String,
    pub reusable: bool,
    pub used: bool,
    /// Seconds since 1970, when the server gives it.
    pub expires: Option<i64>,
    pub tags: Vec<String>,
}

impl KeyInfo {
    fn of(v: &Value) -> Self {
        let b = |k: &str| v[k].as_bool().unwrap_or(false);
        let expires = v["expiration"]["seconds"]
            .as_i64()
            .or_else(|| {
                v["expiration"]["seconds"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
            })
            .or_else(|| {
                v["expiration"]
                    .as_str()
                    .and_then(|s| s.parse::<jiff::Timestamp>().ok())
                    .map(|t| t.as_second())
            });
        let mut tags: Vec<String> = ["acl_tags", "aclTags", "tags"]
            .iter()
            .filter_map(|k| v[*k].as_array())
            .flatten()
            .filter_map(|t| t.as_str().map(String::from))
            .collect();
        tags.sort();
        tags.dedup();
        Self {
            key: v["key"].as_str().unwrap_or_default().to_string(),
            reusable: b("reusable"),
            used: b("used"),
            expires,
            tags,
        }
    }

    /// Fit to join `box_name` once, at `now`: single use, not used yet, not expired, carrying the box's tag. A key with no
    /// expiry the server will state is not fit either.
    pub fn fit_for(&self, box_name: &str, now: i64) -> bool {
        !self.reusable
            && !self.used
            && self.expires.is_some_and(|e| e > now)
            && self.tags.contains(&box_tag(box_name))
    }
}

/// A key is words, digits, `-` and `_`. Anything else is not a key, and is never put in a script.
pub fn key_ok(k: &str) -> bool {
    (16..=256).contains(&k.len())
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl<'a> Headscale<'a> {
    pub fn new(runner: &'a dyn CommandRunner, admin_host: &str) -> Self {
        Self {
            runner,
            admin_host: admin_host.to_string(),
        }
    }

    fn spec(&self, args: &[&str]) -> CommandSpec {
        if self.admin_host.is_empty() {
            CommandSpec::new("headscale").args(args.iter().copied())
        } else {
            // ssh joins the words with spaces for the remote shell: every word here is plain (checked by the callers).
            let mut v = vec!["-o", "BatchMode=yes", self.admin_host.as_str(), "headscale"];
            v.extend_from_slice(args);
            CommandSpec::new("ssh").args(v)
        }
    }

    fn run(&self, spec: &CommandSpec) -> Result<String, &'static str> {
        match self.runner.run(spec) {
            Ok(o) if o.status == Some(0) => Ok(o.stdout),
            Ok(_) => Err("mesh.headscale_failed"),
            Err(ozbox_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err("mesh.headscale_missing")
            }
            Err(_) => Err("mesh.headscale_failed"),
        }
    }

    /// The numeric id of a Headscale user (newer Headscale takes the id, not the name).
    pub fn user_id(&self, user: &str) -> Result<u64, &'static str> {
        let out = self.run(&self.spec(&["users", "list", "--output", "json"]))?;
        let v: Value = serde_json::from_str(&out).map_err(|_| "mesh.headscale_bad_answer")?;
        let bare = user.trim_end_matches('@');
        v.as_array()
            .ok_or("mesh.headscale_bad_answer")?
            .iter()
            .find(|u| u["name"].as_str() == Some(bare))
            .and_then(|u| u["id"].as_u64())
            .ok_or("mesh.no_such_user")
    }

    /// A one-use key for one box, valid for [`KEY_TTL`], that makes the node carry the box's tag.
    pub fn mint_key(&self, user_id: u64, box_name: &str) -> Result<String, &'static str> {
        let id = user_id.to_string();
        let tag = box_tag(box_name);
        let out = self.run(&self.spec(&[
            "preauthkeys",
            "create",
            "--user",
            &id,
            "--tags",
            &tag,
            "--expiration",
            KEY_TTL,
            "--output",
            "json",
        ]))?;
        let v: Value = serde_json::from_str(&out).map_err(|_| "mesh.headscale_bad_answer")?;
        let key = v["key"].as_str().ok_or("mesh.headscale_bad_answer")?;
        if !key_ok(key) {
            return Err("mesh.headscale_bad_answer");
        }
        Ok(key.to_string())
    }

    /// Replace the policy. The document goes in on standard input; it needs Headscale's `policy.mode: database`.
    pub fn set_policy(&self, json: &str) -> Result<(), &'static str> {
        let spec = self
            .spec(&["policy", "set", "--file", "/dev/stdin"])
            .stdin(json.as_bytes().to_vec());
        self.run(&spec).map(|_| ())
    }

    /// The policy the server has loaded (database mode; a file-mode server refuses), as JSON.
    pub fn policy(&self) -> Result<Value, &'static str> {
        let out = self.run(&self.spec(&["policy", "get"]))?;
        serde_json::from_str(&out).map_err(|_| "mesh.headscale_bad_answer")
    }

    /// The pre-auth keys of a user, as the server describes them. No key is kept; the caller compares and drops them.
    pub fn preauth_keys(&self, user_id: u64) -> Result<Vec<KeyInfo>, &'static str> {
        let id = user_id.to_string();
        let out =
            self.run(&self.spec(&["preauthkeys", "list", "--user", &id, "--output", "json"]))?;
        let v: Value = serde_json::from_str(&out).map_err(|_| "mesh.headscale_bad_answer")?;
        let list = v.as_array().ok_or("mesh.headscale_bad_answer")?;
        Ok(list.iter().map(KeyInfo::of).collect())
    }

    pub fn nodes(&self) -> Result<Vec<Node>, &'static str> {
        let out = self.run(&self.spec(&["nodes", "list", "--output", "json"]))?;
        let v: Value = serde_json::from_str(&out).map_err(|_| "mesh.headscale_bad_answer")?;
        let list = v.as_array().ok_or("mesh.headscale_bad_answer")?;
        Ok(list
            .iter()
            .map(|n| {
                let mut tags: Vec<String> = ["forced_tags", "forcedTags", "tags", "valid_tags"]
                    .iter()
                    .filter_map(|k| n[*k].as_array())
                    .flatten()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect();
                tags.sort();
                tags.dedup();
                Node {
                    name: n["given_name"]
                        .as_str()
                        .or_else(|| n["name"].as_str())
                        .unwrap_or("")
                        .to_string(),
                    online: n["online"].as_bool().unwrap_or(false),
                    tags,
                }
            })
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn reply(r: &RecordingRunner, stdout: &str) {
        r.reply(Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        });
    }

    #[test]
    fn a_key_is_minted_for_a_user_id_with_the_boxs_tag_and_one_hour() {
        let r = RecordingRunner::new();
        reply(&r, r#"[{"id":3,"name":"alice"},{"id":4,"name":"bob"}]"#);
        reply(&r, r#"{"key":"hskey-auth-ABCDEFGH-0123456789abcdef"}"#);
        let h = Headscale::new(&r, "");
        let id = h.user_id("alice@").unwrap();
        assert_eq!(id, 3);
        let key = h.mint_key(id, "dev").unwrap();
        assert_eq!(key, "hskey-auth-ABCDEFGH-0123456789abcdef");
        let calls = r.calls();
        assert_eq!(calls[1].program, "headscale");
        assert_eq!(
            calls[1].args,
            [
                "preauthkeys",
                "create",
                "--user",
                "3",
                "--tags",
                "tag:ozbox-dev",
                "--expiration",
                "1h",
                "--output",
                "json"
            ]
        );
        // the key came back on output, never into a command line
        assert!(calls.iter().all(|c| !c.args.join(" ").contains(&key)));
    }

    #[test]
    fn on_a_remote_server_the_command_goes_through_ssh() {
        let r = RecordingRunner::new();
        reply(&r, "[]");
        Headscale::new(&r, "hs.example.com").nodes().unwrap();
        let c = &r.calls()[0];
        assert_eq!(c.program, "ssh");
        assert_eq!(
            c.args[..4],
            ["-o", "BatchMode=yes", "hs.example.com", "headscale"]
        );
    }

    #[test]
    fn an_unusable_key_or_answer_is_an_error_that_carries_no_output() {
        let r = RecordingRunner::new();
        reply(&r, r#"{"key":"bad key; rm -rf"}"#);
        reply(&r, "not json SENTINEL");
        r.reply(Output {
            status: Some(1),
            stdout: "SENTINEL".into(),
            stderr: "SENTINEL".into(),
        });
        let h = Headscale::new(&r, "");
        assert_eq!(h.mint_key(1, "dev"), Err("mesh.headscale_bad_answer"));
        assert_eq!(h.nodes(), Err("mesh.headscale_bad_answer"));
        assert_eq!(h.nodes(), Err("mesh.headscale_failed"));
    }

    #[test]
    fn an_unknown_user_is_named_as_such() {
        let r = RecordingRunner::new();
        reply(&r, r#"[{"id":4,"name":"bob"}]"#);
        assert_eq!(
            Headscale::new(&r, "").user_id("alice"),
            Err("mesh.no_such_user")
        );
    }

    #[test]
    fn the_policy_goes_in_on_standard_input() {
        let r = RecordingRunner::new();
        Headscale::new(&r, "").set_policy("{\"acls\":[]}").unwrap();
        let c = &r.calls()[0];
        assert_eq!(c.stdin.as_deref(), Some(&b"{\"acls\":[]}"[..]));
        assert!(!c.args.join(" ").contains("acls"));
    }

    #[test]
    fn a_hand_made_key_is_fit_only_if_single_use_unused_unexpired_and_tagged_for_the_box() {
        let r = RecordingRunner::new();
        reply(
            &r,
            r#"[{"key":"k1","reusable":false,"used":false,"expiration":{"seconds":2000},"acl_tags":["tag:ozbox-dev"]},
               {"key":"k2","reusable":true,"used":false,"expiration":{"seconds":2000},"aclTags":["tag:ozbox-dev"]},
               {"key":"k3","reusable":false,"used":true,"expiration":"1970-01-01T00:33:20Z","acl_tags":["tag:ozbox-dev"]},
               {"key":"k4","reusable":false,"used":false,"expiration":{"seconds":"500"},"acl_tags":["tag:ozbox-dev"]},
               {"key":"k5","reusable":false,"used":false,"expiration":{"seconds":2000},"acl_tags":["tag:ozbox-build"]},
               {"key":"k6","reusable":false,"used":false,"acl_tags":["tag:ozbox-dev"]}]"#,
        );
        let keys = Headscale::new(&r, "").preauth_keys(3).unwrap();
        assert_eq!(
            r.calls()[0].args,
            ["preauthkeys", "list", "--user", "3", "--output", "json"]
        );
        let fit: Vec<&str> = keys
            .iter()
            .filter(|k| k.fit_for("dev", 1000))
            .map(|k| k.key.as_str())
            .collect();
        assert_eq!(fit, ["k1"]);
        assert_eq!(
            keys[2].expires,
            Some(2000),
            "an RFC 3339 expiry is read too"
        );
    }

    #[test]
    fn the_loaded_policy_is_read_as_json_and_anything_else_is_an_error() {
        let r = RecordingRunner::new();
        reply(&r, r#"{"acls":[]}"#);
        reply(&r, "// a comment\n{}");
        let h = Headscale::new(&r, "");
        assert_eq!(h.policy().unwrap(), serde_json::json!({"acls": []}));
        assert_eq!(r.calls()[0].args, ["policy", "get"]);
        assert_eq!(h.policy(), Err("mesh.headscale_bad_answer"));
    }

    #[test]
    fn nodes_are_read_with_their_tags() {
        let r = RecordingRunner::new();
        reply(
            &r,
            r#"[{"given_name":"dev","online":true,"forced_tags":["tag:ozbox-dev"]},{"name":"laptop","online":false}]"#,
        );
        let n = Headscale::new(&r, "").nodes().unwrap();
        assert_eq!(n[0].name, "dev");
        assert!(n[0].online);
        assert_eq!(n[0].tags, ["tag:ozbox-dev"]);
        assert!(!n[1].online);
    }
}
