//! What a box's own secrets declaration is, and how the box learns it (ADR 0023, item 5).
//!
//! The declaration lives with the box's infrastructure, not in a file on the box: the OpenTofu module takes a backend, a
//! path prefix and a role, writes them as instance tags and grants the instance role read access to exactly that prefix.
//! At boot (and when asked) a root step reads the tags from the instance metadata service and writes the loader's settings,
//! `/etc/ozbox/box-secrets.env`. Nothing about it is in the first-boot configuration, which is at its size limit, and
//! nothing in it is a secret. A box with no tags writes nothing, and one that is not on AWS (no metadata service) is left
//! as it is, so a settings file placed by hand keeps working.

use std::path::Path;

pub const BACKENDS: &[&str] = &["aws-ssm", "openbao"];
pub const TAG_BACKEND: &str = "ozbox-secrets-backend";
pub const TAG_PATH: &str = "ozbox-secrets-path";
pub const TAG_ROLE: &str = "ozbox-box-role";
pub const TAG_REGION: &str = "ozbox-region";
/// The first line of a file this step wrote, so it never removes or rewrites one a person placed.
pub const MARKER: &str = "# written by ozbox secrets configure-box from the instance tags";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxConfig {
    pub backend: String,
    pub path: String,
    pub role: String,
    pub region: String,
}

fn path_ok(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 128
        && !p.contains("//")
        && !p.contains("..")
        && !p.ends_with('/')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'))
}

fn region_ok(r: &str) -> bool {
    r.is_empty()
        || (r.len() <= 20
            && r.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

impl BoxConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !BACKENDS.contains(&self.backend.as_str()) {
            return Err("the secrets backend must be aws-ssm or openbao".into());
        }
        if !path_ok(&self.path) {
            return Err(
                "the secrets path must start with / and hold only letters, digits and / _ . -"
                    .into(),
            );
        }
        if !crate::box_secrets::role_ok(&self.role) {
            return Err("the box role must be lowercase letters, digits and dashes".into());
        }
        if !region_ok(&self.region) {
            return Err("the region is not valid".into());
        }
        Ok(())
    }

    /// The loader's settings file. Plain `NAME=value` lines a service manager reads; no quoting is needed because every
    /// value was validated to plain characters above.
    pub fn render(&self) -> String {
        format!(
            "{MARKER}\nOZBOX_BOX_SECRETS_BACKEND={}\nOZBOX_BOX_SECRETS_PATH={}\nOZBOX_BOX_ROLE={}\nOZBOX_BOX_SECRETS_REGION={}\n",
            self.backend, self.path, self.role, self.region
        )
    }
}

/// Where instance tags are read from. The real one is the metadata service; a test gives its own.
pub trait Tags {
    /// `Ok(None)` when there is no metadata service at all (not an AWS machine).
    fn available(&self) -> bool;
    fn get(&self, key: &str) -> Option<String>;
    /// One tag, with a read that did not work told apart from a tag that is not there. Anything that DECIDES from a missing tag
    /// uses this: a timeout, a throttle or a server error is not "no such tag". The default is for a source that cannot fail.
    fn read(&self, key: &str) -> TagRead {
        self.get(key).map_or(TagRead::Absent, TagRead::Present)
    }
}

/// What reading one instance tag came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagRead {
    Present(String),
    /// The metadata service answered "no such tag" (404), or the tag is empty.
    Absent,
    /// It did not answer, or answered with an error that is not "no such tag".
    Unreadable,
}

/// The declaration in the tags: `Ok(None)` when the box has none.
pub fn from_tags(t: &dyn Tags) -> Result<Option<BoxConfig>, String> {
    let (Some(backend), Some(path), Some(role)) =
        (t.get(TAG_BACKEND), t.get(TAG_PATH), t.get(TAG_ROLE))
    else {
        return Ok(None);
    };
    let c = BoxConfig {
        backend,
        path,
        role,
        region: t.get(TAG_REGION).unwrap_or_default(),
    };
    c.validate()?;
    Ok(Some(c))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Not an AWS machine: nothing was read and nothing was changed.
    NoMetadata,
    Written,
    Unchanged,
    /// The tags are gone and a file this step wrote was removed.
    Removed,
    /// The tags are absent and there is nothing of ours to remove.
    NothingDeclared,
}

pub fn configure(t: &dyn Tags, env_file: &Path) -> Result<Outcome, String> {
    use std::os::unix::fs::PermissionsExt;
    if !t.available() {
        return Ok(Outcome::NoMetadata);
    }
    let current = std::fs::read_to_string(env_file).ok();
    match from_tags(t)? {
        None => match current {
            Some(c) if c.starts_with(MARKER) => {
                std::fs::remove_file(env_file)
                    .map_err(|_| "the settings file could not be removed".to_string())?;
                Ok(Outcome::Removed)
            }
            _ => Ok(Outcome::NothingDeclared),
        },
        Some(c) => {
            let want = c.render();
            // a file a person placed (no marker) is theirs: the declaration does not overwrite it
            if let Some(cur) = &current {
                if !cur.starts_with(MARKER) {
                    return Err("a settings file placed by hand is already there; remove it to use the instance tags".into());
                }
                if *cur == want {
                    return Ok(Outcome::Unchanged);
                }
            }
            let tmp = env_file.with_extension("tmp");
            std::fs::write(&tmp, &want)
                .map_err(|_| "the settings file could not be written".to_string())?;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
            std::fs::rename(&tmp, env_file)
                .map_err(|_| "the settings file could not be written".to_string())?;
            Ok(Outcome::Written)
        }
    }
}

/// The metadata service of an EC2 machine (IMDSv2, a token for each read; the instance's hop limit of 1 keeps it on the
/// machine). Not an outbound request on anyone's say-so, so it does not go through the guarded client.
pub struct Imds {
    base: String,
    token: Option<String>,
}

impl Imds {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(2))
            .build();
        let token = agent
            .put(&format!("{base}/latest/api/token"))
            .set("X-aws-ec2-metadata-token-ttl-seconds", "60")
            .call()
            .ok()
            .and_then(|r| r.into_string().ok());
        Self {
            base: base.to_string(),
            token,
        }
    }
}

impl Tags for Imds {
    fn available(&self) -> bool {
        self.token.is_some()
    }
    fn get(&self, key: &str) -> Option<String> {
        match self.read(key) {
            TagRead::Present(v) => Some(v),
            TagRead::Absent | TagRead::Unreadable => None,
        }
    }
    fn read(&self, key: &str) -> TagRead {
        let Some(tok) = self.token.as_deref() else {
            return TagRead::Unreadable;
        };
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(2))
            .build();
        match agent
            .get(&format!(
                "{}/latest/meta-data/tags/instance/{key}",
                self.base
            ))
            .set("X-aws-ec2-metadata-token", tok)
            .call()
        {
            Ok(r) => match r.into_string() {
                Ok(s) if s.trim().is_empty() => TagRead::Absent,
                Ok(s) => TagRead::Present(s.trim().to_string()),
                Err(_) => TagRead::Unreadable,
            },
            // only the service's own "no such tag" is an absence; a throttle, a 5xx and a timeout are not
            Err(ureq::Error::Status(404, _)) => TagRead::Absent,
            Err(_) => TagRead::Unreadable,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct Fake {
        up: bool,
        tags: HashMap<&'static str, &'static str>,
    }
    impl Tags for Fake {
        fn available(&self) -> bool {
            self.up
        }
        fn get(&self, k: &str) -> Option<String> {
            self.tags.get(k).map(|v| v.to_string())
        }
    }
    fn declared() -> Fake {
        Fake {
            up: true,
            tags: HashMap::from([
                (TAG_BACKEND, "aws-ssm"),
                (TAG_PATH, "/ozbox/dev"),
                (TAG_ROLE, "main"),
                (TAG_REGION, "us-east-1"),
            ]),
        }
    }

    #[test]
    fn the_declaration_is_read_from_the_tags_validated_and_written_once() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("box-secrets.env");
        assert_eq!(configure(&declared(), &f).unwrap(), Outcome::Written);
        let t = std::fs::read_to_string(&f).unwrap();
        assert!(
            t.starts_with(MARKER)
                && t.contains("OZBOX_BOX_SECRETS_PATH=/ozbox/dev\n")
                && t.contains("OZBOX_BOX_ROLE=main\n")
        );
        assert_eq!(configure(&declared(), &f).unwrap(), Outcome::Unchanged);
        // a change in the tags is a change in the file
        let mut d2 = declared();
        d2.tags.insert(TAG_ROLE, "worker-1");
        assert_eq!(configure(&d2, &f).unwrap(), Outcome::Written);
        assert!(std::fs::read_to_string(&f)
            .unwrap()
            .contains("OZBOX_BOX_ROLE=worker-1"));
        // no tags: the file this step wrote is removed
        let none = Fake {
            up: true,
            tags: HashMap::new(),
        };
        assert_eq!(configure(&none, &f).unwrap(), Outcome::Removed);
        assert!(!f.exists());
        assert_eq!(configure(&none, &f).unwrap(), Outcome::NothingDeclared);
    }

    #[test]
    fn a_machine_with_no_metadata_service_and_a_file_placed_by_hand_are_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("box-secrets.env");
        std::fs::write(&f, "OZBOX_BOX_SECRETS_BACKEND=openbao\n").unwrap();
        let off = Fake {
            up: false,
            tags: HashMap::new(),
        };
        assert_eq!(configure(&off, &f).unwrap(), Outcome::NoMetadata);
        assert!(std::fs::read_to_string(&f).unwrap().contains("openbao"));
        // tags on an AWS machine do not overwrite a hand-placed file; they say so
        assert!(configure(&declared(), &f).is_err());
        assert!(std::fs::read_to_string(&f).unwrap().contains("openbao"));
        let none = Fake {
            up: true,
            tags: HashMap::new(),
        };
        assert_eq!(configure(&none, &f).unwrap(), Outcome::NothingDeclared);
        assert!(f.exists());
    }

    #[test]
    fn a_tag_that_is_not_a_plain_value_is_refused_and_nothing_is_written() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("box-secrets.env");
        for (k, v) in [
            (TAG_BACKEND, "gcp"),
            (TAG_PATH, "relative/path"),
            (TAG_PATH, "/a/../b"),
            (TAG_PATH, "/a b"),
            (TAG_PATH, "/a\nOZBOX_X=1"),
            (TAG_PATH, "/ends/"),
            (TAG_ROLE, "Main"),
            (TAG_REGION, "us east"),
        ] {
            let mut t = declared();
            t.tags.insert(k, v);
            assert!(configure(&t, &f).is_err(), "{k}={v}");
            assert!(!f.exists());
        }
    }
}
