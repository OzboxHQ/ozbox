//! A fleet store that two computers can share: one object with compare-and-swap writes.
//!
//! The store's document is one JSON object. A write names the version it was based on and succeeds only if that is still
//! the current version; otherwise the writer is told it lost, reads again and redoes its change. That single rule is what
//! lets two dashboards on two computers share one lease and one set of claims without a coordinator: whatever they do,
//! exactly one write wins each version.
//!
//! [`MemShared`] is the in-memory object the tests use for two computers; [`ObjectShared`] is an S3 object reached through
//! the AWS command line (conditional `put-object`, no SDK, no listening port: the dashboard only ever calls out).

#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use ozbox_core::exec::{CommandRunner, CommandSpec};

/// A version tag the object store hands back (an ETag, or a counter in memory).
pub type Version = String;

#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    Done(Version),
    /// Someone else wrote first.
    Conflict,
}

pub trait Shared: Send + Sync + Debug {
    /// The current bytes and version, or `None` when nothing has been written yet.
    fn get(&self) -> io::Result<Option<(Vec<u8>, Version)>>;
    /// Write `bytes` only if the current version is `expect` (`None`: only if nothing exists yet).
    fn put_if(&self, expect: Option<&str>, bytes: &[u8]) -> io::Result<Put>;
}

/// An object in memory (tests only), shared by cloning the `Arc`. A computer that cannot reach it can be simulated with `cut`.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemShared {
    inner: Mutex<(Option<Vec<u8>>, u64)>,
    cut: Mutex<BTreeMap<String, bool>>,
}

#[cfg(test)]
impl MemShared {
    pub fn new() -> Arc<MemShared> {
        Arc::new(MemShared::default())
    }

    /// A handle for one computer. `cut(name, true)` makes that computer's calls fail like a network that is down.
    pub fn handle(self: &Arc<Self>, name: &str) -> Arc<dyn Shared> {
        Arc::new(MemHandle {
            base: Arc::clone(self),
            name: name.to_string(),
        })
    }

    pub fn cut(&self, name: &str, down: bool) {
        if let Ok(mut c) = self.cut.lock() {
            c.insert(name.to_string(), down);
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct MemHandle {
    base: Arc<MemShared>,
    name: String,
}

#[cfg(test)]
impl MemHandle {
    fn check(&self) -> io::Result<()> {
        let down = self
            .base
            .cut
            .lock()
            .map(|c| c.get(&self.name).copied().unwrap_or(false))
            .unwrap_or(false);
        if down {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the shared store cannot be reached",
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
impl Shared for MemHandle {
    fn get(&self) -> io::Result<Option<(Vec<u8>, Version)>> {
        self.check()?;
        let g = self
            .base
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?;
        Ok(g.0.clone().map(|b| (b, g.1.to_string())))
    }

    fn put_if(&self, expect: Option<&str>, bytes: &[u8]) -> io::Result<Put> {
        self.check()?;
        let mut g = self
            .base
            .inner
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?;
        let cur = g.0.as_ref().map(|_| g.1.to_string());
        if cur.as_deref() != expect {
            return Ok(Put::Conflict);
        }
        g.1 += 1;
        g.0 = Some(bytes.to_vec());
        Ok(Put::Done(g.1.to_string()))
    }
}

/// An S3 object, through `aws s3api` (conditional writes: `--if-match <etag>`, `--if-none-match "*"`).
pub struct ObjectShared {
    pub bucket: String,
    pub key: String,
    pub profile: Option<String>,
    pub runner: Arc<dyn CommandRunner>,
    pub scratch: PathBuf,
}

impl Debug for ObjectShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectShared(s3://{}/{})", self.bucket, self.key)
    }
}

/// `s3://bucket/key` to its two parts. Both are checked: a bucket is 3 to 63 of lower-case letters, digits, dot and dash.
pub fn parse_s3_url(u: &str) -> Option<(String, String)> {
    let rest = u.strip_prefix("s3://")?;
    let (b, k) = rest.split_once('/')?;
    let bucket_ok = (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && !b.starts_with(['-', '.'])
        && !b.ends_with(['-', '.']);
    let key_ok = !k.is_empty()
        && k.len() <= 200
        && !k.starts_with('/')
        && !k.contains("..")
        && k.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'/' | b'.' | b'_' | b'-'));
    (bucket_ok && key_ok).then(|| (b.to_string(), k.to_string()))
}

fn etag_of(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    v.get("ETag")?
        .as_str()
        .map(|s| s.trim_matches('"').to_string())
}

impl ObjectShared {
    fn spec(&self, args: Vec<String>) -> CommandSpec {
        let mut full = vec!["s3api".to_string()];
        full.extend(args);
        if let Some(p) = &self.profile {
            full.push("--profile".into());
            full.push(p.clone());
        }
        full.push("--output".into());
        full.push("json".into());
        let mut c = CommandSpec::new("aws");
        c.args = full;
        c
    }

    fn tmp(&self, tag: &str) -> PathBuf {
        self.scratch
            .join(format!("fleet-shared-{}-{tag}", std::process::id()))
    }
}

impl Shared for ObjectShared {
    fn get(&self) -> io::Result<Option<(Vec<u8>, Version)>> {
        let out = self.tmp("get");
        let _ = std::fs::remove_file(&out);
        let spec = self.spec(vec![
            "get-object".into(),
            "--bucket".into(),
            self.bucket.clone(),
            "--key".into(),
            self.key.clone(),
            out.to_string_lossy().to_string(),
        ]);
        let r = self
            .runner
            .run(&spec)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if r.status != Some(0) {
            if r.stderr.contains("NoSuchKey") || r.stderr.contains("Not Found") {
                return Ok(None);
            }
            return Err(io::Error::other("the shared store could not be read"));
        }
        let etag = etag_of(&r.stdout)
            .ok_or_else(|| io::Error::other("the shared store gave no version"))?;
        let bytes = std::fs::read(&out)?;
        let _ = std::fs::remove_file(&out);
        Ok(Some((bytes, etag)))
    }

    fn put_if(&self, expect: Option<&str>, bytes: &[u8]) -> io::Result<Put> {
        let body = self.tmp("put");
        std::fs::write(&body, bytes)?;
        let mut args = vec![
            "put-object".to_string(),
            "--bucket".into(),
            self.bucket.clone(),
            "--key".into(),
            self.key.clone(),
            "--body".into(),
            body.to_string_lossy().to_string(),
        ];
        match expect {
            Some(v) => {
                args.push("--if-match".into());
                args.push(format!("\"{v}\""));
            }
            None => {
                args.push("--if-none-match".into());
                args.push("*".into());
            }
        }
        let r = self
            .runner
            .run(&self.spec(args))
            .map_err(|e| io::Error::other(e.to_string()));
        let _ = std::fs::remove_file(&body);
        let r = r?;
        if r.status == Some(0) {
            let etag = etag_of(&r.stdout)
                .ok_or_else(|| io::Error::other("the shared store gave no version"))?;
            return Ok(Put::Done(etag));
        }
        if r.stderr.contains("PreconditionFailed")
            || r.stderr.contains("ConditionalRequestConflict")
        {
            return Ok(Put::Conflict);
        }
        Err(io::Error::other("the shared store could not be written"))
    }
}

/// Where two computers keep their one fleet store: `fleet-shared.json` beside the schedule file. Absent means this
/// computer keeps its own (the default, and the only mode before failover is set up).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedConfig {
    /// `s3://bucket/key`.
    pub s3: String,
    /// An AWS CLI profile name, if the credentials for the bucket are not the default ones.
    #[serde(default)]
    pub profile: Option<String>,
}

pub fn config_path(store_path: &std::path::Path) -> PathBuf {
    store_path.with_file_name("fleet-shared.json")
}

pub fn load_config(store_path: &std::path::Path) -> Option<SharedConfig> {
    let c: SharedConfig =
        serde_json::from_slice(&std::fs::read(config_path(store_path)).ok()?).ok()?;
    parse_s3_url(&c.s3)?;
    Some(c)
}

pub fn save_config(store_path: &std::path::Path, c: &SharedConfig) -> Result<(), String> {
    parse_s3_url(&c.s3).ok_or("the address must look like s3://bucket/key")?;
    if let Some(p) = &c.profile {
        if p.is_empty()
            || p.len() > 64
            || !p
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err("a profile name is letters, digits, dash, underscore and dot".into());
        }
    }
    let bytes = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    std::fs::write(config_path(store_path), bytes).map_err(|e| e.to_string())
}

/// The fleet store at `path`, shared with other computers if `fleet-shared.json` says so.
pub fn store_at(path: PathBuf) -> super::store::Store {
    let base = super::store::Store::new(path.clone());
    match load_config(&path).and_then(|c| parse_s3_url(&c.s3).map(|(b, k)| (b, k, c.profile))) {
        Some((bucket, key, profile)) => base.with_shared(Arc::new(ObjectShared {
            bucket,
            key,
            profile,
            runner: Arc::new(ozbox_core::exec::SystemRunner),
            scratch: path
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        })),
        None => base,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn compare_and_swap_lets_exactly_one_writer_win_each_version() {
        let m = MemShared::new();
        let (a, b) = (m.handle("a"), m.handle("b"));
        assert_eq!(a.get().unwrap(), None);
        let v1 = match a.put_if(None, b"one").unwrap() {
            Put::Done(v) => v,
            Put::Conflict => panic!("first write"),
        };
        assert_eq!(
            b.put_if(None, b"x").unwrap(),
            Put::Conflict,
            "already exists"
        );
        assert!(matches!(b.put_if(Some(&v1), b"two").unwrap(), Put::Done(_)));
        assert_eq!(
            a.put_if(Some(&v1), b"three").unwrap(),
            Put::Conflict,
            "a was a version behind"
        );
        assert_eq!(a.get().unwrap().unwrap().0, b"two");
        m.cut("a", true);
        assert!(a.get().is_err());
        assert!(b.get().is_ok());
    }

    #[test]
    fn the_shared_config_is_validated_and_turns_a_store_into_a_shared_one() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("fleet-schedules.json");
        assert!(!store_at(p.clone()).is_shared());
        assert!(save_config(
            &p,
            &SharedConfig {
                s3: "http://x/y".into(),
                profile: None
            }
        )
        .is_err());
        assert!(save_config(
            &p,
            &SharedConfig {
                s3: "s3://my-bucket/k.json".into(),
                profile: Some("a b".into())
            }
        )
        .is_err());
        save_config(
            &p,
            &SharedConfig {
                s3: "s3://my-bucket/k.json".into(),
                profile: Some("ops".into()),
            },
        )
        .unwrap();
        assert!(store_at(p.clone()).is_shared());
        std::fs::write(config_path(&p), b"{\"s3\":\"nonsense\"}").unwrap();
        assert!(!store_at(p).is_shared(), "a bad file never half-enables it");
    }

    #[test]
    fn the_object_address_is_checked() {
        assert_eq!(
            parse_s3_url("s3://my-bucket/fleet/schedules.json"),
            Some(("my-bucket".into(), "fleet/schedules.json".into()))
        );
        for bad in [
            "http://x/y",
            "s3://B/x",
            "s3://ab/x",
            "s3://my-bucket/",
            "s3://my-bucket/../x",
            "s3://my-bucket/a b",
            "my-bucket/x",
        ] {
            assert!(parse_s3_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_cli_calls_carry_the_condition_and_never_a_shell_string() {
        use ozbox_core::exec::RecordingRunner;
        let rec = Arc::new(RecordingRunner::default());
        let s = ObjectShared {
            bucket: "my-bucket".into(),
            key: "fleet/s.json".into(),
            profile: Some("ops".into()),
            runner: rec.clone(),
            scratch: std::env::temp_dir(),
        };
        let _ = s.put_if(Some("abc"), b"{}");
        let _ = s.put_if(None, b"{}");
        let calls = rec.calls();
        assert_eq!(calls[0].program, "aws");
        assert!(calls[0]
            .args
            .windows(2)
            .any(|w| w == ["--if-match", "\"abc\""]));
        assert!(calls[1]
            .args
            .windows(2)
            .any(|w| w == ["--if-none-match", "*"]));
        assert!(calls[0].args.windows(2).any(|w| w == ["--profile", "ops"]));
    }
}
