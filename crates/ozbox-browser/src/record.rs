//! Recording and replay. Each session keeps, on the box, a list of steps and a screenshot per
//! step, under `<root>/sessions/<session>/`. A step holds the action word, the page (host and path, never the query), the
//! *names* of the fields touched, the risk, who acted and how it ended. Never a typed value and never page text.
//!
//! Layout: `meta.json`, `steps.jsonl`, `shots/0001.jpg`, `downloads/`, `downloads/.quarantine/`, `results/`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SESSIONS: &str = "sessions";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub n: u32,
    pub ts_ms: u64,
    /// `agent` or `person`.
    pub actor: String,
    pub action: String,
    /// `host/path`, without a query or a fragment.
    pub page: String,
    /// Names of fields or elements touched.
    #[serde(default)]
    pub names: Vec<String>,
    pub risk: String,
    /// `ok`, `refused`, `handoff`, `error`, `limit`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shot: Option<String>,
    /// The approval request a person decided for this step, when one did. A risky step without one was not done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub session: String,
    pub started_ms: u64,
    pub last_ms: u64,
    #[serde(default)]
    pub ended_ms: Option<u64>,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub run: Option<String>,
    /// `running`, `taken_over`, `paused`, `closed`.
    pub state: String,
    #[serde(default)]
    pub actions: u32,
    #[serde(default)]
    pub paused_reason: Option<String>,
    /// Whether this session ran as the browser's own user (profiles and held-back files out of the box user's reach). A
    /// session of an older recording, or one that ran as the box user, says `false`.
    #[serde(default)]
    pub isolated: bool,
}

pub fn page_of(url: &str) -> String {
    // a page that is not a web address (data:, blob:, about:) is named by its kind only: its address can be the page itself
    let Some(rest) = url
        .split_once("://")
        .filter(|(s, _)| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
        .map(|(_, r)| r)
    else {
        return url
            .split(':')
            .next()
            .filter(|s| !s.is_empty() && s.len() <= 12)
            .map(|s| format!("{}:", s.to_ascii_lowercase()))
            .unwrap_or_default();
    };
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    rest.chars().take(200).collect()
}

pub fn session_dir(root: &Path, session: &str) -> PathBuf {
    root.join(SESSIONS).join(session)
}

pub fn valid_session_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub struct Recorder {
    dir: PathBuf,
    meta: Meta,
    n: u32,
}

impl Recorder {
    pub fn create(root: &Path, meta: Meta) -> Result<Self, String> {
        Self::create_in(root, meta, true)
    }

    /// `held_back_here`: whether the held-back folder for downloads is made inside the recording (a worker that has no
    /// private root of its own), or left to the worker to make elsewhere.
    pub fn create_in(root: &Path, mut meta: Meta, held_back_here: bool) -> Result<Self, String> {
        if !valid_session_id(&meta.session) {
            return Err("a session id is letters, digits, dashes and underscores".into());
        }
        let dir = session_dir(root, &meta.session);
        let subs: &[&str] = if held_back_here {
            &["shots", "downloads/.quarantine", "results"]
        } else {
            &["shots", "downloads", "results"]
        };
        for sub in subs {
            fs::create_dir_all(dir.join(sub))
                .map_err(|e| format!("the recording folder could not be made: {e}"))?;
        }
        let n = count_steps(&dir);
        meta.last_ms = meta.last_ms.max(meta.started_ms);
        let mut r = Self { dir, meta, n };
        r.save_meta()?;
        Ok(r)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    fn save_meta(&mut self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.meta).map_err(|e| e.to_string())?;
        let tmp = self.dir.join("meta.json.tmp");
        fs::write(&tmp, text).map_err(|e| e.to_string())?;
        fs::rename(&tmp, self.dir.join("meta.json")).map_err(|e| e.to_string())
    }

    pub fn set_state(
        &mut self,
        state: &str,
        now_ms: u64,
        reason: Option<String>,
    ) -> Result<(), String> {
        self.meta.state = state.to_string();
        self.meta.last_ms = now_ms;
        self.meta.paused_reason = reason;
        if state == "closed" {
            self.meta.ended_ms = Some(now_ms);
        }
        self.save_meta()
    }

    /// Add a step, with its screenshot (already masked) when there is one. Returns the step number.
    pub fn step(&mut self, mut s: Step, shot: Option<&[u8]>) -> Result<u32, String> {
        self.n += 1;
        s.n = self.n;
        if let Some(bytes) = shot {
            let name = format!("{:04}.jpg", s.n);
            fs::write(self.dir.join("shots").join(&name), bytes).map_err(|e| e.to_string())?;
            s.shot = Some(name);
        }
        let mut line = serde_json::to_string(&s).map_err(|e| e.to_string())?;
        line.push('\n');
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("steps.jsonl"))
            .map_err(|e| e.to_string())?;
        f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        self.meta.last_ms = s.ts_ms;
        self.meta.actions += u32::from(s.actor == "agent" && s.outcome == "ok");
        self.save_meta()?;
        Ok(self.n)
    }
}

fn count_steps(dir: &Path) -> u32 {
    fs::read_to_string(dir.join("steps.jsonl")).map_or(0, |t| {
        t.lines().filter(|l| !l.trim().is_empty()).count() as u32
    })
}

pub fn load_meta(root: &Path, session: &str) -> Result<Meta, String> {
    if !valid_session_id(session) {
        return Err("that is not a session".into());
    }
    let t = fs::read_to_string(session_dir(root, session).join("meta.json"))
        .map_err(|_| "no such session".to_string())?;
    serde_json::from_str(&t).map_err(|e| e.to_string())
}

pub fn load_steps(root: &Path, session: &str) -> Result<Vec<Step>, String> {
    if !valid_session_id(session) {
        return Err("that is not a session".into());
    }
    let t = fs::read_to_string(session_dir(root, session).join("steps.jsonl")).unwrap_or_default();
    Ok(t.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

pub fn list_sessions(root: &Path) -> Vec<Meta> {
    let mut v: Vec<Meta> = fs::read_dir(root.join(SESSIONS))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| load_meta(root, e.file_name().to_str()?).ok())
        .collect();
    v.sort_by_key(|m| std::cmp::Reverse(m.started_ms));
    v
}

/// Delete recordings that have been idle longer than the retention. A running or paused session is never deleted: a person
/// may still resume it. Returns the sessions removed.
pub fn prune(root: &Path, now_ms: u64, retention_days: u32) -> Vec<String> {
    let keep_ms = u64::from(retention_days) * 86_400_000;
    let mut removed = Vec::new();
    for m in list_sessions(root) {
        let live = matches!(m.state.as_str(), "running" | "taken_over" | "paused");
        if !live
            && now_ms.saturating_sub(m.last_ms) > keep_ms
            && fs::remove_dir_all(session_dir(root, &m.session)).is_ok()
        {
            removed.push(m.session);
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, at: u64) -> Meta {
        Meta {
            session: id.into(),
            started_ms: at,
            last_ms: at,
            ended_ms: None,
            device: "desktop".into(),
            run: None,
            state: "running".into(),
            actions: 0,
            paused_reason: None,
            isolated: false,
        }
    }

    fn step(action: &str, at: u64) -> Step {
        Step {
            n: 0,
            ts_ms: at,
            actor: "agent".into(),
            action: action.into(),
            page: "localhost/a".into(),
            names: vec!["email".into()],
            risk: "none".into(),
            outcome: "ok".into(),
            shot: None,
            approval: None,
        }
    }

    #[test]
    fn a_page_that_is_not_a_web_address_is_named_by_its_kind_only() {
        assert_eq!(page_of("data:text/html,<p>SENTINEL</p>"), "data:");
        assert_eq!(page_of("blob:https://a.example/1-2"), "blob:");
        assert_eq!(page_of("about:blank"), "about:");
    }

    #[test]
    fn pages_are_recorded_without_query_fragment_or_credentials() {
        assert_eq!(
            page_of("https://u:pw@a.example/x/y?token=SENTINEL#frag"),
            "a.example/x/y"
        );
        assert_eq!(page_of("http://localhost:3000/"), "localhost:3000/");
    }

    #[test]
    fn steps_and_screenshots_are_kept_in_order_and_read_back() {
        let d = tempfile::tempdir().unwrap();
        let mut r = Recorder::create(d.path(), meta("s1", 1000)).unwrap();
        assert_eq!(r.step(step("navigate", 1100), Some(b"JPEG1")).unwrap(), 1);
        assert_eq!(r.step(step("click", 1200), None).unwrap(), 2);
        let steps = load_steps(d.path(), "s1").unwrap();
        assert_eq!(steps.iter().map(|s| s.n).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(steps[0].shot.as_deref(), Some("0001.jpg"));
        assert!(steps[1].shot.is_none());
        assert_eq!(
            fs::read(d.path().join("sessions/s1/shots/0001.jpg")).unwrap(),
            b"JPEG1"
        );
        assert_eq!(load_meta(d.path(), "s1").unwrap().actions, 2);
        // a recorder opened again carries on the numbering
        let mut again = Recorder::create(d.path(), meta("s1", 2000)).unwrap();
        assert_eq!(again.step(step("back", 2100), None).unwrap(), 3);
    }

    #[test]
    fn a_session_id_cannot_escape_the_folder() {
        let d = tempfile::tempdir().unwrap();
        assert!(Recorder::create(d.path(), meta("../x", 1)).is_err());
        assert!(load_steps(d.path(), "a/b").is_err());
        assert!(load_meta(d.path(), "").is_err());
    }

    #[test]
    fn only_finished_recordings_older_than_the_retention_are_deleted() {
        let d = tempfile::tempdir().unwrap();
        let day = 86_400_000u64;
        let now = 100 * day;
        let mut old = Recorder::create(d.path(), meta("old", 10 * day)).unwrap();
        old.set_state("closed", 10 * day, None).unwrap();
        let mut recent = Recorder::create(d.path(), meta("recent", 90 * day)).unwrap();
        recent.set_state("closed", 90 * day, None).unwrap();
        let mut paused = Recorder::create(d.path(), meta("paused", 10 * day)).unwrap();
        paused
            .set_state("paused", 10 * day, Some("waited".into()))
            .unwrap();
        assert_eq!(prune(d.path(), now, 30), vec!["old".to_string()]);
        assert!(!session_dir(d.path(), "old").exists());
        assert!(session_dir(d.path(), "recent").exists());
        // a paused task can still be resumed, so it is kept whatever its age
        assert!(session_dir(d.path(), "paused").exists());
        // a longer retention keeps what a shorter one would delete
        assert!(prune(d.path(), now, 365).is_empty());
        assert_eq!(list_sessions(d.path()).len(), 2);
    }
}
