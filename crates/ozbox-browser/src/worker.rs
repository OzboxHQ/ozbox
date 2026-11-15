//! The session worker: one process per browsing session, started on the box as a run with its standard input kept open.
//! It owns the Chromium, the recording and who holds the browser (the agent, or a person who has taken over), and it speaks
//! the line protocol in [`crate::protocol`] over the sealed channel in [`crate::channel`].
//!
//! Three rules live here and nowhere else: a line that the tool host did not seal is refused (and recorded); a risky action
//! runs only with a person's [`Grant`] for exactly that action and that state of the page, used once; and the worker only
//! ever pauses *between* actions, so nothing is left half-done. While a person holds the session the agent's actions are
//! refused.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::channel::Channel;
use crate::detect::{self, Gate, Risk};
use crate::driver::{DErr, Driver};
use crate::policy::{self, Budget};
use crate::protocol::{Action, Actor, Grant, Op, Reply, Request, Start};
use crate::record::{self, Meta, Recorder, Step};

/// How long a closing session waits for the browser's helper processes to leave its profile before it gives up.
const PROFILE_REMOVE_WINDOW: Duration = Duration::from_secs(5);

/// True while a process other than this one still has `dir` on its command line (a browser helper started with that
/// profile). Linux only: elsewhere the helpers are gone by the time the main process is, and removal is retried anyway.
#[cfg(target_os = "linux")]
fn profile_in_use(dir: &Path) -> bool {
    let needle = dir.to_string_lossy().into_owned();
    let me = std::process::id().to_string();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return false;
    };
    procs.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name == me.as_str() || !name.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        std::fs::read(e.path().join("cmdline")).is_ok_and(|raw| {
            String::from_utf8_lossy(&raw)
                .replace('\0', " ")
                .contains(&needle)
        })
    })
}

#[cfg(not(target_os = "linux"))]
fn profile_in_use(_dir: &Path) -> bool {
    false
}

/// Removes a closed session's temporary profile. Chromium's helpers (zygote, GPU, crashpad) can still be writing into it for
/// a moment after the main process is gone, which makes a single `remove_dir_all` fail with "directory not empty", so this
/// waits for them to leave and retries with a short, growing pause, for at most [`PROFILE_REMOVE_WINDOW`]. A directory that
/// is already gone is success; a directory that cannot be removed in the window is an error the caller reports.
fn remove_profile_dir(dir: &Path) -> std::io::Result<()> {
    let end = Instant::now() + PROFILE_REMOVE_WINDOW;
    let mut pause = Duration::from_millis(20);
    loop {
        // helpers still holding the profile are given their moment before each removal attempt
        let wait_until = Instant::now() + Duration::from_millis(500);
        while profile_in_use(dir) && Instant::now() < wait_until {
            std::thread::sleep(Duration::from_millis(20));
        }
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if Instant::now() >= end => return Err(e),
            Err(_) => {}
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(250));
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Agent,
    Person,
}

/// The saved place of a paused task.
const RESUME_FILE: &str = "resume.json";
/// The most unsealed lines recorded as steps; beyond that they are refused without a step, so they cannot fill the disk.
const MAX_FORGED_STEPS: u32 = 20;

pub struct Worker {
    start: Start,
    chan: Channel,
    driver: Driver,
    rec: Recorder,
    control: Control,
    held_since: Option<Instant>,
    held_reason: String,
    actions: u32,
    started_ms: u64,
    warned: bool,
    person_keys: u32,
    last_person_step: Option<Instant>,
    tmp_profile: Option<PathBuf>,
    /// Approval requests already used: one approval covers one action.
    spent: HashSet<String>,
    forged: u32,
}

/// Where the things only the worker may see live: its profiles (cookies), a clean session's temporary profile, a paused
/// session's saved place, and, in a session of its own user, the downloads that were held back. With no private root they
/// are under the recording root, which is the layout of a worker on a person's own computer.
fn private_root(start: &Start) -> PathBuf {
    PathBuf::from(start.private_root.as_deref().unwrap_or(&start.root))
}

fn profile_dir(start: &Start) -> (PathBuf, Option<PathBuf>) {
    let private = private_root(start);
    match &start.policy.profile {
        Some(p) => (private.join("profiles").join(p), None),
        None => {
            let d = private.join("tmp").join(&start.session);
            (d.clone(), Some(d))
        }
    }
}

/// A paused session's saved place (the addresses of its tabs, which can hold a token). Beside the recording when the worker
/// has no private root; otherwise in the private root, because the recording is readable by the box's other users.
fn resume_path(start: &Start) -> PathBuf {
    match &start.private_root {
        Some(p) => PathBuf::from(p)
            .join("resume")
            .join(format!("{}.json", start.session)),
        None => record::session_dir(&PathBuf::from(&start.root), &start.session).join(RESUME_FILE),
    }
}

/// The folder a session's held-back downloads wait in.
fn quarantine_dir(start: &Start) -> PathBuf {
    match &start.private_root {
        Some(p) => PathBuf::from(p).join("held").join(&start.session),
        None => record::session_dir(&PathBuf::from(&start.root), &start.session)
            .join("downloads")
            .join(".quarantine"),
    }
}

/// The host part of a `host/path` destination.
fn dest_host(dest: &str) -> String {
    detect::normal_host(dest.split(['/', ',']).next().unwrap_or(""))
}

impl Worker {
    pub fn open(start: Start) -> Result<Self, String> {
        start.policy.validate()?;
        if !record::valid_session_id(&start.session) {
            return Err("bad session id".into());
        }
        let chan = Channel::worker(&start.key, &start.session)?;
        let root = PathBuf::from(&start.root);
        // retention: old recordings go when a session opens or closes, so nothing on the box needs a timer
        let _ = record::prune(&root, now_ms(), start.policy.retention_days);
        let t = now_ms();
        let resume: Option<Value> = std::fs::read_to_string(resume_path(&start))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let meta = Meta {
            session: start.session.clone(),
            started_ms: resume
                .as_ref()
                .and_then(|r| r["started_ms"].as_u64())
                .unwrap_or(t),
            last_ms: t,
            ended_ms: None,
            device: format!("{:?}", start.device).to_ascii_lowercase(),
            run: start.run.clone(),
            state: "running".into(),
            actions: resume
                .as_ref()
                .and_then(|r| r["actions"].as_u64())
                .unwrap_or(0) as u32,
            paused_reason: None,
            isolated: start.private_root.is_some(),
        };
        let actions = meta.actions;
        let isolated = start.private_root.is_some();
        let mut rec = Recorder::create_in(&root, meta, !isolated)?;
        if isolated {
            // The recording and the released documents are for the box's other users to read (the dashboard shows them and
            // the agent opens a document it was given), so the folders are readable by the group and by no one else. What
            // must stay private is in the private root.
            crate::driver::shared_dir(rec.dir()).map_err(|e| e.to_string())?;
            crate::driver::shared_dir(&rec.dir().join("downloads")).map_err(|e| e.to_string())?;
            crate::driver::private_dir(&private_root(&start).join("resume"))
                .map_err(|e| e.to_string())?;
        } else {
            let _ = crate::driver::private_dir(rec.dir());
        }
        let (profile, tmp) = profile_dir(&start);
        let dl = rec.dir().join("downloads");
        let held = quarantine_dir(&start);
        let driver = Driver::launch(&start, &profile, &dl, &held).map_err(|e| e.msg)?;
        rec.set_state("running", t, None)?;
        let mut w = Self {
            started_ms: rec.meta().started_ms.min(t),
            start,
            chan,
            driver,
            rec,
            control: Control::Agent,
            held_since: None,
            held_reason: String::new(),
            actions,
            warned: false,
            person_keys: 0,
            last_person_step: None,
            tmp_profile: tmp,
            spent: HashSet::new(),
            forged: 0,
        };
        if let Some(r) = resume {
            // open the pages the task was on again, by address only: nothing is ever replayed, and each address is judged
            // again (robots.txt, the pace, and the allow-list, by the browser's own check on every page load)
            for u in r["tabs"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|u| u.starts_with("http://") || u.starts_with("https://"))
            {
                let a = Action::TabNew {
                    url: Some(u.to_string()),
                };
                if w.driver
                    .preview(&a)
                    .is_ok_and(|x| detect::gate(x.risk, w.start.policy.payments) == Gate::Allow)
                {
                    let _ = w.driver.perform(&a, None);
                }
            }
            let _ = w.driver.take_blocked();
            let _ = std::fs::remove_file(resume_path(&w.start));
        }
        Ok(w)
    }

    fn root(&self) -> PathBuf {
        PathBuf::from(&self.start.root)
    }

    #[allow(clippy::too_many_arguments)]
    fn step_with(
        &mut self,
        actor: Actor,
        action: &str,
        names: Vec<String>,
        risk: Risk,
        outcome: &str,
        shot: bool,
        approval: Option<String>,
    ) {
        let url = self.driver.url();
        let bytes = if shot {
            self.driver.screenshot(false, true).ok()
        } else {
            None
        };
        let _ = self.rec.step(
            Step {
                n: 0,
                ts_ms: now_ms(),
                actor: if actor == Actor::Agent {
                    "agent"
                } else {
                    "person"
                }
                .into(),
                action: action.into(),
                page: record::page_of(&url),
                names,
                risk: risk.word().into(),
                outcome: outcome.into(),
                shot: None,
                approval,
            },
            bytes.as_deref(),
        );
    }

    fn step(
        &mut self,
        actor: Actor,
        action: &str,
        names: Vec<String>,
        risk: Risk,
        outcome: &str,
        shot: bool,
    ) {
        self.step_with(actor, action, names, risk, outcome, shot, None);
    }

    fn hold(&mut self, reason: &str) {
        self.control = Control::Person;
        self.held_since = Some(Instant::now());
        self.held_reason = reason.to_string();
        self.driver.set_person(true);
        let _ = self
            .rec
            .set_state("taken_over", now_ms(), Some(reason.to_string()));
    }

    fn assessment_json(a: &detect::Assessment, g: &Gate) -> Value {
        let (gate, msg) = match g {
            Gate::Allow => ("allow", String::new()),
            Gate::Ask => ("ask", String::new()),
            Gate::Refuse(m) => ("refuse", m.clone()),
            Gate::Handoff(m) => ("handoff", m.clone()),
        };
        json!({
            "risk": a.risk.word(), "host": a.host, "reason": a.reason, "gate": gate, "message": msg,
            "dest": a.dest, "fingerprint": a.fingerprint,
            "fields": a.fields.iter().map(|(n, v)| json!({ "name": detect::clean_name(n), "value": v })).collect::<Vec<_>>(),
        })
    }

    fn budget_check(&mut self) -> Option<Reply> {
        match policy::budget(&self.start.policy, self.actions, self.started_ms, now_ms()) {
            Budget::Exceeded(why) => Some(Reply::err(0, "limit", why)),
            Budget::Warn if !self.warned => {
                self.warned = true;
                None
            }
            _ => None,
        }
    }

    /// Check a person's approval for the action about to run. `Ok` carries the approval id.
    fn check_grant(
        &mut self,
        action: &Action,
        a: &detect::Assessment,
        grant: Option<&Grant>,
    ) -> Result<String, (&'static str, String)> {
        let Some(g) = grant else {
            return Err((
                "risk",
                format!("this needs a person's approval first ({})", a.reason),
            ));
        };
        if self.spent.contains(&g.approval) {
            return Err((
                "risk",
                "that approval was already used: one approval covers one action".into(),
            ));
        }
        if !self.chan.grant_ok(
            &g.approval,
            &g.fingerprint,
            &g.risk,
            &action.grant_bytes(),
            &g.mac,
        ) {
            return Err((
                "risk",
                "that is not a person's approval for this action, so it was not done".into(),
            ));
        }
        if g.fingerprint != a.fingerprint || g.risk != a.risk.word() {
            return Err((
                "changed",
                "the page changed after a person approved this (a different element, form or destination), so nothing was done: take a new snapshot and ask again".into(),
            ));
        }
        self.spent.insert(g.approval.clone());
        Ok(g.approval.clone())
    }

    pub fn handle(&mut self, req: Request) -> (Reply, bool) {
        let id = req.id;
        let fail = |e: DErr| Reply::err(id, e.code, e.msg);
        match req.op {
            Op::Preview { action } => {
                if self.control == Control::Person {
                    return (Reply::err(id, "person_holds", self.holds_message()), false);
                }
                if let Some(mut r) = self.budget_check() {
                    r.id = id;
                    return (r, false);
                }
                match self.driver.preview(&action) {
                    Ok(mut a) => {
                        // a challenge on the page outranks everything: only a person can go on
                        if a.risk < Risk::Captcha && !action.reads() {
                            if let Some(why) = self.driver.challenge() {
                                a = detect::Assessment::with(Risk::Captcha, &a.host, &why);
                            }
                        }
                        let g = detect::gate(a.risk, self.start.policy.payments);
                        let mut out = Self::assessment_json(&a, &g);
                        out["names"] = json!(self
                            .driver
                            .field_name(&action)
                            .into_iter()
                            .collect::<Vec<_>>());
                        out["warn"] = json!(
                            policy::budget(
                                &self.start.policy,
                                self.actions,
                                self.started_ms,
                                now_ms()
                            ) == Budget::Warn
                        );
                        if matches!(g, Gate::Handoff(_)) {
                            self.step(Actor::Agent, action.word(), vec![], a.risk, "handoff", true);
                            self.hold(&format!("challenge: {}", a.reason));
                            out["control"] = json!("person");
                        }
                        (Reply::ok(id, out), false)
                    }
                    Err(e) => (fail(e), false),
                }
            }
            Op::Act { action, grant } => {
                if self.control == Control::Person {
                    return (Reply::err(id, "person_holds", self.holds_message()), false);
                }
                if let Some(mut r) = self.budget_check() {
                    r.id = id;
                    let _ = self.rec.set_state("running", now_ms(), None);
                    return (r, false);
                }
                // the worker judges again: an approval is for what was shown, not for whatever the page became
                let assessment = match self.driver.preview(&action) {
                    Ok(a) => a,
                    Err(e) => {
                        if e.code == "refused" {
                            self.step(
                                Actor::Agent,
                                action.word(),
                                vec![],
                                Risk::None,
                                "refused",
                                false,
                            );
                        }
                        return (fail(e), false);
                    }
                };
                let g = detect::gate(assessment.risk, self.start.policy.payments);
                let mut approval = None;
                match g {
                    Gate::Refuse(m) => {
                        self.step(
                            Actor::Agent,
                            action.word(),
                            vec![],
                            assessment.risk,
                            "refused",
                            true,
                        );
                        return (Reply::err(id, "risk", m), false);
                    }
                    Gate::Handoff(m) => {
                        self.step(
                            Actor::Agent,
                            action.word(),
                            vec![],
                            assessment.risk,
                            "handoff",
                            true,
                        );
                        self.hold(&format!("challenge: {}", assessment.reason));
                        return (Reply::err(id, "person_holds", m), false);
                    }
                    Gate::Ask => match self.check_grant(&action, &assessment, grant.as_ref()) {
                        Ok(a) => approval = Some(a),
                        Err((code, msg)) => {
                            // a forged, reused or stale approval is a refusal in the recording, like any other
                            if grant.is_some() {
                                self.step(
                                    Actor::Agent,
                                    action.word(),
                                    vec![],
                                    assessment.risk,
                                    "refused",
                                    false,
                                );
                            }
                            return (Reply::err(id, code, msg), false);
                        }
                    },
                    Gate::Allow => {}
                }
                // where the page may send data while this runs: only where a person approved it to go
                let sends = matches!(
                    assessment.risk,
                    Risk::Submit | Risk::Send | Risk::Payment | Risk::NewDomain
                );
                let grant_hosts = approval.as_ref().map(|_| {
                    let mut h: Vec<String> = if sends {
                        assessment
                            .dest
                            .split(',')
                            .map(dest_host)
                            .filter(|x| !x.is_empty())
                            .collect()
                    } else {
                        Vec::new()
                    };
                    if sends && !assessment.host.is_empty() && assessment.risk != Risk::NewDomain {
                        h.push(detect::normal_host(&assessment.host));
                    }
                    h
                });
                if approval.is_some() && assessment.risk == Risk::NewDomain {
                    self.driver.approve_host(&assessment.host);
                }
                let name = self.driver.field_name(&action);
                let names: Vec<String> = name.into_iter().collect();
                let counts = !matches!(
                    action,
                    Action::Snapshot
                        | Action::Screenshot { .. }
                        | Action::TabList
                        | Action::Downloads
                        | Action::Wait { .. }
                );
                let result = self.driver.perform(&action, grant_hosts);
                let held = self.driver.take_blocked();
                // what an element tried to send without an approval: the next time it is aimed at, a person is asked. Only for
                // the agent's own clicks and key presses: a page's background requests are not the action's doing
                if approval.is_none()
                    && matches!(
                        action,
                        Action::Click { .. }
                            | Action::Type { submit: true, .. }
                            | Action::Press { .. }
                    )
                {
                    self.driver.learn(&assessment.fingerprint, &held);
                }
                let robots_read = if held.iter().any(|h| h.why == "robots_unread") {
                    self.driver.read_wanted_robots()
                } else {
                    Vec::new()
                };
                let opened = self.driver.take_opened();
                match result {
                    Ok(mut v) => {
                        if counts || matches!(action, Action::Snapshot | Action::Extract { .. }) {
                            self.actions += 1;
                        }
                        let shot = !matches!(action, Action::TabList | Action::Downloads);
                        self.step_with(
                            Actor::Agent,
                            action.word(),
                            names,
                            assessment.risk,
                            "ok",
                            shot,
                            approval,
                        );
                        if !held.is_empty() {
                            v["blocked_requests"] = json!(held.len());
                            v["held_back"] = json!(held
                                .iter()
                                .map(|h| json!({ "host": h.host, "why": h.why }))
                                .collect::<Vec<_>>());
                            v["note"] = json!("The page tried to load or send something that was held back (see held_back). Data goes only where a person approved it; a site that is not on the allow-list does not open. If it is needed, ask for that step again: it will be shown to a person.");
                        }
                        if !robots_read.is_empty() {
                            v["robots_read"] = json!(robots_read);
                        }
                        if opened > 0 {
                            v["opened_tabs"] = json!(opened);
                            v["tabs_note"] = json!("The page opened a new tab. You are still on this one: list the tabs and switch if you need it.");
                        }
                        // the action may have landed on a challenge
                        if let Some(why) = self.driver.challenge() {
                            self.step(
                                Actor::Agent,
                                "challenge_found",
                                vec![],
                                Risk::Captcha,
                                "handoff",
                                true,
                            );
                            self.hold(&format!("challenge: {why}"));
                            v["handoff"] = json!({ "reason": why, "message": "This page asks to prove you are human. A person has to take over the browser; Oz Box never solves these." });
                        }
                        v["actions_used"] = json!(self.actions);
                        (Reply::ok(id, v), false)
                    }
                    Err(e) => {
                        let outcome = if e.code == "robots" || e.code == "refused" {
                            "refused"
                        } else {
                            "error"
                        };
                        self.step_with(
                            Actor::Agent,
                            action.word(),
                            names,
                            assessment.risk,
                            outcome,
                            false,
                            approval,
                        );
                        (fail(e), false)
                    }
                }
            }
            Op::Input { event } => {
                if self.control != Control::Person {
                    return (
                        Reply::err(
                            id,
                            "not_taken_over",
                            "take over the session before sending input",
                        ),
                        false,
                    );
                }
                let kind = event["kind"].as_str().unwrap_or("").to_string();
                let t = event["t"].as_str().unwrap_or("").to_string();
                match self.driver.input(&event) {
                    Ok(()) => {
                        // a person's pointer clicks are steps; typing is counted, never recorded
                        if t == "mouse" && kind == "down" {
                            self.step(Actor::Person, "click", vec![], Risk::None, "ok", true);
                        } else if t == "dialog" {
                            self.step(Actor::Person, "dialog", vec![], Risk::None, "ok", false);
                        } else if t == "key" || t == "text" {
                            self.person_keys += 1;
                            let due = self
                                .last_person_step
                                .is_none_or(|l| l.elapsed() > Duration::from_secs(2));
                            if due {
                                self.last_person_step = Some(Instant::now());
                                self.step(Actor::Person, "type", vec![], Risk::None, "ok", false);
                            }
                        }
                        (Reply::ok(id, json!({ "ok": true })), false)
                    }
                    Err(e) => (fail(e), false),
                }
            }
            Op::Takeover { who } => {
                if self.control == Control::Person {
                    return (
                        Reply::ok(id, json!({ "control": "person", "already": true })),
                        false,
                    );
                }
                self.step(Actor::Person, "takeover", vec![], Risk::None, "ok", true);
                self.hold(&format!(
                    "taken over by {}",
                    who.chars().take(40).collect::<String>()
                ));
                (Reply::ok(id, json!({ "control": "person" })), false)
            }
            Op::Handback => {
                if self.control == Control::Agent {
                    return (
                        Reply::ok(id, json!({ "control": "agent", "already": true })),
                        false,
                    );
                }
                // handing back while the challenge is still showing would just hand the agent the same wall
                if let Some(why) = self.driver.challenge() {
                    return (
                        Reply::err(
                            id,
                            "challenge",
                            format!("the page still shows a check ({why}): finish it first"),
                        ),
                        false,
                    );
                }
                self.control = Control::Agent;
                self.held_since = None;
                self.driver.set_person(false);
                self.step(Actor::Person, "handback", vec![], Risk::None, "ok", true);
                let _ = self.rec.set_state("running", now_ms(), None);
                (
                    Reply::ok(
                        id,
                        json!({ "control": "agent", "person_keys": std::mem::take(&mut self.person_keys) }),
                    ),
                    false,
                )
            }
            Op::Frame => match self.driver.frame() {
                Ok((bytes, page)) => {
                    let mut v = json!({
                        "jpeg": crate::b64::encode(&bytes), "page": page,
                        "control": if self.control == Control::Person { "person" } else { "agent" },
                        "device": self.start.device.metrics().width,
                    });
                    if let Some(d) = self.driver.dialog() {
                        v["dialog"] = d;
                    }
                    (Reply::ok(id, v), false)
                }
                Err(e) => (fail(e), false),
            },
            Op::Status => (Reply::ok(id, self.status()), false),
            Op::Pause { reason } => {
                let tabs = self.driver.tab_addresses();
                let save = json!({ "tabs": tabs, "actions": self.actions, "started_ms": self.started_ms, "reason": reason });
                let path = resume_path(&self.start);
                if let Err(e) = std::fs::write(&path, save.to_string()) {
                    return (
                        Reply::err(id, "failed", format!("the place could not be saved: {e}")),
                        false,
                    );
                }
                self.step(Actor::Agent, "pause", vec![], Risk::None, "ok", true);
                let _ = self.rec.set_state(
                    "paused",
                    now_ms(),
                    Some(reason.chars().take(100).collect()),
                );
                self.driver.close();
                (
                    Reply::ok(id, json!({ "paused": true, "tabs": tabs.len() })),
                    true,
                )
            }
            Op::Close => {
                let _ = self.rec.set_state("closed", now_ms(), None);
                self.driver.close();
                let removed = match &self.tmp_profile {
                    Some(t) => remove_profile_dir(t),
                    None => Ok(()),
                };
                let _ = record::prune(&self.root(), now_ms(), self.start.policy.retention_days);
                match removed {
                    Ok(()) => (Reply::ok(id, json!({ "closed": true })), true),
                    // never swallowed: a temporary profile holds the session's cookies, so the caller must hear it stayed
                    Err(e) => (
                        Reply::err(
                            id,
                            "failed",
                            format!("the session closed but its temporary profile could not be removed: {}", e.kind()),
                        ),
                        true,
                    ),
                }
            }
        }
    }

    /// A line that is not the tool host's: refused, and (up to a limit) recorded, so a replay shows that something tried.
    fn refuse_line(&mut self, why: &str) -> Reply {
        if self.forged < MAX_FORGED_STEPS {
            self.forged += 1;
            self.step(
                Actor::Agent,
                "unsealed_input",
                vec![],
                Risk::None,
                "refused",
                false,
            );
        }
        Reply::err(
            0,
            "unauthenticated",
            format!("{why}: only the session's tool host drives this browser"),
        )
    }

    fn holds_message(&self) -> String {
        format!("A person holds this browser ({}). Wait for them to hand it back; do not try again until then.", self.held_reason)
    }

    fn status(&self) -> Value {
        json!({
            "session": self.start.session,
            "control": if self.control == Control::Person { "person" } else { "agent" },
            "held_reason": self.held_reason,
            "actions": self.actions,
            "max_actions": self.start.policy.max_actions,
            "minutes": (now_ms().saturating_sub(self.started_ms)) / 60_000,
            "max_minutes": self.start.policy.max_minutes,
            "device": format!("{:?}", self.start.device).to_ascii_lowercase(),
        })
    }

    /// The take-over has waited too long: the same pause as any other long wait.
    fn held_too_long(&self) -> bool {
        self.control == Control::Person
            && self.held_since.is_some_and(|s| {
                s.elapsed() > Duration::from_secs(u64::from(self.start.policy.wait_minutes) * 60)
            })
    }

    /// Seal a reply into the line that goes out.
    fn seal(&mut self, r: &Reply) -> String {
        let plain = serde_json::to_vec(r).unwrap_or_default();
        self.chan.seal(r.id, &plain)
    }

    /// Open one line from the tool host and answer it. `None` closes the session.
    pub fn handle_line(&mut self, line: &str) -> (String, bool) {
        let (reply, stop) = match self.chan.open(line) {
            Ok((_, plain)) => match serde_json::from_slice::<Request>(&plain) {
                Ok(req) => self.handle(req),
                Err(e) => (
                    Reply::err(0, "invalid", format!("that is not a request: {e}")),
                    false,
                ),
            },
            Err(e) => (self.refuse_line(e.sentence()), false),
        };
        (self.seal(&reply), stop)
    }
}

/// Run a worker on a stream of lines until it is closed or paused. The first line out says it is ready (sealed, so the tool
/// host knows it speaks to the worker it started).
pub fn run(
    start: Start,
    input: impl BufRead + Send + 'static,
    out: &mut impl Write,
) -> Result<(), String> {
    let mut early = Channel::worker(&start.key, &start.session)?;
    let session = start.session.clone();
    let mut w = match Worker::open(start) {
        Ok(w) => w,
        Err(e) => {
            let r = Reply::err(0, "failed", e.clone());
            emit(
                out,
                &early.seal(0, &serde_json::to_vec(&r).unwrap_or_default()),
            );
            return Err(e);
        }
    };
    let ready = Reply::ok(0, json!({ "ready": true, "session": session }));
    let line = w.seal(&ready);
    emit(out, &line);
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in input.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    loop {
        match rx.recv_timeout(Duration::from_millis(60)) {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let (reply, stop) = w.handle_line(&line);
                emit(out, &reply);
                if stop {
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                w.driver.service();
                if w.held_too_long() {
                    let (r, _) = w.handle(Request {
                        id: 0,
                        op: Op::Pause {
                            reason: "waited too long for a person".into(),
                        },
                    });
                    let line = w.seal(&r);
                    emit(out, &line);
                    return Ok(());
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                // the host went away: close cleanly so nothing is left running
                let (r, _) = w.handle(Request {
                    id: 0,
                    op: Op::Close,
                });
                if !r.ok {
                    let line = w.seal(&r);
                    emit(out, &line);
                }
                return Ok(());
            }
        }
    }
}

fn emit(out: &mut impl Write, line: &str) {
    let mut s = line.to_string();
    s.push('\n');
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}
