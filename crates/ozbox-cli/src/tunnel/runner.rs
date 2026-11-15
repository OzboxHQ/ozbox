//! Keeping a tunnel up while `ozbox serve` runs: start it, notice when it has died and start it again with a growing
//! pause, check the public address now and then, and write what it knows to a small file so `ozbox tunnel status`
//! (another process) and the dashboard can show it. The file holds no secret.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{probe, Kind, State, Tunnel};
use crate::netguard::HttpClient;

const POLL_MS: u64 = 10_000;
const PROBE_MS: u64 = 60_000;
const FIRST_BACKOFF_MS: u64 = 2_000;
const MAX_BACKOFF_MS: u64 = 120_000;
/// A state file older than this was written by a server that is no longer running.
pub const STALE_MS: u64 = 3 * POLL_MS + 30_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRec {
    pub ok: bool,
    pub code: String,
    pub http_status: Option<u16>,
    pub checked_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub provider: String,
    pub public_url: String,
    /// The loopback port the dashboard listens on, which a provider that forwards to it needs to recognise its own work.
    #[serde(default)]
    pub port: u16,
    pub state: State,
    pub code: Option<String>,
    pub restarts: u32,
    pub health: Option<HealthRec>,
    pub updated_ms: u64,
}

pub struct Runner {
    tunnel: Box<dyn Tunnel>,
    kind: Kind,
    http: Arc<dyn HttpClient>,
    snap: Arc<Mutex<Snapshot>>,
    state_path: Option<PathBuf>,
    next_poll_ms: u64,
    next_probe_ms: u64,
    next_restart_ms: u64,
    backoff_ms: u64,
    probing: Arc<AtomicBool>,
    /// False after an explicit `stop`: a tunnel someone turned off is not started again by the next tick.
    enabled: bool,
}

fn lock(m: &Mutex<Snapshot>) -> std::sync::MutexGuard<'_, Snapshot> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Runner {
    pub fn new(
        tunnel: Box<dyn Tunnel>,
        public_url: &str,
        http: Arc<dyn HttpClient>,
        state_path: Option<PathBuf>,
        port: u16,
        now_ms: u64,
    ) -> Self {
        let kind = tunnel.kind();
        let snap = Snapshot {
            provider: kind.id().into(),
            public_url: public_url.into(),
            port,
            state: State::Stopped,
            code: None,
            restarts: 0,
            health: None,
            updated_ms: now_ms,
        };
        Self {
            tunnel,
            kind,
            http,
            snap: Arc::new(Mutex::new(snap)),
            state_path,
            next_poll_ms: 0,
            next_probe_ms: 0,
            next_restart_ms: 0,
            backoff_ms: FIRST_BACKOFF_MS,
            probing: Arc::new(AtomicBool::new(false)),
            enabled: true,
        }
    }

    /// Has this tunnel been asked to be up (it has not been stopped on purpose)?
    #[cfg(test)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// A handle the dashboard's route reads.
    pub fn snapshot(&self) -> Arc<Mutex<Snapshot>> {
        Arc::clone(&self.snap)
    }

    fn try_start(&mut self, now: u64) {
        match self.tunnel.start() {
            Ok(()) => self.backoff_ms = FIRST_BACKOFF_MS,
            Err(e) => {
                let mut s = lock(&self.snap);
                s.state = State::Failed;
                s.code = Some(e.code().into());
                self.next_restart_ms = now + self.backoff_ms;
                self.backoff_ms = (self.backoff_ms * 2).min(MAX_BACKOFF_MS);
            }
        }
    }

    /// Start once. A failure (no token yet, program missing) is recorded, not fatal: the dashboard still serves, and
    /// the next ticks try again.
    pub fn start(&mut self, now: u64) {
        self.enabled = true;
        self.try_start(now);
        self.poll(now);
    }

    fn poll(&mut self, now: u64) {
        let st = self.tunnel.status();
        {
            let mut s = lock(&self.snap);
            // Keep the more specific reason from a failed start while nothing is running.
            if !(st.state == State::Stopped && s.state == State::Failed) {
                s.state = st.state;
                s.code = st.code.map(String::from);
            }
            s.updated_ms = now;
        }
        self.write(now);
    }

    pub fn tick(&mut self, now: u64) {
        if !self.enabled || now < self.next_poll_ms {
            return;
        }
        self.next_poll_ms = now + POLL_MS;
        let running = self.tunnel.status().state == State::Running;
        if !running && now >= self.next_restart_ms {
            let had_run = lock(&self.snap).state == State::Running;
            if had_run {
                lock(&self.snap).restarts += 1;
            }
            // Start from a clean state, so a half-dead child is not left behind.
            let _ = self.tunnel.stop();
            self.try_start(now);
        }
        self.poll(now);
        let running = lock(&self.snap).state == State::Running;
        if running && now >= self.next_probe_ms && !self.probing.swap(true, Ordering::SeqCst) {
            self.next_probe_ms = now + PROBE_MS;
            if self.kind.probes_public_url() {
                let (http, url, snap, flag) = (
                    Arc::clone(&self.http),
                    lock(&self.snap).public_url.clone(),
                    Arc::clone(&self.snap),
                    Arc::clone(&self.probing),
                );
                std::thread::spawn(move || {
                    let h = probe(http.as_ref(), &url);
                    lock(&snap).health = Some(HealthRec {
                        ok: h.ok,
                        code: h.code.into(),
                        http_status: h.http_status,
                        checked_ms: now,
                    });
                    flag.store(false, Ordering::SeqCst);
                });
            } else {
                lock(&self.snap).health = Some(HealthRec {
                    ok: true,
                    code: "ok".into(),
                    http_status: None,
                    checked_ms: now,
                });
                self.probing.store(false, Ordering::SeqCst);
            }
        }
    }

    pub fn stop(&mut self, now: u64) {
        self.enabled = false;
        let _ = self.tunnel.stop();
        {
            let mut s = lock(&self.snap);
            s.state = State::Stopped;
            s.code = None;
            s.updated_ms = now;
        }
        self.write(now);
    }

    fn write(&self, _now: u64) {
        if let Some(p) = &self.state_path {
            let text = serde_json::to_string(&*lock(&self.snap)).unwrap_or_default();
            let tmp = p.with_extension("json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }
}

/// What a running `ozbox serve` last wrote, and whether it is recent enough to believe.
pub fn read_state(path: &Path, now_ms: u64) -> Option<(Snapshot, bool)> {
    let text = std::fs::read_to_string(path).ok()?;
    let s: Snapshot = serde_json::from_str(&text).ok()?;
    let fresh = now_ms.saturating_sub(s.updated_ms) < STALE_MS;
    Some((s, fresh))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::cloudflare::Cloudflare;
    use super::super::testing::*;
    use super::super::TunnelFile;
    use super::*;
    use crate::netguard::FakeHttp;
    use std::sync::atomic::Ordering::SeqCst;

    fn rig() -> (Runner, Arc<FakeSpawner>, Arc<FakeHttp>, tempfile::TempDir) {
        let sp = Arc::new(FakeSpawner::default());
        let secrets = Arc::new(crate::secrets::MemorySecrets::default());
        crate::secrets::SecretStore::set(secrets.as_ref(), "tunnel-token-cloudflare", "SENTINEL")
            .unwrap();
        let e = env(
            Arc::clone(&sp),
            Arc::new(ozbox_core::RecordingRunner::new()),
            secrets,
        );
        let f = TunnelFile {
            provider: "cloudflare".into(),
            public_url: "https://ozbox.example.com".into(),
            caddy: None,
        };
        let http = Arc::new(FakeHttp::default());
        let dir = tempfile::tempdir().unwrap();
        let r = Runner::new(
            Box::new(Cloudflare::new(&f, &e)),
            &f.public_url,
            http.clone(),
            Some(dir.path().join("tunnel-state.json")),
            7878,
            0,
        );
        (r, sp, http, dir)
    }

    #[test]
    fn a_dead_tunnel_is_restarted_with_a_growing_pause_and_stop_leaves_nothing() {
        let (mut r, sp, _http, dir) = rig();
        r.start(1_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), 1);
        assert_eq!(lock(&r.snapshot()).state, State::Running);
        sp.alive.store(false, SeqCst);
        r.tick(20_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), 2, "restarted");
        assert_eq!(lock(&r.snapshot()).restarts, 1);
        // an unstartable tunnel (program missing) backs off instead of spinning
        sp.missing.store(true, SeqCst);
        sp.alive.store(false, SeqCst);
        r.tick(40_000);
        assert_eq!(lock(&r.snapshot()).code.as_deref(), Some("tool_missing"));
        let n = sp.spawned.lock().unwrap().len();
        r.tick(50_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), n);
        sp.missing.store(false, SeqCst);
        r.tick(200_000);
        assert_eq!(lock(&r.snapshot()).state, State::Running);
        r.stop(210_000);
        assert!(!sp.alive.load(SeqCst));
        let (s, fresh) = read_state(&dir.path().join("tunnel-state.json"), 211_000).unwrap();
        assert_eq!(s.state, State::Stopped);
        assert!(fresh);
        assert!(
            !read_state(
                &dir.path().join("tunnel-state.json"),
                211_000 + STALE_MS + 1
            )
            .unwrap()
            .1
        );
    }

    #[test]
    fn a_tunnel_stopped_on_purpose_stays_stopped_until_started_again() {
        let (mut r, sp, _http, _dir) = rig();
        r.start(1_000);
        assert!(r.is_enabled());
        r.stop(2_000);
        assert!(!r.is_enabled());
        // the tick that would restart a dead tunnel leaves a stopped one alone
        r.tick(100_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), 1);
        assert_eq!(lock(&r.snapshot()).state, State::Stopped);
        r.start(200_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), 2);
        assert_eq!(lock(&r.snapshot()).state, State::Running);
    }

    #[test]
    fn the_state_file_holds_no_token_and_a_probe_fills_in_health() {
        let (mut r, _sp, http, dir) = rig();
        http.reply(200, r#"{"mode":"session"}"#);
        r.start(0);
        r.tick(1);
        for _ in 0..50 {
            if lock(&r.snapshot()).health.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let h = lock(&r.snapshot()).health.clone().unwrap();
        assert!(h.ok && h.code == "ok");
        let text = std::fs::read_to_string(dir.path().join("tunnel-state.json")).unwrap();
        assert!(!text.contains("SENTINEL"));
        assert!(text.contains("cloudflare") && text.contains("ozbox.example.com"));
    }
}
