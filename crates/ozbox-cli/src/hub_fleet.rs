//! The hub, attached to `ozbox serve` (ADR 0042, ADR 0057): what makes this box the hub the workers dial.
//!
//! The pieces already exist apart: the daemon (`ozbox-hubd`) faces the network and keeps the spool and the roster enrolment made;
//! the secrets service signs and opens for the supervisor; the worker channel's logic ([`ozbox_core::hub::engine::HubService`]) and
//! the conversation fabric ([`ozbox_core::fabric::node::HubFabric`]) are pure. This module puts them together for the server:
//!
//! * the channel and the fabric both ride the daemon's spool ([`SpoolTransport`], endpoints `<hub>` and `<hub>.fabric`);
//! * the signer, sealer and verifier are the real ones ([`ozbox_hubd::crypto`]), and the secrets service is reached on the
//!   supervisor's socket only;
//! * the roster is **not copied by hand**: [`HubAttachment::tick`] reads what enrolment attested from the daemon and adds each
//!   worker to the channel, the fabric and the key directory, and drops those that were removed;
//! * a worker's key asks are served through the issuer path ([`ozbox_hubd::fleet`]) and its fabric frames are pumped.
//!
//! A box with no daemon socket is not a hub: [`from_environment`] answers `None` and nothing changes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ozbox_core::fabric::node::{HubFabric, Seams as FabricSeams};
use ozbox_core::fabric::walls::WallSource;
use ozbox_core::fabric::CoreScreen;
use ozbox_core::hub::approvals::ServicePin;
use ozbox_core::hub::engine::{HubService, HubState, RosterEntry};
use ozbox_hubd::crypto::{Directory, DirectoryVerifier, ServiceSealer, ServiceSigner};
use ozbox_hubd::daemon::{ask, SpoolTransport};
use ozbox_hubd::enrol::RosterRecord;
use ozbox_hubd::fleet::ServiceIssuer;
use ozbox_hubd::ops::KeyOps;

/// Where the daemon's supervisor-facing socket is, unless said otherwise.
pub const DEFAULT_HUBD_SOCKET: &str = "/run/ozbox-hub/supervisor/hubd.sock";

/// The hub as the server holds it.
pub struct HubAttachment {
    pub svc: Arc<HubService>,
    pub fabric: Arc<HubFabric>,
    socket: PathBuf,
    dir: Directory,
    known: Mutex<BTreeSet<String>>,
    issuer: ServiceIssuer,
    attest: Arc<dyn ozbox_core::hub::keys::Attestations>,
}

/// What attaching needs. `ops` is the secrets service on the supervisor's socket.
pub struct AttachConfig {
    pub hubd_socket: PathBuf,
    /// The hub's name on the channel.
    pub name: String,
    pub ops: Arc<dyn KeyOps>,
    pub walls: Option<Arc<dyn WallSource>>,
    /// Where the channel's state persists, or `None` to keep it in memory.
    pub state_dir: Option<PathBuf>,
}

/// The hub this box is configured to be, if it is one: the daemon's socket exists. Names the environment's overrides.
pub fn from_environment(ops: impl FnOnce() -> Option<Arc<dyn KeyOps>>) -> Option<AttachConfig> {
    let socket = std::env::var_os("OZBOX_HUBD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_HUBD_SOCKET));
    if !socket.exists() {
        return None;
    }
    Some(AttachConfig {
        hubd_socket: socket,
        name: std::env::var("OZBOX_HUB_NAME").unwrap_or_else(|_| "main".into()),
        ops: ops()?,
        walls: None,
        state_dir: std::env::var_os("OZBOX_HUB_STATE_DIR").map(PathBuf::from),
    })
}

fn roster_of(socket: &std::path::Path) -> Result<Vec<RosterRecord>, String> {
    let v = ask(socket, &serde_json::json!({"op": "roster"}))?;
    if v["ok"].as_bool() != Some(true) {
        return Err("the hub daemon did not give the roster".into());
    }
    serde_json::from_value(v["result"]["workers"].clone())
        .map_err(|_| "the roster is not valid".to_string())
}

impl HubAttachment {
    pub fn connect(cfg: AttachConfig) -> Result<Arc<HubAttachment>, String> {
        let me = cfg
            .ops
            .identity()
            .map_err(|e| format!("the secrets service did not give the hub's identity: {e}"))?;
        let my_fp = me.channel_fp();
        let dir = Directory::default();
        let net = Arc::new(SpoolTransport::new(&cfg.hubd_socket));
        let signer = Arc::new(ServiceSigner {
            ops: cfg.ops.clone(),
        });
        let verifier = Arc::new(DirectoryVerifier { dir: dir.clone() });
        let sealer = Arc::new(ServiceSealer {
            ops: cfg.ops.clone(),
            dir: dir.clone(),
        });
        let store = cfg.state_dir.as_ref().and_then(|d| {
            let s = ozbox_core::channel::store::Store::<HubState>::new(d.join("hub"));
            if !s.exists() {
                s.create(&HubState::new(&cfg.name, &my_fp, 1)).ok()?;
            }
            Some(s)
        });
        let state = match &store {
            Some(s) => s
                .read()
                .map_err(|_| "the hub's state could not be read".to_string())?,
            None => HubState::new(&cfg.name, &my_fp, 1),
        };
        let svc = Arc::new(HubService {
            me: cfg.name.clone(),
            my_fp: my_fp.clone(),
            roster: BTreeMap::new(),
            signer: signer.clone(),
            verifier: verifier.clone(),
            sealer: sealer.clone(),
            net: net.clone(),
            enrolled: Default::default(),
            state: Mutex::new(state),
            store,
        });
        let fabric = Arc::new(HubFabric::new(
            &cfg.name,
            &my_fp,
            BTreeMap::new(),
            FabricSeams {
                signer,
                verifier,
                sealer,
                net,
                screen: Arc::new(CoreScreen),
                audit: None,
            },
            cfg.walls.clone(),
        ));
        let att = Arc::new(HubAttachment {
            svc,
            fabric,
            socket: cfg.hubd_socket.clone(),
            dir,
            known: Mutex::new(BTreeSet::new()),
            issuer: ServiceIssuer { ops: cfg.ops },
            attest: Arc::new(AttestSocket {
                socket: cfg.hubd_socket,
            }),
        });
        att.sync_roster()?;
        Ok(att)
    }

    /// Add what enrolment attested to the channel, the fabric and the key directory, and drop what was removed. Each worker's
    /// approval-service pin follows the roster too: it is whatever the owner's enrolment applied (the ids and the public envelope
    /// key the worker offered, covered by its proof), set when the worker joins and gone when it leaves. A message never moves it.
    pub fn sync_roster(&self) -> Result<usize, String> {
        let roster = roster_of(&self.socket)?;
        let mut now_known = BTreeSet::new();
        let mut pins: BTreeMap<String, ServicePin> = BTreeMap::new();
        for r in &roster {
            if let Some(p) = &r.service_pin {
                pins.insert(r.worker.clone(), p.clone());
            }
            if !self.dir.insert(&r.identity) {
                continue;
            }
            let fp = r.identity.channel_fp();
            self.svc
                .enrol(&r.worker, RosterEntry { key_fp: fp.clone() });
            self.fabric.enrol(&r.worker, &fp);
            now_known.insert(r.worker.clone());
        }
        if let Ok(mut known) = self.known.lock() {
            for gone in known.difference(&now_known) {
                self.svc.unenrol(gone);
                self.fabric.unenrol(gone);
            }
            *known = now_known;
        }
        let on_roster: BTreeSet<&str> = roster.iter().map(|r| r.worker.as_str()).collect();
        let now = ozbox_hubd::daemon::now_ms();
        let _ = self.svc.with(now, |_, st| {
            // a worker that left the roster takes its pin with it
            let stale: Vec<String> = st
                .service_pins
                .keys()
                .filter(|w| !on_roster.contains(w.as_str()))
                .cloned()
                .collect();
            for w in stale {
                st.service_pins.remove(&w);
            }
            for (w, p) in &pins {
                if st.service_pins.get(w) != Some(p) {
                    st.pin_service(w, p.clone());
                }
            }
        });
        Ok(roster.len())
    }

    /// Pin a worker's approval service (its envelope key and ids) directly, from the server's own code (never a message): for a
    /// worker whose enrolment offered none, and what tests use to pin a deliberately different key. The normal route is the owner's
    /// enrolment, applied by [`HubAttachment::sync_roster`], which also replaces a pin set here for a worker that offered one and
    /// drops the pin of a worker that left the roster. Until a worker is pinned, nothing it files is shown as a request.
    // no server route sets it yet (the roster does); the tests pin a deliberately different key through it
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn pin_service(&self, worker: &str, pin: ServicePin, now: u64) -> bool {
        self.svc
            .with(now, |_, st| st.pin_service(worker, pin))
            .is_some()
    }

    /// One round, called on the server's tick: the roster, what the workers sent, the key asks, the fabric.
    pub fn tick(&self, now: u64) {
        let _ = self.sync_roster();
        let _ = self.svc.with(now, |hub, st| {
            hub.poll(st, now);
            // keys by name: through the issuer path, sealed to the attested key, never Production
            hub.serve_key_asks(st, self.attest.as_ref(), &self.issuer, now);
        });
        let _ = self.fabric.pump(now);
    }
}

/// Reads a worker's attested delivery key from the daemon's roster, per call: never a key `main` reported on its own word.
struct AttestSocket {
    socket: PathBuf,
}

impl ozbox_core::hub::keys::Attestations for AttestSocket {
    fn delivery_key(&self, worker: &str) -> Option<ozbox_core::hub::keys::AttestedKey> {
        roster_of(&self.socket)
            .ok()?
            .into_iter()
            .find(|r| r.worker == worker)
            .map(|r| ozbox_core::hub::keys::AttestedKey {
                public: r.identity.delivery_public.clone(),
                fp: r.identity.delivery_fp(),
            })
    }
}
