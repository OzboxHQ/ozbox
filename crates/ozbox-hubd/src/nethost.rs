//! The network end of the hub, inside `ozbox-hubd` (ADR 0042 sections 2 and 3, ADR 0005).
//!
//! `ozbox-hubd` is the only process that faces the network, and its one private operation is a handshake signature (the secrets
//! service's **hub** socket). So the transport of `ozbox_core::hub::net` runs here: workers dial out to the address the hub
//! listens on (loopback or private only), prove who they are with the keys their enrolment attested, and their sealed envelopes
//! are checked once more by the daemon and spooled ([`Hubd::accept`]). The supervisor reads the spool through the daemon's socket
//! ([`crate::daemon::SpoolTransport`]); what it sends for a worker is taken from the outbound spool and put on that worker's link.
//!
//! The daemon never opens a body and never signs one: it carries bytes. The conversation fabric's envelopes (`<box>.fabric`
//! endpoints, ADR 0057) ride the same connection and the same spool; they are checked against their own profile.
//!
//! The roster is not copied by hand: [`NetHost::sync_roster`] reads what enrolment attested, so a worker that enrols is admitted
//! on its next connection, and one that is removed is dropped.

use std::net::SocketAddr;
use std::sync::Arc;

use ozbox_core::hub::engine::RosterEntry;
use ozbox_core::hub::net::{HubNetConfig, NetHub};
use ozbox_core::hub::wire::Transport;

use crate::crypto::{HandshakeSigner, HandshakeVerifier};
use crate::daemon::Hubd;
use crate::ops::KeyOps;

/// The daemon's listener and the bridge between it and the spool.
pub struct NetHost {
    pub net: Arc<NetHub>,
    hubd: Arc<Hubd>,
}

/// What one pump moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Moved {
    pub inbound: usize,
    pub outbound: usize,
    pub refused: usize,
}

impl NetHost {
    /// Listen on `listen` (loopback or private; a wildcard or a public address is refused). `hub_ops` is the secrets service's
    /// hub socket: the handshake is the only thing it signs.
    pub fn start(
        hubd: Arc<Hubd>,
        hub_ops: Arc<dyn KeyOps>,
        listen: SocketAddr,
    ) -> Result<NetHost, String> {
        Self::start_with_clock(hubd, hub_ops, listen, Arc::new(crate::daemon::now_ms))
    }

    /// As [`NetHost::start`], with the clock the first-contact check reads (a test that holds fixed attestations passes its own).
    pub fn start_with_clock(
        hubd: Arc<Hubd>,
        hub_ops: Arc<dyn KeyOps>,
        listen: SocketAddr,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<NetHost, String> {
        let net = NetHub::start(HubNetConfig {
            listen,
            me: hubd.config().name.clone(),
            roster: Default::default(),
            signer: Arc::new(HandshakeSigner { ops: hub_ops }),
            verifier: Arc::new(HandshakeVerifier {
                dir: hubd.directory(),
            }),
        })
        .map_err(|e| format!("the hub could not listen: {e}"))?;
        // first contact: a box that is not on the roster sends its enrolment request once; the daemon screens it (the one-use
        // token, the registrar's attestation, the worker's own proof) and holds it for the owner's plan and apply
        let taker = hubd.clone();
        net.set_enrol_handler(Arc::new(move |bytes: &[u8]| {
            let req: crate::enrol::EnrolRequest = serde_json::from_slice(bytes).map_err(|_| {
                (
                    "malformed".to_string(),
                    "that request is not valid".to_string(),
                )
            })?;
            taker
                .receive_enrolment(&req, clock())
                .map_err(|e| (e.code.to_string(), e.message))
        }));
        let host = NetHost {
            net: Arc::new(net),
            hubd,
        };
        host.sync_roster()?;
        Ok(host)
    }

    /// The address the hub listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.net.local_addr()
    }

    /// Admit the workers enrolment attested and drop the ones that were removed.
    pub fn sync_roster(&self) -> Result<usize, String> {
        let roster = self.hubd.roster()?;
        let mut names = std::collections::BTreeSet::new();
        for r in &roster {
            names.insert(r.worker.clone());
            let entry = RosterEntry {
                key_fp: r.identity.channel_fp(),
            };
            // a worker already known with the same key keeps its link; a new key is a new session
            self.net
                .enrol(&r.worker, entry)
                .map_err(|_| "a worker's name is not valid".to_string())?;
        }
        for (w, _, _) in self.net.status() {
            if !names.contains(&w) {
                self.net.remove(&w);
            }
        }
        Ok(roster.len())
    }

    /// Move what workers sent into the spool (checked once more, spooled before it is acknowledged to anyone) and what the
    /// supervisor queued onto each worker's link. Call it often: it never blocks.
    pub fn pump(&self, now: u64) -> Moved {
        let mut m = Moved::default();
        let me = self.hubd.config().name.clone();
        for endpoint in [me.clone(), format!("{me}.fabric")] {
            while let Some(msg) = self.net.recv(&endpoint) {
                match self.hubd.accept(msg, now) {
                    Ok(()) => m.inbound += 1,
                    Err(_) => m.refused += 1,
                }
            }
        }
        let Ok(roster) = self.hubd.roster() else {
            return m;
        };
        for r in roster {
            let out = self.hubd.take_outbound(&r.worker);
            let mut unsent = Vec::new();
            for msg in out {
                let to = msg.envelope.to.clone();
                // the link keeps what it can carry; past its limit the message goes back to the spool for the next round
                match self.net.send(&to, msg.clone()) {
                    Ok(()) => m.outbound += 1,
                    Err(_) => unsent.push(msg),
                }
            }
            if !unsent.is_empty() {
                let _ = self.hubd.put_outbound(&r.worker, unsent, now);
            }
        }
        m
    }

    pub fn stop(&self) {
        self.net.stop();
    }
}
