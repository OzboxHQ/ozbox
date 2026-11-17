//! The real seams, put together for each end, so the hub's logic (`ozbox_core::hub`) runs on them unchanged.
//!
//! * On `main`, [`hub_seams`] builds the signer, verifier and sealer the supervisor's `HubService` takes, and the roster it
//!   assigns from, out of the roster the daemon's enrolment attested and the supervisor's own secrets service.
//! * On a worker, [`worker_seams`] builds the same from the worker's own service and the hub identity its handshake verified.

use std::collections::BTreeMap;
use std::sync::Arc;

use ozbox_core::channel::wire::{Sealer, Signer, Verifier};
use ozbox_core::hub::engine::RosterEntry;

use crate::crypto::{Directory, DirectoryVerifier, ServiceSealer, ServiceSigner};
use crate::enrol::RosterRecord;
use crate::identity::Identity;
use crate::ops::{KeyOps, OpsError};

/// What one channel end runs on.
pub struct Seams {
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub sealer: Arc<dyn Sealer>,
    /// The attested keys, by channel fingerprint. Add to it when a worker enrols; the sealer and verifier see the change.
    pub directory: Directory,
    /// This end's channel fingerprint: `HubState::new`'s `my_fp`, or `WorkerState::new`'s.
    pub my_fp: String,
}

fn seams(ops: Arc<dyn KeyOps>, directory: Directory) -> Result<Seams, OpsError> {
    let me = ops.identity()?;
    Ok(Seams {
        signer: Arc::new(ServiceSigner { ops: ops.clone() }),
        verifier: Arc::new(DirectoryVerifier {
            dir: directory.clone(),
        }),
        sealer: Arc::new(ServiceSealer {
            ops,
            dir: directory.clone(),
        }),
        directory,
        my_fp: me.channel_fp(),
    })
}

/// `main`'s seams and roster. `ops` is the supervisor's socket to its own secrets service.
pub fn hub_seams(
    ops: Arc<dyn KeyOps>,
    roster: &[RosterRecord],
) -> Result<(Seams, BTreeMap<String, RosterEntry>), OpsError> {
    let dir = Directory::default();
    let mut entries = BTreeMap::new();
    for r in roster {
        if dir.insert(&r.identity) {
            entries.insert(
                r.worker.clone(),
                RosterEntry {
                    key_fp: r.identity.channel_fp(),
                },
            );
        }
    }
    Ok((seams(ops, dir)?, entries))
}

/// A worker's seams. `hub` is the identity the handshake verified against the pinned identity fingerprint; returns the seams
/// and the hub's channel fingerprint (`WorkerState::new`'s `hub_fp`).
pub fn worker_seams(ops: Arc<dyn KeyOps>, hub: &Identity) -> Result<(Seams, String), OpsError> {
    let dir = Directory::default();
    if !dir.insert(hub) {
        return Err(OpsError("the hub's identity is not valid".into()));
    }
    Ok((seams(ops, dir)?, hub.channel_fp()))
}
