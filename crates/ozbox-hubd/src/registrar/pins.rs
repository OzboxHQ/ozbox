//! `ozbox hub repin`: which registrars `main` trusts, changed by plan and apply (ADR 0002).
//!
//! The registrars file is written by root from public keys the owner brings, and is read by the hub on every enrolment, so a
//! removed pin stops counting at once. The box user and the agents cannot write it (it is `0644 root`, in a folder only root
//! writes), and [`apply`] itself refuses to run as anyone but root. A rotation is one plan: add the new key and remove the old
//! one together, so there is never a window with neither.
//!
//! What a repin does **not** do: it does not revoke a worker already enrolled by a registrar that is removed (a roster entry
//! stays until that worker is removed), and it does not carry a signed succession statement (not built).

use std::path::Path;

use ozbox_core::approval_subject::to_hex;
use ozbox_core::channel::wire::{fingerprint, normalize_hex};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::*;
use crate::daemon::read_registrars;
use crate::enrol::{Provider, Refusal, Registrar, Registrars};

/// One change to the pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "lowercase")]
pub enum Change {
    /// Trust a registrar's Ed25519 public key (hex) for a provider.
    Add { provider: Provider, public: String },
    /// Stop trusting the registrar with this fingerprint.
    Remove { fingerprint: String },
    /// A rotation: trust the new key and stop trusting the old, in one step.
    Replace {
        fingerprint: String,
        provider: Provider,
        public: String,
    },
}

/// What a repin would do, before it is done. Public keys and fingerprints only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepinPlan {
    pub change: Change,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub steps: Vec<String>,
    /// A digest of the file this plan read.
    pub based_on: String,
}

fn fp_of(r: &Registrar) -> String {
    r.fingerprint()
}

fn line(r: &Registrar) -> String {
    format!("{} registrar {}", r.provider.word(), fp_of(r))
}

fn digest_of(r: &Registrars) -> String {
    to_hex(digest(&SHA256, &serde_json::to_vec(r).unwrap_or_default()).as_ref())
}

fn pin(provider: Provider, public: &str) -> Result<Registrar, Refusal> {
    let p = normalize_hex(public)
        .filter(|h| h.len() == 64)
        .ok_or_else(|| {
            no(
                CODE_BAD_PIN,
                "a registrar key is 32 bytes of hex (an Ed25519 public key)",
            )
        })?;
    Ok(Registrar {
        provider,
        public: p,
    })
}

fn changed(current: &Registrars, change: &Change) -> Result<Registrars, Refusal> {
    let mut next = current.clone();
    let remove = |next: &mut Registrars, fp: &str| -> Result<(), Refusal> {
        let before = next.registrars.len();
        next.registrars.retain(|r| fp_of(r) != fp);
        if next.registrars.len() == before {
            return Err(no(
                CODE_NO_SUCH_PIN,
                "no pinned registrar has that fingerprint",
            ));
        }
        Ok(())
    };
    let add = |next: &mut Registrars, r: Registrar| -> Result<(), Refusal> {
        if next.registrars.iter().any(|x| fp_of(x) == fp_of(&r)) {
            return Err(no(CODE_DUPLICATE_PIN, "that key is already pinned"));
        }
        next.registrars.push(r);
        Ok(())
    };
    match change {
        Change::Add { provider, public } => add(&mut next, pin(*provider, public)?)?,
        Change::Remove { fingerprint } => remove(&mut next, fingerprint)?,
        Change::Replace {
            fingerprint,
            provider,
            public,
        } => {
            remove(&mut next, fingerprint)?;
            add(&mut next, pin(*provider, public)?)?;
        }
    }
    Ok(next)
}

/// Plan a change against the file as it is now.
pub fn plan(path: &Path, change: &Change) -> Result<RepinPlan, Refusal> {
    let current = read_registrars(path)
        .map_err(|_| no(CODE_WRITE, "the registrars file could not be read"))?;
    let next = changed(&current, change)?;
    let mut steps = Vec::new();
    match change {
        Change::Add { provider, public } => steps.push(format!(
            "pin {} registrar {}: the hub will accept its attestations from now on",
            provider.word(),
            fingerprint(&unhex_or_empty(public))
        )),
        Change::Remove { fingerprint } => steps.push(format!(
            "unpin registrar {fingerprint}: new attestations from it are refused at once; workers it already enrolled stay until removed"
        )),
        Change::Replace {
            fingerprint: old,
            provider,
            public,
        } => steps.push(format!(
            "rotate: unpin registrar {old} and pin {} registrar {} in one step",
            provider.word(),
            fingerprint(&unhex_or_empty(public))
        )),
    }
    if next.registrars.is_empty() {
        steps.push("no registrar will be pinned: no worker can enrol until one is".to_string());
    }
    Ok(RepinPlan {
        change: change.clone(),
        before: current.registrars.iter().map(line).collect(),
        after: next.registrars.iter().map(line).collect(),
        steps,
        based_on: digest_of(&current),
    })
}

fn unhex_or_empty(s: &str) -> Vec<u8> {
    ozbox_core::channel::wire::unhex(s).unwrap_or_default()
}

/// Whether this process is root (it can write the file). Read from `/proc/self`'s owner; no unsafe code.
pub fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

/// Apply a plan: read the file again and refuse a changed one, then write it atomically as `0644`. `as_root` is
/// [`running_as_root`] on a box; a test passes its own answer.
pub fn apply(path: &Path, plan: &RepinPlan, as_root: bool) -> Result<(), Refusal> {
    use std::os::unix::fs::PermissionsExt;
    if !as_root {
        return Err(no(
            CODE_NOT_ROOT,
            "the registrars file is changed by root only, never by the box user or an agent",
        ));
    }
    let current = read_registrars(path)
        .map_err(|_| no(CODE_WRITE, "the registrars file could not be read"))?;
    if digest_of(&current) != plan.based_on {
        return Err(no(
            CODE_STALE_PLAN,
            "the registrars changed since this plan was made; plan again",
        ));
    }
    let next = changed(&current, &plan.change)?;
    let body = serde_json::to_vec_pretty(&next)
        .map_err(|_| no(CODE_WRITE, "the registrars could not be written"))?;
    let tmp = path.with_extension("json.new");
    std::fs::write(&tmp, &body)
        .map_err(|_| no(CODE_WRITE, "the registrars could not be written"))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
        .map_err(|_| no(CODE_WRITE, "the registrars could not be written"))?;
    std::fs::rename(&tmp, path)
        .map_err(|_| no(CODE_WRITE, "the registrars could not be written"))?;
    Ok(())
}
