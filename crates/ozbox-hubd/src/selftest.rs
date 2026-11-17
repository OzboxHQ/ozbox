//! `ozbox-hubd self-test`: what must hold before the daemon is trusted with a worker. Each check says what it found; none
//! prints a key, a token or a value.

use std::path::Path;

use crate::crypto::verify_ed25519;
use crate::daemon::{handshake_bytes, read_registrars, Config};
use crate::identity::tag_prefix;
use crate::keys::{SignPurpose, HUB_ENVELOPE_TAG};
use crate::ops::KeyOps;

/// One check and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
    }
}

fn mode_uid(p: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(p)
        .ok()
        .map(|m| (m.mode() & 0o7777, m.uid()))
}

/// Run every check. `root_uid` is the uid the registrars file must belong to (0 on a box; a test passes its own).
pub fn self_test(cfg: &Config, ops: &dyn KeyOps, root_uid: u32, now: u64) -> Vec<Check> {
    let mut out = Vec::new();
    // the state directory: this user's alone
    match mode_uid(&cfg.dir) {
        Some((m, _)) if m & 0o077 == 0 => out.push(check("state-dir", true, format!("mode {m:o}"))),
        Some((m, _)) => out.push(check(
            "state-dir",
            false,
            format!("mode {m:o}: another user can read or enter it"),
        )),
        None => out.push(check("state-dir", false, "missing")),
    }
    // the socket's directory: the supervisor's group may enter, nobody else
    match cfg.socket.parent().and_then(mode_uid) {
        Some((m, _)) if m & 0o007 == 0 => {
            out.push(check("socket-dir", true, format!("mode {m:o}")))
        }
        Some((m, _)) => out.push(check(
            "socket-dir",
            false,
            format!("mode {m:o}: any user could connect"),
        )),
        None => out.push(check("socket-dir", false, "missing")),
    }
    // the registrars: written by root only, and at least one
    match (mode_uid(&cfg.registrars), read_registrars(&cfg.registrars)) {
        (None, _) => out.push(check(
            "registrars",
            false,
            "no registrars file: no worker can enrol until the laptop pins one",
        )),
        (Some((m, uid)), _) if uid != root_uid || m & 0o022 != 0 => out.push(check(
            "registrars",
            false,
            "the registrars file must belong to root and be writable by root alone",
        )),
        (Some(_), Err(e)) => out.push(check("registrars", false, e)),
        (Some(_), Ok(r)) if r.registrars.is_empty() => out.push(check(
            "registrars",
            false,
            "no registrar is pinned: no worker can enrol",
        )),
        (Some(_), Ok(r)) => out.push(check(
            "registrars",
            true,
            format!("{} pinned", r.registrars.len()),
        )),
    }
    // the secrets service: answers, and is the hub's socket (handshake yes, envelope no)
    match ops.identity() {
        Err(e) => out.push(check("secrets-service", false, e.to_string())),
        Ok(id) => {
            out.push(check(
                "secrets-service",
                true,
                format!("identity {}", id.identity_fp()),
            ));
            let challenge = [7u8; 32];
            let bytes = handshake_bytes(&id.identity_fp(), &challenge, now);
            let hs = ops
                .sign(SignPurpose::Handshake, &bytes)
                .is_ok_and(|sig| verify_ed25519(&id.handshake_public, &bytes, &sig));
            out.push(check(
                "handshake",
                hs,
                if hs {
                    "the handshake key signs and verifies"
                } else {
                    "the handshake did not sign or verify"
                },
            ));
            let mut probe = tag_prefix(HUB_ENVELOPE_TAG);
            probe.extend_from_slice(b"self-test");
            let refused = ops.sign(SignPurpose::Envelope, &probe).is_err()
                && ops.open(&[], &[0u8; 64]).is_err();
            out.push(check(
                "no-body-operations",
                refused,
                if refused {
                    "this daemon's socket cannot sign an envelope or open a body"
                } else {
                    "this daemon's socket can sign envelopes: it is the wrong socket"
                },
            ));
        }
    }
    out
}
