//! A fresh second factor before the box user can replace a secret (ADR 0018, item 10).
//!
//! Anything that can connect to the box's import socket is a process of the box user, so "I passed a second factor" can
//! only be believed when it comes from somewhere the box user cannot reach. The dashboard (the supervisor, which has a
//! user of its own) checks the person's passkey or authenticator code in its sign-in, and only then asks this service,
//! over a socket only it may open, for a **short-lived approval**: a random 80-bit code bound to one scope (an import of a
//! project's keys for one environment, a project's declaration, a tunnel token, a one-off guard override), good once, for
//! five minutes. The person carries the code to the command that makes the change (`--approval CODE`). The service keeps
//! only a keyed hash of each live code, in memory; a restart forgets every approval.
//!
//! A box with no second factor enrolled yet (a fresh box, before the dashboard has a passkey) cannot ask for one, so
//! until the dashboard says one exists the change is allowed and recorded as `bootstrap`. Once enrolled the box never
//! goes back: only root (the admin socket) can clear the marker, so a process of the box user cannot talk the service
//! into the weaker mode.

use std::collections::HashMap;
use std::sync::Mutex;

use ring::hmac;

/// Every scope an approval can be for, and what a box with **no second factor enrolled yet** may do in it. This table is
/// the one place that is decided: [`crate::secrets_service::Gates::require`] reads it, and so do the root helper's checks
/// (`host_guard_cli::authorize`) and the box's secrets declaration script, which applies the first-setting rule. The
/// dashboard's list of scopes it can mint is compared with it by a test (`packages/dashboard/src/api/secrets.ts`).
pub const SCOPE_RULES: &[(&str, InBootstrap)] = &[
    // a fresh box takes its first keys, declarations and tunnel token before anyone has a passkey (ADR 0023 item 2)
    ("import", InBootstrap::Allowed),
    // the first declaration of a project only: replacing one is a change of what its commands may receive
    ("policy", InBootstrap::FirstSettingOnly),
    ("tunnel-token", InBootstrap::Allowed),
    // a held commit or push: with no one to approve it, the box user would be approving its own override, so it is edited, not let
    // through (ADR 0041)
    ("guard-override", InBootstrap::Refused),
    // who may approve: the box user must never name its own approver (ADR 0028 Amendment 1)
    ("signer-enroll", InBootstrap::Refused),
    // the two things that leave the box for the owner's computer through the ingress route: the dashboard's first-time code
    // and a copy of the file-kept store key. Once a second factor exists the SSH key alone is not enough. The store
    // key is refused before one exists: an escrow that anyone holding only the SSH key can take protects
    // nothing; enrol a passkey or pin a laptop key first. The first-time code is how that first passkey gets enrolled.
    ("setup-code", InBootstrap::Allowed),
    ("kek-export", InBootstrap::Refused),
    // the box's own vault: the first declaration only; a new address, or anything while a token is in place, is refused
    ("box-secrets", InBootstrap::FirstSettingOnly),
    // a change to the box's own guards that lets it do more (ADR 0034, 0035): the root helper asks before it applies one
    ("host-guard", InBootstrap::Refused),
    // replacing the dashboard's kept sign-in settings, which decide who may approve: the box user must never name its own approver
    ("dashboard-auth", InBootstrap::Refused),
];

/// The scopes, in the order of [`SCOPE_RULES`] (a test keeps the two the same).
pub const SCOPES: &[&str] = &[
    "import",
    "policy",
    "tunnel-token",
    "guard-override",
    "signer-enroll",
    "setup-code",
    "kek-export",
    "box-secrets",
    "host-guard",
    "dashboard-auth",
];

/// What a box with no second factor enrolled may do in one scope. Before a second factor exists the box user cannot be told
/// apart from the owner, so this says which changes are still the box's own first settings and which are not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InBootstrap {
    /// Allowed, and recorded as `bootstrap`.
    Allowed,
    /// Allowed for a first setting, refused for a change of one already in place (the caller knows which it is).
    FirstSettingOnly,
    /// Refused: it would let the box user approve for itself, or let the box do more than its owner set.
    Refused,
}

/// The rule for `scope`; a scope this version does not know is refused.
pub fn in_bootstrap(scope: &str) -> InBootstrap {
    SCOPE_RULES
        .iter()
        .find(|(s, _)| *s == scope)
        .map_or(InBootstrap::Refused, |(_, r)| *r)
}

/// What a person is told when a scope is refused because no second factor exists yet.
pub fn bootstrap_refusal(scope: &str) -> String {
    match scope {
        "signer-enroll" => NO_APPROVER.to_string(),
        _ => format!("this box has no second factor enrolled, so nothing here can approve a {scope} change (the box user asking is not an approval). Enrol a passkey in the dashboard, or make the box with `ozbox create` from a computer with a keychain (it pins that computer's key), then ask for an approval"),
    }
}

/// Why the first approver cannot come from inside the box, and the ways it can come.
pub const NO_APPROVER: &str = "this box has no approver yet, and the first one cannot be enrolled from the box: a process on the box could enrol its own key that way. Make the box with `ozbox create` from a computer with a keychain (it pins this computer's key; `ozbox upgrade` pins it on a box that has none), or enrol a passkey in the dashboard, then enrol this key with an approval from it (Settings, Secret approvals, scope signer-enroll)";
/// The rule a refused Production import is told (ADR 0041 §3: a key kept on a computer never decides Production). The same
/// sentence is in the message catalogue (`approval_key.production_needs_dashboard`), which `ozbox secrets approve` uses to refuse
/// before it makes a code; a test keeps the two equal.
pub const PRODUCTION_IMPORT_RULE: &str = "Production imports need an approval from the dashboard (passkey or authenticator), not this computer's key";

/// Whether an approval for `scope` in `env` is one this computer's key may never make: an import into Production (any
/// environment that is not a listed non-Production one, see `is_production_environment`). Only for a name the person gave: an
/// empty environment is not a Production import, it is a request with no environment.
pub fn laptop_key_never_covers(scope: &str, env: &str) -> bool {
    scope == "import"
        && !env.is_empty()
        && ozbox_core::approval_subject::is_production_environment(env)
}

/// What a person is told when a code is refused as not valid (the gate's own wording, [`NOT_VALID`]): for a Production import it
/// also names the rule that most often explains it, since a code made with this computer's own key never covers Production.
/// Any other refusal, and any other scope or environment, is returned as it was.
pub fn refusal_with_rule(scope: &str, env: &str, refusal: String) -> String {
    if refusal == NOT_VALID && laptop_key_never_covers(scope, env) {
        format!("that approval is not valid, has been used, or has expired. {PRODUCTION_IMPORT_RULE}: ask for a new one there")
    } else {
        refusal
    }
}

/// How the gate words a code it does not accept (unknown, spent, expired, or for another scope, project or environment).
pub const NOT_VALID: &str =
    "that approval is not valid, has been used, or has expired: ask for a new one in the dashboard";
pub const DEFAULT_TTL_MS: u64 = 5 * 60_000;
const MAX_TTL_MS: u64 = 10 * 60_000;
const MAX_LIVE: usize = 16;
/// The store name of the marker that says a second factor exists. Not a secret; its presence is the fact.
pub const ENROLLED_MARKER: &str = "second-factor-enrolled";

/// No `0`, `O`, `1` or `I`: a code is read aloud and typed.
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

struct Approval {
    scope: String,
    project: String,
    env: String,
    via: String,
    expires_ms: u64,
}

#[derive(Default)]
struct State {
    live: HashMap<String, Approval>,
}

pub struct ApprovalGate {
    key: hmac::Key,
    state: Mutex<State>,
}

fn seg_ok(s: &str) -> bool {
    s.is_empty()
        || (s.len() <= 32
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// Whether `code` has the shape of an approval code (16 characters of the code alphabet, in any case, with any dashes or
/// spaces a person typed). Checked on the person's computer before a code is sent anywhere, so a typo is said at once and a
/// value that could not be a code never reaches a script.
pub fn is_code_shape(code: &str) -> bool {
    let n = normalise(code);
    n.len() == 16
        && n.bytes().all(|b| ALPHABET.contains(&b))
        && code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ' ')
}

/// What an approval for a tunnel-token change is bound to: the first 32 hex digits (128 bits) of the SHA-256 of the token,
/// trimmed. It goes in the approval's environment field, which the laptop signs and the gate compares, so a code made for
/// one token cannot store another (the box user can see a token that passes through its files, but cannot change which
/// token the code approves). 32 digits is the longest a field may be. Pure; the laptop and the box both call it.
pub fn tunnel_token_binding(token: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, token.trim().as_bytes());
    d.as_ref()
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The code in the one shape the gate and the root helper's request line know: 16 characters of the code alphabet in
/// groups of four, upper case, dashes between (`XXXX-XXXX-XXXX-XXXX`). `None` when it is not a code. A code typed with
/// spaces or in lower case would otherwise split into several words in the helper's request line.
pub fn canonical_code(code: &str) -> Option<String> {
    if !is_code_shape(code) {
        return None;
    }
    let n = normalise(code);
    Some(format!(
        "{}-{}-{}-{}",
        &n[0..4],
        &n[4..8],
        &n[8..12],
        &n[12..16]
    ))
}

/// Letters and digits only, upper case, without the separators a person may have typed.
fn normalise(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalGate {
    pub fn new() -> Self {
        let mut raw = [0u8; 32];
        // If the system has no random numbers nothing can be minted below either (it fails the same way).
        let _ = getrandom::getrandom(&mut raw);
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &raw),
            state: Mutex::new(State::default()),
        }
    }

    fn tag(&self, code: &str) -> String {
        hmac::sign(&self.key, normalise(code).as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A new approval, once usable, for `scope` (and the project and environment it is about, when it is about one).
    pub fn mint(
        &self,
        scope: &str,
        project: &str,
        env: &str,
        via: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<String, String> {
        if !SCOPES.contains(&scope) || !seg_ok(project) || !seg_ok(env) {
            return Err("that approval is not valid".into());
        }
        let ttl = ttl_ms.clamp(1_000, MAX_TTL_MS);
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw)
            .map_err(|_| "no random numbers are available".to_string())?;
        let code: String = raw
            .iter()
            .take(16)
            .map(|b| ALPHABET[(*b & 31) as usize] as char)
            .collect();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.live.retain(|_, a| a.expires_ms > now_ms);
        if st.live.len() >= MAX_LIVE {
            return Err("too many approvals are waiting to be used".into());
        }
        st.live.insert(
            self.tag(&code),
            Approval {
                scope: scope.to_string(),
                project: project.to_string(),
                env: env.to_string(),
                via: via.to_string(),
                expires_ms: now_ms + ttl,
            },
        );
        Ok(format!(
            "{}-{}-{}-{}",
            &code[0..4],
            &code[4..8],
            &code[8..12],
            &code[12..16]
        ))
    }

    /// Use an approval. It is spent by a good answer and by nothing else. **A wrong code never locks anything** (ADR 0041
    /// §2): the code is 80 bits and lives five minutes, so a guess cannot be repeated into success,
    /// and a counter shared by every caller was a lever for the box user to lock the owner out of the codes (the old
    /// five-a-minute lock was global). The service writes a refused line for each wrong code instead.
    pub fn consume(
        &self,
        code: &str,
        scope: &str,
        project: &str,
        env: &str,
        now_ms: u64,
    ) -> Result<String, String> {
        let wrong = NOT_VALID;
        // No code at all is a person who has not asked yet, not a guess.
        if normalise(code).is_empty() {
            return Err(wrong.into());
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.live.retain(|_, a| a.expires_ms > now_ms);
        let tag = self.tag(code);
        let ok = st
            .live
            .get(&tag)
            .is_some_and(|a| a.scope == scope && a.project == project && a.env == env);
        if !ok {
            return Err(wrong.into());
        }
        Ok(st.live.remove(&tag).map(|a| a.via).unwrap_or_default())
    }

    /// [`ApprovalGate::consume`], spent only if `effect` succeeds. The approval is checked and TAKEN under the lock, and the lock is
    /// released before `effect` runs: the effect may be slow (a store on a KMS key calls the key service over the network), and a
    /// slow effect must not stall every other mint and consume on the box. Taking it first is what keeps a code single use: a second
    /// request with the same code, arriving while the effect runs, finds nothing. If the effect fails the approval is put back with its own expiry, so a refused write leaves the person's code usable; if the effect panics the code stays spent,
    /// which is the safe side. The effect may take this gate's lock (it can mint another code).
    pub fn consume_then<T>(
        &self,
        code: &str,
        scope: &str,
        project: &str,
        env: &str,
        now_ms: u64,
        effect: impl FnOnce(&str) -> Result<T, String>,
    ) -> Result<T, ConsumeThen> {
        let wrong = NOT_VALID;
        if normalise(code).is_empty() {
            return Err(ConsumeThen::Approval(wrong.into()));
        }
        let tag = self.tag(code);
        let taken = {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.live.retain(|_, a| a.expires_ms > now_ms);
            let ok = st
                .live
                .get(&tag)
                .is_some_and(|a| a.scope == scope && a.project == project && a.env == env);
            if !ok {
                return Err(ConsumeThen::Approval(wrong.into()));
            }
            st.live.remove(&tag)
        };
        let Some(approval) = taken else {
            return Err(ConsumeThen::Approval(wrong.into()));
        };
        match effect(&approval.via) {
            Ok(out) => Ok(out),
            Err(e) => {
                // put back as it was, with its own expiry: the next use or mint drops it if it has run out meanwhile
                let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                st.live.insert(tag, approval);
                Err(ConsumeThen::Effect(e))
            }
        }
    }
}

/// Why [`ApprovalGate::consume_then`] did not finish: the approval was not valid (nothing ran), or it was and the effect failed (the
/// approval is still unused).
#[derive(Debug)]
pub enum ConsumeThen {
    Approval(String),
    Effect(String),
}

/// What a change is allowed by, in words for the audit line.
pub const VIA_BOOTSTRAP: &str = "bootstrap";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_token_binding_is_32_hex_digits_that_follow_the_token_and_ignore_edge_whitespace() {
        let a = tunnel_token_binding("tok-aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(a.len(), 32);
        assert!(seg_ok(&a));
        assert_eq!(a, tunnel_token_binding("  tok-aaaaaaaaaaaaaaaaaaaaaaaa\n"));
        assert_ne!(a, tunnel_token_binding("tok-bbbbbbbbbbbbbbbbbbbbbbbb"));
    }

    #[test]
    fn a_code_typed_with_spaces_or_in_lower_case_becomes_one_canonical_word() {
        assert_eq!(
            canonical_code("abcd efgh jkmn pqrs").as_deref(),
            Some("ABCD-EFGH-JKMN-PQRS")
        );
        assert_eq!(canonical_code("ABCD-EFGH"), None);
        assert_eq!(canonical_code("ABCD-EFGH-JKMN-PQR$"), None);
    }

    /// One table decides what a box with no approver may do; the plain list of scopes is the same list, in order, and a
    /// scope that is not in it is refused (so a new scope cannot pick the open default by accident).
    #[test]
    fn the_bootstrap_rules_cover_every_scope_and_an_unknown_scope_is_refused() {
        let names: Vec<&str> = SCOPE_RULES.iter().map(|(s, _)| *s).collect();
        assert_eq!(names, SCOPES);
        assert_eq!(in_bootstrap("signer-enroll"), InBootstrap::Refused);
        assert_eq!(in_bootstrap("host-guard"), InBootstrap::Refused);
        assert_eq!(in_bootstrap("box-secrets"), InBootstrap::FirstSettingOnly);
        assert_eq!(in_bootstrap("policy"), InBootstrap::FirstSettingOnly);
        assert_eq!(in_bootstrap("import"), InBootstrap::Allowed);
        assert_eq!(in_bootstrap("something-new"), InBootstrap::Refused);
        assert!(bootstrap_refusal("signer-enroll").contains("no approver yet"));
        assert!(bootstrap_refusal("host-guard").contains("no second factor enrolled"));
    }

    /// The dashboard can mint every scope the service accepts (a security review, 2026-11-11, found two missing: a box
    /// with only a passkey had no way to enrol a laptop key or approve a box-secrets change).
    #[test]
    fn the_dashboard_offers_exactly_the_scopes_the_service_accepts() {
        let ts = include_str!("../../../packages/dashboard/src/api/secrets.ts");
        let line = ts
            .lines()
            .find(|l| l.contains("export const APPROVAL_SCOPES"))
            .unwrap();
        let listed: Vec<&str> = line
            .split('[')
            .nth(1)
            .and_then(|r| r.split(']').next())
            .unwrap_or("")
            .split(',')
            .map(|w| w.trim().trim_matches('\'').trim_matches('"'))
            .filter(|w| !w.is_empty())
            .collect();
        let mut want: Vec<&str> = SCOPES.to_vec();
        let mut have = listed.clone();
        want.sort_unstable();
        have.sort_unstable();
        assert_eq!(
            have, want,
            "packages/dashboard/src/api/secrets.ts APPROVAL_SCOPES"
        );
    }

    #[test]
    fn an_approval_is_good_once_for_its_own_scope_and_expires() {
        let g = ApprovalGate::new();
        let c = g
            .mint(
                "import",
                "app",
                "staging",
                "dashboard-stepup",
                1000,
                DEFAULT_TTL_MS,
            )
            .unwrap();
        assert_eq!(c.len(), 19);
        // another project, another environment and another scope are refused, and the code is still good afterwards
        assert!(g.consume(&c, "import", "other", "staging", 2000).is_err());
        assert!(g.consume(&c, "import", "app", "prod", 2000).is_err());
        assert!(g.consume(&c, "policy", "app", "staging", 2000).is_err());
        // typed in lower case, without the dashes
        let typed = c.replace('-', "").to_lowercase();
        assert_eq!(
            g.consume(&typed, "import", "app", "staging", 3000).unwrap(),
            "dashboard-stepup"
        );
        // spent
        assert!(g.consume(&c, "import", "app", "staging", 4000).is_err());
        // expired
        let c2 = g.mint("policy", "app", "", "x", 10_000, 5_000).unwrap();
        assert!(g.consume(&c2, "policy", "app", "", 15_001).is_err());
    }

    /// ADR 0041 §12 test: garbage on a box-user socket never slows or locks the path that approves. A wrong code is refused
    /// and counts against nothing: a right code still works straight after any number of wrong ones.
    #[test]
    fn wrong_guesses_never_lock_the_gate_and_a_right_code_still_works_straight_after() {
        let g = ApprovalGate::new();
        let c = g.mint("import", "a", "b", "x", 0, DEFAULT_TTL_MS).unwrap();
        for i in 0..1000 {
            assert!(g
                .consume("AAAA-AAAA-AAAA-AAAA", "import", "a", "b", i as u64)
                .is_err());
        }
        assert!(g.consume(&c, "import", "a", "b", 1001).is_ok());
    }

    #[test]
    fn a_bad_scope_or_name_is_never_minted_and_the_queue_is_bounded() {
        let g = ApprovalGate::new();
        assert!(g.mint("root", "", "", "x", 0, 1000).is_err());
        assert!(g.mint("import", "Bad Name", "", "x", 0, 1000).is_err());
        for _ in 0..MAX_LIVE {
            g.mint("import", "a", "b", "x", 0, DEFAULT_TTL_MS).unwrap();
        }
        assert!(g.mint("import", "a", "b", "x", 0, DEFAULT_TTL_MS).is_err());
    }

    #[test]
    fn codes_differ_and_are_made_of_the_readable_alphabet() {
        let g = ApprovalGate::new();
        let a = g.mint("import", "a", "b", "x", 0, 9000).unwrap();
        let b = g.mint("import", "a", "b", "x", 0, 9000).unwrap();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c == '-' || ALPHABET.contains(&(c as u8))));
        assert!(is_code_shape(&a));
    }

    #[test]
    fn only_something_shaped_like_a_code_passes_the_shape_check() {
        assert!(is_code_shape("7B8Y-WLGW-8VVV-33KG"));
        assert!(is_code_shape("7b8ywlgw8vvv33kg"));
        for bad in [
            "",
            "7B8Y-WLGW-8VVV",
            "7B8Y-WLGW-8VVV-33KG-AAAA",
            "0OIL-WLGW-8VVV-33KG",
            "7B8Y;WLGW-8VVV-33KG",
            "7B8Y-WLGW-8VVV-33K'",
        ] {
            assert!(!is_code_shape(bad), "{bad}");
        }
    }

    /// A code is spent by a write that happened and by nothing else: a refused write leaves it usable, and a write that happened
    /// cannot be repeated with it.
    #[test]
    fn a_code_is_spent_only_when_the_write_it_was_for_succeeded() {
        let a = ApprovalGate::new();
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 60_000)
            .unwrap();
        // the wrong scope never runs the effect
        let mut ran = false;
        assert!(matches!(
            a.consume_then(&code, "import", "app", "", 1001, |_| {
                ran = true;
                Ok(())
            }),
            Err(ConsumeThen::Approval(_))
        ));
        assert!(!ran);
        // a write that fails leaves the code usable, any number of times
        for _ in 0..3 {
            assert!(matches!(
                a.consume_then(&code, "policy", "app", "", 1002, |_| Err::<(), _>("full".into())),
                Err(ConsumeThen::Effect(e)) if e == "full"
            ));
        }
        // a write that happens spends it, and says how it was approved
        assert_eq!(
            a.consume_then(&code, "policy", "app", "", 1003, |via| Ok(via.to_string()))
                .unwrap(),
            "dashboard-stepup"
        );
        assert!(a
            .consume_then(&code, "policy", "app", "", 1004, |_| Ok(()))
            .is_err());
        assert!(a.consume(&code, "policy", "app", "", 1004).is_err());
    }

    /// A code put back after a failed write keeps its own expiry: it is usable until then and not a moment longer.
    #[test]
    fn a_code_put_back_after_a_failed_write_still_expires_at_its_own_time() {
        let a = ApprovalGate::new();
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 1000)
            .unwrap();
        assert!(a
            .consume_then(&code, "policy", "app", "", 1500, |_| Err::<(), _>(
                "full".into()
            ))
            .is_err());
        // put back, but the code was only ever good until 2000
        assert!(a.consume(&code, "policy", "app", "", 2000).is_err());
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 1000)
            .unwrap();
        assert!(a
            .consume_then(&code, "policy", "app", "", 1500, |_| Err::<(), _>(
                "full".into()
            ))
            .is_err());
        assert!(a.consume(&code, "policy", "app", "", 1999).is_ok());
    }

    /// Two requests with one code at the same moment: exactly one write happens, however slow it is.
    #[test]
    fn two_requests_with_one_code_make_exactly_one_write() {
        let a = std::sync::Arc::new(ApprovalGate::new());
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 60_000)
            .unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (a, code, writes, barrier) =
                    (a.clone(), code.clone(), writes.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    a.consume_then(&code, "policy", "app", "", 1001, |_| {
                        // a slow store: long enough for every other thread to arrive while this one is writing
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Ok(())
                    })
                    .is_ok()
                })
            })
            .collect();
        let ok = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|b| *b)
            .count();
        assert_eq!(ok, 1);
        assert_eq!(writes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(a.consume(&code, "policy", "app", "", 1002).is_err());
    }

    /// The write may be slow (a store on a key service): while it runs the gate is free, so another code can be minted and used
    /// (a gate held across the write would stall here, and on a real box would stall every mint and consume).
    #[test]
    fn the_gate_is_not_held_while_the_write_runs() {
        let a = std::sync::Arc::new(ApprovalGate::new());
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 60_000)
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let a2 = a.clone();
        std::thread::spawn(move || {
            let r = a2.consume_then(&code, "policy", "app", "", 1001, |_| {
                let other = a2
                    .mint("import", "app", "dev", "dashboard-stepup", 1001, 60_000)
                    .unwrap();
                a2.consume(&other, "import", "app", "dev", 1002).map(|_| ())
            });
            let _ = tx.send(r.is_ok());
        });
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "the write could not use the gate: it is held across the write"
        );
    }

    /// A write that panics leaves the code spent (never live after a write that may have happened), and the gate still works.
    #[test]
    fn a_panicking_write_leaves_the_code_spent_and_the_gate_usable() {
        let a = std::sync::Arc::new(ApprovalGate::new());
        let code = a
            .mint("policy", "app", "", "dashboard-stepup", 1000, 60_000)
            .unwrap();
        let (a2, c2) = (a.clone(), code.clone());
        let r = std::thread::spawn(move || {
            let _ = a2.consume_then(&c2, "policy", "app", "", 1001, |_| -> Result<(), String> {
                panic!("store write panicked")
            });
        })
        .join();
        assert!(r.is_err());
        assert!(a.consume(&code, "policy", "app", "", 1002).is_err());
        assert!(a.mint("policy", "app", "", "x", 1003, 60_000).is_ok());
    }
}
