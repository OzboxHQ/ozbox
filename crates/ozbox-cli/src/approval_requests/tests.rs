use super::*;
use crate::secrets::SecretStore;
use crate::secrets_enc::{KeyProvider, LocalKekProvider};
use crate::secrets_service::{handle_from, Policy};
use crate::tokenmac::TokenMac;
use ozbox_core::approval::PasskeyEvidence;

const T0: u64 = 1_000_000_000;
const BOX_UID: u32 = 1000;

struct Rig {
    dir: tempfile::TempDir,
    store: Arc<EncryptedSecrets>,
    mac: TokenMac,
    gates: Gates,
}

fn hex64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn guard_subject(tree: char) -> Value {
    json!({
        "scope": "guard-override", "hook": "commit",
        "repo_path_hash": hex64('1'), "hook_kind": "pre-commit",
        "tree_id": tree.to_string().repeat(40),
    })
}

/// The unified diff a hook scanned, with nothing in it the box would call a key.
fn clean_diff() -> &'static str {
    "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1,2 @@\n hello\n+a public url\n"
}

fn unhex32(h: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&unhex(h).unwrap());
    out
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// WebAuthn authenticator data: the rpIdHash of the test relying party, the flags and a counter.
fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
    let mut ad = ring::digest::digest(&ring::digest::SHA256, b"x.test")
        .as_ref()
        .to_vec();
    ad.push(flags);
    ad.extend_from_slice(&counter.to_be_bytes());
    ad
}

fn client_data(challenge: &[u8; 32]) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://x.test"}}"#,
        b64url(challenge)
    )
    .into_bytes()
}

fn tunnel_subject() -> Value {
    json!({"scope": "tunnel-token", "kind": "ide", "token_sha256": hex64('c'), "account_tag": "acct1", "tunnel_id": "tun1"})
}

fn rig(enrolled: bool, with_audit: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
    let mac = TokenMac::new(store.clone() as Arc<dyn SecretStore>);
    let gates = Gates::default();
    if enrolled {
        store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
    }
    if with_audit {
        let ad = dir.path().join("audit");
        std::fs::create_dir_all(&ad).unwrap();
        let _ = gates
            .audit
            .set(Arc::new(crate::audit_service::AuditCfg::new(
                &ad,
                dir.path().join("anchor"),
            )));
    }
    gates
        .enable_requests(
            &store,
            &dir.path().join("req"),
            &dir.path().join("state"),
            "box-1",
            T0,
        )
        .unwrap();
    Rig {
        dir,
        store,
        mac,
        gates,
    }
}

impl Rig {
    fn jdir(&self) -> PathBuf {
        self.dir.path().join("req")
    }
    fn sdir(&self) -> PathBuf {
        self.dir.path().join("state")
    }
    fn reopen(&self, now: u64) -> Result<RequestService, String> {
        RequestService::open(&self.store, &self.jdir(), &self.sdir(), "box-1", now)
    }
    fn svc(&self) -> Arc<RequestService> {
        self.gates.requests.get().unwrap().clone()
    }
    /// One request through the real dispatch of the service (real clock), on a socket policy.
    fn call(&self, policy: Policy, uid: Option<u32>, v: Value) -> Value {
        serde_json::from_str(&handle_from(
            &self.store,
            &self.mac,
            &self.gates,
            policy,
            uid,
            &v.to_string(),
        ))
        .unwrap()
    }
    /// One request straight to the request service, with a clock of the test's own.
    fn at(
        &self,
        class: SocketClass,
        uid: Option<u32>,
        now: u64,
        v: Value,
    ) -> Result<Value, String> {
        self.svc()
            .handle(&self.store, &self.gates, class, uid, &v, now)
    }
    fn file_guard(&self, tree: char, uid: u32, now: u64) -> String {
        let r = self
            .at(SocketClass::Box, Some(uid), now, json!({"op":"areq_file","subject":guard_subject(tree),"scanned_text":clean_diff(),"reason":"public url"}))
            .unwrap();
        r["request"]["id"].as_str().unwrap().to_string()
    }
    fn passkey_approve(
        &self,
        id: &str,
        role: &str,
        person: &str,
        cred: &str,
        sig: &str,
        now: u64,
    ) -> Result<Value, String> {
        self.passkey_approve_flags(id, role, person, cred, sig, now, 0x05)
    }
    /// With the authenticator data's flags named: 0x05 is a touch and user verification, 0x01 a touch alone.
    #[allow(clippy::too_many_arguments)]
    fn passkey_approve_flags(
        &self,
        id: &str,
        role: &str,
        person: &str,
        cred: &str,
        sig: &str,
        now: u64,
        flags: u8,
    ) -> Result<Value, String> {
        let c = self.at(
            SocketClass::Supervisor,
            None,
            now,
            json!({"op":"areq_decide_challenge","id":id}),
        )?;
        self.at(
            SocketClass::Supervisor,
            None,
            now,
            json!({"op":"areq_decide","id":id,"outcome":"approve","person":person,"role":role,
                   "surface":"dashboard","factor":"passkey",
                   "rp":{"rp_id":"x.test","origin":"https://x.test"},
                   "evidence":{"passkey":{"credential_id":cred,
                                          "authenticator_data":to_hex(&auth_data(flags, 0)),
                                          "client_data":to_hex(&client_data(&unhex32(c["challenge"].as_str().unwrap()))),
                                          "signature":sig}}}),
        )
    }
    fn chain_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit").join("tasks.audit.jsonl"))
            .unwrap_or_default()
    }
}

// ---- reachability ---------------------------------------------------------------------------------------------------

#[test]
fn the_request_operations_are_unreachable_until_a_decider_turns_them_on() {
    let dir = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
    let mac = TokenMac::new(store.clone() as Arc<dyn SecretStore>);
    let gates = Gates::default();
    let ask = |pol: Policy, v: Value| -> Value {
        serde_json::from_str(&handle_from(
            &store,
            &mac,
            &gates,
            pol,
            Some(BOX_UID),
            &v.to_string(),
        ))
        .unwrap()
    };
    let c = ask(Policy::Box, json!({"op":"areq_capabilities"}));
    assert_eq!(c["ok"], true);
    assert_eq!(
        c["result"]["request_ops"], false,
        "a service that has not turned them on says so"
    );
    let f = ask(
        Policy::Box,
        json!({"op":"areq_file","subject":guard_subject('a'),"scanned_text":clean_diff()}),
    );
    assert_eq!(f["ok"], false);
    assert!(f["error"]
        .as_str()
        .unwrap()
        .contains("does not keep approval requests yet"));
    // the production service turns them on at start (a decider ships in phase 2): `ozbox secrets serve` calls it, and no
    // other production file does
    let cli = include_str!("../secrets_cli.rs");
    let prod = cli.split("#[cfg(test)]\nmod tests").next().unwrap();
    assert!(
        prod.contains("gates.enable_requests("),
        "secrets serve turns the request operations on"
    );
    assert!(!include_str!("../main.rs").contains("enable_requests("));
}

#[test]
fn capabilities_name_the_scopes_and_other_sockets_have_no_request_operations() {
    let r = rig(true, false);
    let c = r.call(Policy::Supervisor, None, json!({"op":"areq_capabilities"}));
    assert_eq!(c["result"]["request_ops"], true);
    let scopes = c["result"]["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 10);
    assert!(scopes.iter().any(|s| s == "setup-code") && scopes.iter().any(|s| s == "kek-export"));
    assert!(!scopes.iter().any(|s| s == "secret-use"));
    // the runner, import and broker sockets do not offer them
    for p in [
        Policy::Runner,
        Policy::Import,
        Policy::Broker,
        Policy::BrokerLocked,
    ] {
        let x = r.call(p, Some(BOX_UID), json!({"op":"areq_capabilities"}));
        assert_eq!(x["ok"], false, "{p:?}");
    }
    assert_eq!(journal_scopes().len(), 10);
}

// ---- the whole flow through the real dispatch ---------------------------------------------------------------------

#[test]
fn a_hook_files_a_dashboard_decides_and_the_hook_spends_once() {
    let r = rig(true, true);
    // the box user's hook files; it sees only the narrow view
    let f = r.call(Policy::Box, Some(BOX_UID), json!({"op":"areq_file","subject":guard_subject('a'),"scanned_text":clean_diff(),"reason":"a public url"}));
    assert_eq!(f["ok"], true, "{f}");
    let id = f["result"]["request"]["id"].as_str().unwrap().to_string();
    let keys: Vec<&str> = f["result"]["request"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        vec!["expires_at_ms", "id", "scope", "state", "subject_digest"]
    );
    assert_eq!(f["result"]["request"]["state"], "pending");
    // a person decides on the dashboard, with the assertion for this request
    let ch = r.call(
        Policy::Supervisor,
        None,
        json!({"op":"areq_decide_challenge","id":id}),
    );
    assert_eq!(ch["ok"], true);
    let d = r.call(
        Policy::Supervisor,
        None,
        json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"member","surface":"dashboard","factor":"passkey",
               "rp":{"rp_id":"x.test","origin":"https://x.test"},
               "evidence":{"passkey":{"credential_id":"c1","authenticator_data":to_hex(&auth_data(0x01, 0)),
                                      "client_data":to_hex(&client_data(&unhex32(ch["result"]["challenge"].as_str().unwrap()))),
                                      "signature":"s1"}}}),
    );
    assert_eq!(d["ok"], true, "{d}");
    assert_eq!(
        d["result"]["request"]["decision"]["factor_label"],
        "passkey"
    );
    // the hook waits and sees it approved, with the digest to recompute
    let w = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"areq_await","id":id,"wait_ms":1000}),
    );
    assert_eq!(w["result"]["request"]["state"], "approved");
    assert_eq!(w["result"]["waiting"], false);
    // and spends it with the subject it recomputed
    let s = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    );
    assert_eq!(s["ok"], true, "{s}");
    let fin = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"areq_finish","id":id}),
    );
    assert_eq!(fin["ok"], true, "{fin}");
    // a second spend is refused
    let again = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    );
    assert_eq!(again["ok"], false);
    assert!(again["error"].as_str().unwrap().contains("already used"));
    // every step is a line in the chain, with the decider, the surface and the factor, and no value
    let chain = r.chain_text();
    for w in [
        "secrets.approval.request.filed",
        "secrets.approval.request.decided",
        "secrets.approval.request.delivered",
        "secrets.approval.request.spent",
        "decider=alice",
        "surface=dashboard",
        "factor=passkey",
    ] {
        assert!(chain.contains(w), "missing {w} in the chain");
    }
    assert!(
        !chain.contains("a public url"),
        "the requester's reason is not in the chain"
    );
}

#[test]
fn the_box_socket_cannot_decide_and_cannot_file_what_is_not_its_to_file() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    for p in [
        Policy::Box,
        Policy::BoxLocked,
        Policy::Runner,
        Policy::Import,
    ] {
        let d = r.call(
            p,
            Some(BOX_UID),
            json!({"op":"areq_decide","id":id,"outcome":"approve","person":"me","role":"owner","surface":"dashboard","factor":"passkey"}),
        );
        assert_eq!(d["ok"], false, "{p:?}");
        assert!(
            d["error"]
                .as_str()
                .unwrap()
                .contains("not allowed on this socket"),
            "{d}"
        );
    }
    // not a challenge either
    let c = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"areq_decide_challenge","id":id}),
    );
    assert_eq!(c["ok"], false);
    // an import is not the box user's to file
    let f = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_file","subject":{"scope":"import","project":"app","environment":"staging","names":[{"name":"A","classification":"secret","value_digest":hex64('a')}],"store_generation":1}}),
        )
        .unwrap_err();
    assert!(f.contains("cannot be filed by the box-user"), "{f}");
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
}

#[test]
fn the_supervisor_can_neither_file_nor_spend_and_a_laptop_key_does_not_decide_here() {
    let r = rig(true, false);
    for v in [
        json!({"op":"areq_file","subject":guard_subject('a'),"scanned_text":clean_diff()}),
        json!({"op":"areq_spend","id":"x","subject":guard_subject('a'),"scanned_text":clean_diff()}),
        json!({"op":"areq_await","id":"x"}),
    ] {
        let e = r.at(SocketClass::Supervisor, None, T0, v).unwrap_err();
        assert!(e.contains("not allowed on this socket"), "{e}");
    }
    let id = r.file_guard('a', BOX_UID, T0);
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0,
            json!({"op":"areq_decide","id":id,"outcome":"approve","person":"p","role":"owner","surface":"dashboard","factor":"laptop-key"}),
        )
        .unwrap_err();
    assert!(e.contains("sealed route"), "{e}");
}

#[test]
fn a_box_user_sees_only_its_own_requests_by_digest_and_state() {
    let r = rig(true, false);
    let mine = r.file_guard('a', BOX_UID, T0);
    let theirs = r.file_guard('b', BOX_UID + 1, T0);
    let t = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":tunnel_subject()}),
        )
        .unwrap();
    let t = t["request"]["id"].as_str().unwrap().to_string();
    let l = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_list"}),
        )
        .unwrap();
    assert_eq!(l["requests"].as_array().unwrap().len(), 1);
    assert_eq!(l["requests"][0]["id"], mine.as_str());
    for other in [&theirs, &t] {
        let e = r
            .at(
                SocketClass::Box,
                Some(BOX_UID),
                T0,
                json!({"op":"areq_get","id":other}),
            )
            .unwrap_err();
        assert_eq!(e, ozbox_core::approval::NOT_FOUND);
        let e = r
            .at(
                SocketClass::Box,
                Some(BOX_UID),
                T0,
                json!({"op":"areq_await","id":other,"wait_ms":10}),
            )
            .unwrap_err();
        assert_eq!(e, ozbox_core::approval::NOT_FOUND);
    }
    // the supervisor sees all, with the card derived from the subject
    let all = r
        .at(SocketClass::Supervisor, None, T0, json!({"op":"areq_list"}))
        .unwrap();
    assert_eq!(all["requests"].as_array().unwrap().len(), 3);
    assert!(all["requests"][0]["display"].is_array());
}

// ---- the review's attack cases -------------------------------------------------------------------------------------

#[test]
fn a_lookalike_card_filed_in_the_persons_slot_neither_burns_nor_swaps_the_approval() {
    let r = rig(true, false);
    let honest = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&honest, "member", "alice", "c1", "s1", T0 + 10)
        .unwrap();
    // the agent files a lookalike (another tree) in the same slot
    let look = r.file_guard('b', BOX_UID, T0 + 20);
    let all = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 21,
            json!({"op":"areq_list"}),
        )
        .unwrap();
    let find = |id: &str| {
        all["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(find(&honest)["state"], "approved");
    assert_eq!(find(&look)["state"], "pending");
    assert_eq!(
        find(&look)["replaces"],
        honest.as_str(),
        "the second card says what it replaces"
    );
    // the honest approval is still spendable for its own digest
    let s = r.at(SocketClass::Box, Some(BOX_UID), T0 + 30, json!({"op":"areq_spend","id":honest,"subject":guard_subject('a'),"scanned_text":clean_diff()}));
    assert!(s.is_ok(), "{s:?}");
}

#[test]
fn a_digest_mismatch_keeps_the_approval_and_names_the_field_never_the_value() {
    let r = rig(true, true);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    let e = r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 2, json!({"op":"areq_spend","id":id,"subject":guard_subject('b'),"scanned_text":clean_diff()}))
        .unwrap_err();
    assert!(e.contains("not what was approved"), "{e}");
    assert!(!e.contains(&"b".repeat(40)));
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Approved);
    assert!(
        r.chain_text().contains("differs=tree"),
        "{}",
        r.chain_text()
    );
    assert!(r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 3, json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}))
        .is_ok());
}

#[test]
fn a_double_spend_a_decide_after_expiry_and_two_deciders_are_all_refused() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    // two deciders: the second is told who and how
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    let e = r
        .passkey_approve(&id, "owner", "bob", "c2", "s2", T0 + 2)
        .unwrap_err();
    assert!(e.contains("already approved by alice"), "{e}");
    // double spend
    let spend =
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()});
    r.at(SocketClass::Box, Some(BOX_UID), T0 + 3, spend.clone())
        .unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 4,
        json!({"op":"areq_finish","id":id}),
    )
    .unwrap();
    assert!(r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 5, spend)
        .is_err());
    // decide after expiry
    let late = r.file_guard('c', BOX_UID + 5, T0 + 10);
    let e = r
        .passkey_approve(
            &late,
            "member",
            "alice",
            "c3",
            "s3",
            T0 + 10 + 30 * 60_000 + 1,
        )
        .unwrap_err();
    assert!(
        e.contains("expired") || e.contains("could not be found"),
        "{e}"
    );
    assert_eq!(r.svc().book().get(&late).unwrap().state, State::Expired);
}

#[test]
fn a_wrong_answer_never_burns_a_request_and_garbage_on_the_box_socket_never_slows_the_decider() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    // an assertion over another challenge is refused, and the request is still pending
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"member","surface":"dashboard","factor":"passkey",
                   "rp":{"rp_id":"x.test","origin":"https://x.test"},
                   "evidence":{"passkey":{"credential_id":"c","authenticator_data":to_hex(&auth_data(0x01, 0)),
                                          "client_data":to_hex(&client_data(&[9u8; 32])),"signature":"s"}}}),
        )
        .unwrap_err();
    assert!(e.contains("another request"), "{e}");
    // and one for this request's challenge but to DENY it is not an approval (the challenge names the outcome)
    let deny_ch = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_decide_challenge","id":id,"outcome":"deny"}),
        )
        .unwrap();
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"member","surface":"dashboard","factor":"passkey",
                   "rp":{"rp_id":"x.test","origin":"https://x.test"},
                   "evidence":{"passkey":{"credential_id":"c","authenticator_data":to_hex(&auth_data(0x01, 0)),
                                          "client_data":to_hex(&client_data(&unhex32(deny_ch["challenge"].as_str().unwrap()))),"signature":"s"}}}),
        )
        .unwrap_err();
    assert!(e.contains("another request"), "{e}");
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
    // a hundred garbage calls on the box socket, a hundred refused decides: the supervisor's path is untouched
    for i in 0..100 {
        let _ = r.call(
            Policy::Box,
            Some(BOX_UID),
            json!({"op":"areq_decide","id":id,"outcome":"approve","n":i}),
        );
        let _ = r.call(
            Policy::Box,
            Some(BOX_UID),
            json!({"op":"areq_spend","id":id,"subject":{"scope":"nope"}}),
        );
    }
    assert!(r
        .passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 2)
        .is_ok());
}

#[test]
fn a_software_key_cannot_decide_through_the_supervisors_socket_and_an_authenticator_code_is_no_factor(
) {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    for factor in ["laptop-key", "totp", "code", ""] {
        let e = r
            .at(
                SocketClass::Supervisor,
                None,
                T0 + 1,
                json!({"op":"areq_decide","id":id,"outcome":"approve","person":"p","role":"owner","surface":"dashboard","factor":factor}),
            )
            .unwrap_err();
        assert!(
            e.contains("sealed route") || e.contains("not valid"),
            "{factor}: {e}"
        );
    }
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
}

#[test]
fn the_owner_decides_a_tunnel_token_until_a_presence_key_has_ever_existed_and_then_only_root_does()
{
    let r = rig(true, false);
    let t = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":tunnel_subject()}),
        )
        .unwrap();
    let id = t["request"]["id"].as_str().unwrap().to_string();
    // a member cannot; the owner can
    assert!(r
        .passkey_approve(&id, "member", "mia", "c1", "s1", T0 + 1)
        .is_err());
    // an owner-only change needs user verification as well as a touch
    let e = r
        .passkey_approve_flags(&id, "owner", "olga", "c2", "s2", T0 + 2, 0x01)
        .unwrap_err();
    assert!(e.contains("user verification"), "{e}");
    assert!(r
        .passkey_approve(&id, "owner", "olga", "c2", "s2", T0 + 2)
        .is_ok());
    // the sticky marker is set (by the verifier of phase 2, or root): the dashboard no longer decides it
    r.store.set(EVER_PRESENCE_MARKER, "1").unwrap();
    let mut other = tunnel_subject();
    other["token_sha256"] = json!(hex64('d'));
    let t2 = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 3,
            json!({"op":"areq_file","subject":other}),
        )
        .unwrap();
    let id2 = t2["request"]["id"].as_str().unwrap().to_string();
    let e = r
        .passkey_approve(&id2, "owner", "olga", "c3", "s3", T0 + 4)
        .unwrap_err();
    assert!(
        e.contains("laptop key with presence has been enrolled"),
        "{e}"
    );
    // root still can, and the root helper spends it from the admin socket (never the box socket)
    let d = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 5,
            json!({"op":"areq_decide","id":id2,"outcome":"approve"}),
        )
        .unwrap();
    assert_eq!(d["request"]["decision"]["factor_label"], "root");
    let e = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0 + 6,
            json!({"op":"areq_spend","id":id2,"subject":tunnel_subject()}),
        )
        .unwrap_err();
    assert!(
        e.contains("not spent from this socket") || e == ozbox_core::approval::NOT_FOUND,
        "{e}"
    );
    let mut sub = tunnel_subject();
    sub["token_sha256"] = json!(hex64('d'));
    assert!(r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 7,
            json!({"op":"areq_spend","id":id2,"subject":sub})
        )
        .is_ok());
}

#[test]
fn a_decider_removed_by_the_supervisor_voids_what_they_approved() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "mia", "c1", "s1", T0 + 1)
        .unwrap();
    let v = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 2,
            json!({"op":"areq_decider_revoked","person":"mia"}),
        )
        .unwrap();
    assert_eq!(v["voided"].as_array().unwrap().len(), 1);
    assert!(r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 3, json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}))
        .is_err());
    // the box socket cannot push this
    assert!(r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_decider_revoked","person":"mia"})
        )
        .is_err());
}

#[test]
fn a_box_with_no_second_factor_refuses_a_guard_override_and_host_guard_and_says_how_to_enrol() {
    // with no one to approve it, the box user would be approving its own override
    let r = rig(false, true);
    let e = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_file","subject":guard_subject('a'),"scanned_text":clean_diff()}),
        )
        .unwrap_err();
    assert!(
        e.contains("no second factor") && e.contains("Enrol a passkey"),
        "{e}"
    );
    assert!(
        !r.chain_text().contains("factor=bootstrap"),
        "{}",
        r.chain_text()
    );
    let hg = json!({"scope":"host-guard","action":"open-port","loosening":true,"fields":[["port","8080"]]});
    let e = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":hg}),
        )
        .unwrap_err();
    assert!(e.contains("no second factor"), "{e}");
}

// ---- long poll and caps --------------------------------------------------------------------------------------------

#[test]
fn an_await_wakes_when_the_decision_arrives_and_never_busy_loops() {
    let r = Arc::new(rig(true, false));
    let id = r.file_guard('a', BOX_UID, T0);
    let r2 = r.clone();
    let id2 = id.clone();
    let waiter = std::thread::spawn(move || {
        let t = Instant::now();
        let w = r2
            .at(
                SocketClass::Box,
                Some(BOX_UID),
                T0 + 1,
                json!({"op":"areq_await","id":id2,"wait_ms":20000}),
            )
            .unwrap();
        (w, t.elapsed())
    });
    std::thread::sleep(Duration::from_millis(150));
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 2)
        .unwrap();
    let (w, took) = waiter.join().unwrap();
    assert_eq!(w["request"]["state"], "approved");
    assert!(took < Duration::from_secs(5), "{took:?}");
    // a request nobody decides answers "still waiting" after the wait, with the request left pending
    let id3 = r.file_guard('b', BOX_UID + 7, T0);
    let w = r
        .at(
            SocketClass::Box,
            Some(BOX_UID + 7),
            T0,
            json!({"op":"areq_await","id":id3,"wait_ms":50}),
        )
        .unwrap();
    assert_eq!(w["waiting"], true);
    assert_eq!(w["request"]["state"], "pending");
}

#[test]
fn the_await_caps_hold_and_resolve_and_the_broker_still_answer_while_they_are_full() {
    let r = Arc::new(rig(true, false));
    r.store.set("workload.app.staging.API_KEY", "v-1").unwrap();
    let id = r.file_guard('a', BOX_UID, T0);
    // park AWAITS_PER_REQUEST waits on one request, so the per-request cap bites
    let mut parked = Vec::new();
    for i in 0..AWAITS_PER_REQUEST {
        let r2 = r.clone();
        let id2 = id.clone();
        parked.push(std::thread::spawn(move || {
            r2.at(
                SocketClass::Box,
                Some(BOX_UID),
                T0 + 1,
                json!({"op":"areq_await","id":id2,"wait_ms":1500}),
            )
            .map(|_| i)
        }));
    }
    std::thread::sleep(Duration::from_millis(300));
    let e = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0 + 1,
            json!({"op":"areq_await","id":id,"wait_ms":10}),
        )
        .unwrap_err();
    assert!(e.contains("already being waited on"), "{e}");
    // per uid: the root helper (one uid) holds AWAITS_PER_UID waits on as many requests, and the next is refused
    let tunnel = |n: usize| {
        let mut s = tunnel_subject();
        s["kind"] = json!(format!("ide-{n}"));
        s
    };
    let mut ids = Vec::new();
    for n in 0..=AWAITS_PER_UID {
        let f = r
            .at(
                SocketClass::Admin,
                Some(0),
                T0,
                json!({"op":"areq_file","subject":tunnel(n)}),
            )
            .unwrap();
        ids.push(f["request"]["id"].as_str().unwrap().to_string());
    }
    for id in ids.iter().take(AWAITS_PER_UID) {
        let r2 = r.clone();
        let id2 = id.clone();
        parked.push(std::thread::spawn(move || {
            r2.at(
                SocketClass::Admin,
                Some(0),
                T0 + 1,
                json!({"op":"areq_await","id":id2,"wait_ms":1500}),
            )
            .map(|_| 0)
        }));
    }
    std::thread::sleep(Duration::from_millis(300));
    let extra = ids[AWAITS_PER_UID].clone();
    let e = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 1,
            json!({"op":"areq_await","id":extra,"wait_ms":10}),
        )
        .unwrap_err();
    assert!(e.contains("too many requests are being waited on"), "{e}");
    // with every cap full, resolve and the box socket's own operations still answer, and fast
    let t = Instant::now();
    let res = r.call(
        Policy::Runner,
        Some(BOX_UID),
        json!({"op":"resolve","project":"app","env":"staging","text":"{{secret:API_KEY}}","allowed":["API_KEY"]}),
    );
    assert_eq!(res["value"], "v-1", "{res}");
    let ex = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"exists","name":"email-api-key"}),
    );
    assert_eq!(ex["ok"], true);
    assert!(
        t.elapsed() < Duration::from_millis(800),
        "{:?}",
        t.elapsed()
    );
    for p in parked {
        let _ = p.join();
    }
    // and the slots came back
    assert!(r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 1,
            json!({"op":"areq_await","id":extra,"wait_ms":10})
        )
        .is_ok());
}

// ---- the journal ---------------------------------------------------------------------------------------------------

#[test]
fn the_journal_is_sealed_and_never_the_secrets_file_and_requests_never_write_the_store() {
    let r = rig(true, false);
    let before = std::fs::read(r.dir.path().join("s.json")).unwrap();
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 2,
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    )
    .unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 3,
        json!({"op":"areq_finish","id":id}),
    )
    .unwrap();
    r.at(
        SocketClass::Supervisor,
        None,
        T0 + 4,
        json!({"op":"areq_get","id":id,"envelope":true}),
    )
    .unwrap();
    r.at(
        SocketClass::Supervisor,
        None,
        T0 + 4,
        json!({"op":"areq_list"}),
    )
    .unwrap();
    // the secrets file is byte for byte what it was: no request wrote it (every key it needs was made when it was opened)
    assert_eq!(std::fs::read(r.dir.path().join("s.json")).unwrap(), before);
    // the journal is a file of its own, sealed: no scope, id or digest in it in the clear
    let j = std::fs::read(r.jdir().join(JOURNAL_FILE)).unwrap();
    let text = String::from_utf8_lossy(&j);
    for needle in ["guard-override", id.as_str(), "alice", "pre-commit"] {
        assert!(
            !text.contains(needle),
            "{needle} is readable in the journal"
        );
    }
    assert!(!String::from_utf8_lossy(&before).contains(&id));
}

#[test]
fn a_damaged_journal_or_one_from_another_store_is_set_aside_and_every_request_in_it_is_void() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    let epoch = r.svc().book().epoch;
    let path = r.jdir().join(JOURNAL_FILE);
    let mut j = std::fs::read(&path).unwrap();
    let n = j.len();
    j[n - 3] ^= 0xff;
    std::fs::write(&path, &j).unwrap();
    // reopened: the box is usable, nothing from the damaged journal is, and a new epoch started
    let svc = r.reopen(T0 + 2).unwrap();
    let b = svc.book();
    assert!(b.get(&id).is_none());
    assert_ne!(b.epoch, epoch);
    let aside: Vec<_> = std::fs::read_dir(r.jdir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("void-"))
        .collect();
    assert_eq!(
        aside.len(),
        1,
        "the damaged file is kept for root, not deleted"
    );
    let g = Gates::default();
    assert!(svc
        .handle(&r.store, &g, SocketClass::Box, Some(BOX_UID), &json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}), T0 + 3)
        .is_err());
    // a journal sealed under another store's key (the store was replaced, the files copied across) is the same case
    let d2 = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let other = EncryptedSecrets::new(d2.path().join("s.json"), "box-b", p).unwrap();
    let svc2 = RequestService::open(&other, &r.jdir(), &r.sdir(), "box-1", T0 + 4).unwrap();
    assert!(svc2.book().requests.is_empty());
}

#[test]
fn a_restore_that_brings_back_an_approved_request_cannot_spend_it() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    let jpath = r.jdir().join(JOURNAL_FILE);
    let backup = std::fs::read(&jpath).unwrap();
    // the box is restored: a new epoch is made (the state file is outside what a restore brings back), and the old journal
    // is put back
    let e = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 2,
            json!({"op":"areq_new_epoch"}),
        )
        .unwrap();
    assert!(!e["voided"].as_array().unwrap().is_empty());
    std::fs::write(&jpath, &backup).unwrap();
    let reopened = r.reopen(T0 + 3).unwrap();
    let b = reopened.book();
    assert_eq!(b.get(&id).unwrap().state, State::Expired);
    assert!(b
        .get(&id)
        .unwrap()
        .void_reason
        .as_ref()
        .unwrap()
        .contains("restore"));
    let g = Gates::default();
    let err = reopened
        .handle(&r.store, &g, SocketClass::Box, Some(BOX_UID), &json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}), T0 + 4)
        .unwrap_err();
    assert!(err.contains("expired") || err.contains("reset"), "{err}");
    // only root makes an epoch
    assert!(r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_new_epoch"})
        )
        .is_err());
    assert!(r
        .at(
            SocketClass::Supervisor,
            None,
            T0,
            json!({"op":"areq_new_epoch"})
        )
        .is_err());
}

#[test]
fn a_journal_copied_back_inside_one_epoch_cannot_revive_a_spent_request() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    let jpath = r.jdir().join(JOURNAL_FILE);
    let backup = std::fs::read(&jpath).unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 2,
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    )
    .unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 3,
        json!({"op":"areq_finish","id":id}),
    )
    .unwrap();
    std::fs::write(&jpath, &backup).unwrap();
    let reopened = r.reopen(T0 + 4).unwrap();
    assert_eq!(
        reopened.book().get(&id).unwrap().state,
        State::Spent,
        "the ledger outside the journal still holds it"
    );
    let g = Gates::default();
    assert!(reopened
        .handle(&r.store, &g, SocketClass::Box, Some(BOX_UID), &json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}), T0 + 5)
        .is_err());
}

#[test]
fn a_spend_interrupted_after_the_journal_was_written_is_refused_and_shown_never_spent_twice() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    r.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 2,
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    )
    .unwrap();
    // the service crashes here (no finish); it restarts
    let reopened = r.reopen(T0 + 3).unwrap();
    assert_eq!(reopened.book().get(&id).unwrap().state, State::Spending);
    let g = Gates::default();
    let e = reopened
        .handle(&r.store, &g, SocketClass::Box, Some(BOX_UID), &json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}), T0 + 4)
        .unwrap_err();
    assert!(e.contains("interrupted"), "{e}");
}

// ---- the audit chain: approve and spend fail closed, deny fails safe -----------------------------------------------

fn rig_with_broken_chain() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
    let mac = TokenMac::new(store.clone() as Arc<dyn SecretStore>);
    let gates = Gates::default();
    store
        .set(crate::secrets_approval::ENROLLED_MARKER, "1")
        .unwrap();
    // the chain's directory is a file: nothing can be written to it
    let bad = dir.path().join("not-a-dir");
    std::fs::write(&bad, "x").unwrap();
    let _ = gates
        .audit
        .set(Arc::new(crate::audit_service::AuditCfg::new(
            &bad,
            dir.path().join("anchor"),
        )));
    gates
        .enable_requests(
            &store,
            &dir.path().join("req"),
            &dir.path().join("state"),
            "box-1",
            T0,
        )
        .unwrap();
    Rig {
        dir,
        store,
        mac,
        gates,
    }
}

#[test]
fn approve_and_spend_fail_closed_when_the_chain_cannot_be_written_and_deny_fails_safe() {
    let r = rig_with_broken_chain();
    let id = r.file_guard('a', BOX_UID, T0);
    let e = r
        .passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap_err();
    assert!(e.contains("audit chain could not be written"), "{e}");
    assert_eq!(
        r.svc().book().get(&id).unwrap().state,
        State::Pending,
        "no chain line, no approval"
    );
    // root cannot approve it either
    assert!(r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 2,
            json!({"op":"areq_decide","id":id,"outcome":"approve"})
        )
        .is_err());
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
    // a deny fails safe: the state changes at once, and the line waits for the chain
    let d = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0 + 3,
            json!({"op":"areq_decide","id":id,"outcome":"deny"}),
        )
        .unwrap();
    assert_eq!(d["request"]["state"], "denied");
    // a spend: approve is impossible, so build the case with a healthy chain, then spend against a broken one
    let ok = rig(true, true);
    let id = ok.file_guard('a', BOX_UID, T0);
    ok.passkey_approve(&id, "member", "alice", "c1", "s1", T0 + 1)
        .unwrap();
    // swap the chain for a broken one by breaking the directory under it
    std::fs::remove_dir_all(ok.dir.path().join("audit")).unwrap();
    std::fs::write(ok.dir.path().join("audit"), "x").unwrap();
    let e = ok
        .at(SocketClass::Box, Some(BOX_UID), T0 + 2, json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}))
        .unwrap_err();
    assert!(e.contains("audit chain could not be written"), "{e}");
    assert_eq!(
        ok.svc().book().get(&id).unwrap().state,
        State::Approved,
        "no chain line, no effect, approval kept"
    );
}

// ---- the box user cannot reach the service's own names --------------------------------------------------------------

#[test]
fn the_markers_and_keys_this_module_keeps_are_not_the_box_users_to_read_write_or_list() {
    let r = rig(true, false);
    for n in RESERVED {
        for op in ["set", "delete"] {
            let x = r.call(
                Policy::Box,
                Some(BOX_UID),
                json!({"op":op,"name":n,"value":"1"}),
            );
            assert_eq!(x["ok"], false, "{op} {n}");
        }
        let x = r.call(Policy::Box, Some(BOX_UID), json!({"op":"get","name":n}));
        assert_eq!(x["ok"], false, "get {n}");
        assert!(crate::approval_key::is_reserved(n), "{n}");
    }
    let names = r.call(
        Policy::Box,
        Some(BOX_UID),
        json!({"op":"names","prefix":"approval"}),
    );
    let listed = names["names"].to_string();
    for n in RESERVED {
        assert!(!listed.contains(n), "{n} is listed to the box user");
    }
    // the supervisor cannot set the software-key marker either: only root can
    let x = r.call(
        Policy::Supervisor,
        None,
        json!({"op":"set","name":SOFTWARE_KEYS_MARKER,"value":"1"}),
    );
    assert_eq!(x["ok"], false);
    assert_eq!(
        r.call(
            Policy::Admin,
            Some(0),
            json!({"op":"set","name":SOFTWARE_KEYS_MARKER,"value":"1"})
        )["ok"],
        true
    );
}

#[test]
fn enrolling_a_laptop_key_sets_the_ever_had_a_key_marker_and_revoking_it_does_not_clear_it() {
    let r = rig(false, false);
    let (_, public) = crate::approval_key::generate().unwrap();
    let e = r.call(
        Policy::Admin,
        Some(0),
        json!({"op":"approval_key_enroll","key_id":"laptop","public_key":public}),
    );
    assert_eq!(e["ok"], true, "{e}");
    assert!(r.store.exists(EVER_KEY_MARKER).unwrap());
    let x = r.call(
        Policy::Admin,
        Some(0),
        json!({"op":"approval_key_revoke","key_id":"laptop"}),
    );
    assert_eq!(x["ok"], true, "{x}");
    assert!(
        r.store.exists(EVER_KEY_MARKER).unwrap(),
        "only root clears it"
    );
}

// ---- parity and benchmark guards -----------------------------------------------------------------------------------

#[test]
fn the_rule_table_agrees_with_the_bootstrap_table_for_every_scope_it_knows() {
    use crate::secrets_approval::{in_bootstrap, InBootstrap, SCOPE_RULES};
    for (scope, boot) in SCOPE_RULES {
        let row = ozbox_core::approval::rule_for(scope)
            .unwrap_or_else(|| panic!("{scope} has no row in the rule table"));
        let want = match boot {
            InBootstrap::Allowed => ozbox_core::approval::Boot::Allowed,
            InBootstrap::FirstSettingOnly => ozbox_core::approval::Boot::FirstSettingOnly,
            InBootstrap::Refused => ozbox_core::approval::Boot::Refused,
        };
        assert_eq!(row.bootstrap, want, "{scope}");
        assert_eq!(in_bootstrap(scope), *boot);
    }
    // the scopes other branches add are in the table; ADR 0029 A9's setup-code and kek-export are in SCOPE_RULES too (merged
    // with feat/prod-secrets-p1, and checked above), ADR 0042's worker-keys and the issuer's secret-use are not yet
    let extra: Vec<&str> = ozbox_core::approval::RULES
        .iter()
        .map(|r| r.key)
        .filter(|k| !SCOPE_RULES.iter().any(|(s, _)| s == k))
        .collect();
    for k in [
        "setup-code",
        "kek-export",
        "worker-keys",
        "secret-use",
        "agent-action",
        "agent-action-protected",
        "agent-action-production",
    ] {
        assert!(
            extra.contains(&k) || SCOPE_RULES.iter().any(|(s, _)| *s == k),
            "{k}"
        );
    }
}

#[test]
fn the_dashboards_copy_of_the_rule_table_is_the_generated_one() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/dashboard/src/api/approval-rules.ts");
    let want = ozbox_core::approval::rule_table_ts();
    if std::env::var("OZBOX_WRITE_APPROVAL_RULES").is_ok() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        have, want,
        "packages/dashboard/src/api/approval-rules.ts is out of date: regenerate with OZBOX_WRITE_APPROVAL_RULES=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_rule_table"
    );
}

/// The benchmark (owner rule, 2026-11-12): nothing here is on the path of `resolve` or `exec`. The guard and the secrets
/// service's `resolve` arm do not reach the request journal, and the only place the service touches it is one dispatch that
/// runs before any other op is parsed, only for an `areq_` op.
#[test]
fn nothing_on_the_path_of_resolve_or_exec_reaches_the_request_journal() {
    for (name, src) in [
        ("guard.rs", include_str!("../guard.rs")),
        (
            "secrets_approval.rs",
            include_str!("../secrets_approval.rs"),
        ),
    ] {
        assert!(
            !src.contains("areq_") && !src.contains("approval_requests"),
            "{name}"
        );
    }
    let svc = include_str!("../secrets_service.rs");
    let prod = svc.split("#[cfg(test)]\nmod tests").next().unwrap();
    // the dispatch, and the import's spend: that runs only when the import names a request id, never for `resolve`
    assert_eq!(
        prod.matches("gates.requests").count(),
        2,
        "the dispatch and the import by request, nothing else"
    );
    let resolve_arm = prod
        .split("(Policy::Runner | Policy::Admin, \"resolve\")")
        .nth(1)
        .unwrap();
    let resolve_arm = resolve_arm.split("\n        (").next().unwrap();
    assert!(!resolve_arm.contains("requests") && !resolve_arm.contains("areq"));
    // and no waiting hook: no operation anywhere waits on a request yet
    assert!(
        !include_str!("../main.rs").contains("areq_await"),
        "a waiting hook ships with a decider"
    );
}

#[test]
fn no_unsafe_or_wrongly_open_state_file_the_journal_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig(true, false);
    r.file_guard('a', BOX_UID, T0);
    for (d, f) in [(r.jdir(), JOURNAL_FILE), (r.sdir(), STATE_FILE)] {
        let m = std::fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o600, "{f}");
    }
}

#[test]
fn the_signed_envelope_is_signed_under_its_own_tag_and_read_only_through_verify() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    let g = r
        .at(
            SocketClass::Supervisor,
            None,
            T0,
            json!({"op":"areq_get","id":id,"envelope":true}),
        )
        .unwrap();
    let se: SignedEnvelope = serde_json::from_value(g["signed_envelope"].clone()).unwrap();
    // nothing but the signed text, the algorithm and the signature travels in it: no unsigned body, no key to trust
    let keys: Vec<&str> = g["signed_envelope"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, vec!["alg", "canonical", "signature"]);
    // the key a verifier pins comes beside it, at pairing time, and is the only thing the signature is checked against
    let pinned = g["envelope_key"].as_str().unwrap().to_string();
    let ids = r.svc().ids.clone();
    let env = se.verify(&pinned, &ids).unwrap();
    assert_eq!(env.id, id);
    assert_eq!(env.epoch, r.svc().book().epoch);
    assert_eq!(
        (env.box_id.as_str(), env.store_id.as_str()),
        ("box-1", ids.store_id.as_str())
    );
    assert_eq!(se.alg, "ed25519");
    // a changed text does not verify, and neither does a signature checked as if it were over the bare text
    let tampered = SignedEnvelope {
        canonical: se.canonical.replace(&id, "OTHER"),
        ..se.clone()
    };
    assert!(tampered.verify(&pinned, &ids).is_err());
    let msg = SignedEnvelope::signed_message(&se.canonical);
    assert!(crate::approval_key::verify(&pinned, &msg, &se.signature));
    assert!(!crate::approval_key::verify(
        &pinned,
        &se.canonical,
        &se.signature
    ));
    // another box's service does not accept it
    assert!(se
        .verify(
            &pinned,
            &Ids {
                box_id: "box-2".into(),
                store_id: ids.store_id.clone()
            }
        )
        .is_err());
    // the box socket never gets one
    let b = r
        .at(
            SocketClass::Box,
            Some(BOX_UID),
            T0,
            json!({"op":"areq_get","id":id,"envelope":true}),
        )
        .unwrap();
    assert!(b.get("signed_envelope").is_none());
}

/// RL3: when a verdict cannot be kept, the request this filing made is cancelled, but a filing that joined a live request (it made
/// nothing) leaves that request alone.
#[test]
fn a_verdict_that_cannot_be_kept_cancels_only_a_request_the_filing_made() {
    let r = rig(true, false);
    let id = r.file_guard('b', BOX_UID, T0);
    let svc = r.svc();
    let mut g = svc.inner.lock().unwrap();
    let failed = || Err::<(), String>("the enrolment could not be kept".into());
    assert!(settle_kept(&mut g.book.requests, &id, true, Ok(())).is_ok());
    assert_eq!(
        g.book.get(&id).unwrap().state,
        State::Pending,
        "a kept verdict cancels nothing"
    );
    assert!(settle_kept(&mut g.book.requests, &id, true, failed()).is_err());
    assert_eq!(
        g.book.get(&id).unwrap().state,
        State::Pending,
        "a filing that joined a live request must not cancel it"
    );
    assert!(settle_kept(&mut g.book.requests, &id, false, failed()).is_err());
    assert_eq!(g.book.get(&id).unwrap().state, State::Cancelled);
}

/// The check "is whoever approved still valid" at spend reads the service's own key records by the key's id, which is the
/// decision's `decider` (the key's id from the service's record, never the caller's word).
#[test]
fn an_approval_a_laptop_key_gave_dies_at_spend_when_the_key_is_revoked() {
    use ozbox_core::approval::{DecideInput, KeyType, KeyView, LaptopEvidence, SignatureFormat};
    let r = rig(true, false);
    let (seed, pk) = crate::approval_key::generate().unwrap();
    r.store.set("approval-key.lap", &pk).unwrap();
    let id = r.file_guard('a', BOX_UID, T0);
    {
        // the ingress socket does not exist yet (phase 2); the same core call it will make, with a real signature over this
        // request's own message
        let svc = r.svc();
        let mut g = svc.inner.lock().unwrap();
        let (ctx, _) = svc.ctx(&r.store).unwrap();
        let k = KeyView {
            id: "lap".into(),
            key_type: KeyType::Ed25519,
            presence_proved: false,
            attestation_digest: None,
            public_half: pk.clone(),
            active: true,
            application: None,
            rp: None,
        };
        let digest = unhex32(&g.book.get(&id).unwrap().subject_digest);
        let msg = ozbox_core::approval_subject::decide_message(&ctx.ids, &id, &digest, "approve");
        let evidence = |sig: String, m: &str| Evidence {
            passkey: None,
            laptop: Some(LaptopEvidence {
                key_id: "lap".into(),
                key_type: KeyType::Ed25519,
                signature_format: SignatureFormat::Ed25519Message,
                signed_message: to_hex(m.as_bytes()),
                signature: sig,
                authenticator_data: None,
                attestation_digest: None,
            }),
            authenticator: None,
        };
        let input = |evidence: Evidence| DecideInput {
            class: SocketClass::Ingress,
            outcome: Outcome::Approve,
            surface: Surface::Laptop,
            factor: Factor::LaptopKey,
            decider: "whatever the caller says".into(),
            role: None,
            evidence,
            key: Some(k.clone()),
            passkey_rp: None,
            via_fleet: None,
        };
        // a signature over another request's message is refused
        let other =
            ozbox_core::approval_subject::decide_message(&ctx.ids, "OTHER", &digest, "approve");
        let wrong = g.book.decide(
            &ctx,
            T0 + 1,
            &id,
            input(evidence(
                crate::approval_key::sign(&seed, &other).unwrap(),
                &other,
            )),
        );
        assert!(wrong.is_err(), "{wrong:?}");
        g.book
            .decide(
                &ctx,
                T0 + 1,
                &id,
                input(evidence(
                    crate::approval_key::sign(&seed, &msg).unwrap(),
                    &msg,
                )),
            )
            .unwrap();
        assert_eq!(
            g.book.get(&id).unwrap().decision.as_ref().unwrap().decider,
            "lap"
        );
    }
    // the key is revoked (its record is gone): the approval is void at spend
    r.store.delete("approval-key.lap").unwrap();
    let e = r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 2, json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}))
        .unwrap_err();
    assert!(e.contains("no longer valid"), "{e}");
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Denied);
}

#[test]
fn the_environments_the_rules_call_non_production_are_the_ones_the_boxs_own_declaration_accepts() {
    assert_eq!(
        ozbox_core::approval_subject::NON_PRODUCTION_ENVS,
        crate::box_secrets::ENVS
    );
    // and an environment named for production in the box's workload rule is production here
    for e in ["production", "prod", "live"] {
        assert!(crate::workload::live_reason("K", "v", e).is_some());
        assert!(ozbox_core::approval_subject::is_production_environment(e));
    }
}

#[test]
fn a_passkey_evidence_struct_is_what_the_supervisor_sends_and_the_record_keeps() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    let d = r
        .passkey_approve(&id, "member", "alice", "cred-9", "sig-9", T0 + 1)
        .unwrap();
    let ev: PasskeyEvidence =
        serde_json::from_value(d["request"]["decision"]["evidence"]["passkey"].clone()).unwrap();
    assert_eq!(ev.credential_id, "cred-9");
    assert_eq!(ev.signature, "sig-9");
    assert_eq!(ev.credential_id.len(), 6);
    // an oversized field is refused
    let id2 = r.file_guard('b', BOX_UID + 3, T0);
    let big = "x".repeat(MAX_EVIDENCE_FIELD + 1);
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 2,
            json!({"op":"areq_decide","id":id2,"outcome":"approve","person":"p","role":"owner","surface":"dashboard","factor":"passkey",
                   "rp":{"rp_id":"x.test","origin":"https://x.test"},
                   "evidence":{"passkey":{"credential_id":big,"authenticator_data":"aa","client_data":"bb","signature":"s"}}}),
        )
        .unwrap_err();
    assert!(e.contains("not valid"), "{e}");
}

#[test]
fn a_service_scope_is_spent_only_inside_its_own_operation_never_as_a_separate_spend() {
    let r = rig(true, true);
    let subject = json!({"scope":"import","project":"app","environment":"staging",
        "names":[{"name":"API_KEY","classification":"secret","value_digest":hex64('a')}],"store_generation":0});
    // a laptop files it (over ingress, in a later phase); here the admin socket stands in as the root helper
    let f = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":subject}),
        )
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    r.passkey_approve(&id, "member", "mia", "c1", "s1", T0 + 1)
        .unwrap();
    let typed: Subject = serde_json::from_value(subject_value(&subject)).unwrap();
    // no socket can spend it as a separate operation
    for class in [SocketClass::Box, SocketClass::Admin] {
        let e = r
            .at(
                class,
                Some(0),
                T0 + 2,
                json!({"op":"areq_spend","id":id,"subject":subject}),
            )
            .unwrap_err();
        assert!(
            e.contains("not spent from this socket") || e == ozbox_core::approval::NOT_FOUND,
            "{e}"
        );
    }
    // the operation itself spends it, with the subject it recomputed, and then finishes it
    let svc = r.svc();
    let spent = svc
        .spend(&r.store, &r.gates, SpendVia::Inside, &id, &typed, T0 + 3)
        .unwrap();
    assert_eq!(spent.state, State::Spending);
    assert_eq!(svc.finish_inside(&id, T0 + 4).unwrap().state, State::Spent);
    assert!(svc
        .spend(&r.store, &r.gates, SpendVia::Inside, &id, &typed, T0 + 5)
        .is_err());
}

fn subject_value(v: &Value) -> Value {
    v.clone()
}

// ---- the service derives a guard override's matches itself -----------------------------------------------

fn diff_adding(line: &str) -> String {
    format!("diff --git a/src/app.rs b/src/app.rs\n--- a/src/app.rs\n+++ b/src/app.rs\n@@ -1 +1,2 @@\n x\n+{line}\n")
}

fn file_with(r: &Rig, subject: Value, text: Option<&str>) -> Result<Value, String> {
    let mut v = json!({"op":"areq_file","subject":subject});
    if let Some(t) = text {
        v["scanned_text"] = json!(t);
    }
    r.at(SocketClass::Box, Some(BOX_UID), T0, v)
}

#[test]
fn the_filers_matches_and_text_hash_are_never_used_the_service_scans_the_text_it_is_given() {
    let r = rig(true, false);
    // a filer that sends its own list, or its own hash, is refused
    let mut with_matches = guard_subject('a');
    with_matches["matches"] =
        json!([{"path":"README.md","line":3,"rule":"stored-value","key_id":"k1"}]);
    let e = file_with(&r, with_matches, Some(clean_diff())).unwrap_err();
    assert!(e.contains("works out"), "{e}");
    let mut with_hash = guard_subject('a');
    with_hash["scanned_text_hash"] = json!(hex64('2'));
    assert!(file_with(&r, with_hash, Some(clean_diff()))
        .unwrap_err()
        .contains("works out"));
    // and one that sends no text at all
    assert!(file_with(&r, guard_subject('a'), None)
        .unwrap_err()
        .contains("scanned"));
    assert!(file_with(&r, guard_subject('a'), Some("")).is_err());

    // a diff that adds a value the box stores: the service's request carries the service's match, whatever the filer meant
    r.store
        .set(
            "workload.app.staging.API_KEY",
            "abcdef0123456789staging-secret",
        )
        .unwrap();
    let diff = diff_adding("let k = \"abcdef0123456789staging-secret\";");
    let f = file_with(&r, guard_subject('a'), Some(&diff)).unwrap();
    let id = f["request"]["id"].as_str().unwrap();
    let got = r
        .at(
            SocketClass::Supervisor,
            None,
            T0,
            json!({"op":"areq_get","id":id}),
        )
        .unwrap();
    let m = &got["request"]["subject"]["matches"];
    assert_eq!(m.as_array().unwrap().len(), 1, "{m}");
    assert_eq!(m[0]["path"], "src/app.rs");
    assert_eq!(m[0]["rule"], "stored-value");
    assert_eq!(m[0]["key_id"], "workload.app.staging.API_KEY");
    assert_eq!(
        got["request"]["subject"]["scanned_text_hash"],
        ozbox_core::approval_subject::sha256_hex(&diff)
    );
    // the same filing with a clean diff is another request: the digest is of what the service found
    let clean = file_with(&r, guard_subject('a'), Some(clean_diff())).unwrap();
    assert_ne!(
        clean["request"]["subject_digest"],
        f["request"]["subject_digest"]
    );
}

#[test]
fn a_production_looking_hit_is_derived_by_the_service_and_never_decidable_even_with_no_second_factor(
) {
    for enrolled in [true, false] {
        let r = rig(enrolled, false);
        // the box stores a live-mode key: a diff that adds it is Production-looking by the box's own rule
        r.store
            .set(
                "workload.app.staging.PAY",
                concat!("sk_", "live_abcdefghijklmnopqrstuvwx"),
            )
            .unwrap();
        let diff = diff_adding(concat!("let k = \"sk_", "live_abcdefghijklmnopqrstuvwx\";"));
        let e = file_with(&r, guard_subject('a'), Some(&diff)).unwrap_err();
        assert!(e.contains("Production-looking"), "enrolled={enrolled}: {e}");
        assert!(r.svc().book().requests.is_empty());
        // and a payment key's shape alone (not stored) is read the same way
        let shape = diff_adding(concat!("STRIPE=sk_", "live_abcdefghijklmnopqrstuvwxyz0123"));
        assert!(file_with(&r, guard_subject('b'), Some(&shape))
            .unwrap_err()
            .contains("Production-looking"));
    }
}

#[test]
fn a_spend_recomputes_the_matches_from_the_text_the_hook_sends() {
    let r = rig(true, false);
    r.store
        .set(
            "workload.app.staging.API_KEY",
            "abcdef0123456789staging-secret",
        )
        .unwrap();
    let diff = diff_adding("let k = \"abcdef0123456789staging-secret\";");
    let f = file_with(&r, guard_subject('a'), Some(&diff)).unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    r.passkey_approve(&id, "member", "alice", "cred-1", "sig-1", T0 + 1)
        .unwrap();
    // a spend with different text (a tree that now holds something else) is another digest: refused, the approval kept
    let e = r
        .at(SocketClass::Box, Some(BOX_UID), T0 + 2, json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}))
        .unwrap_err();
    assert!(e.contains("not what was approved"), "{e}");
    // the same text spends
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        T0 + 3,
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":diff}),
    )
    .unwrap();
}

#[test]
fn a_policy_change_is_not_filed_through_this_operation_yet() {
    let r = rig(true, false);
    let p = json!({"scope":"policy","policy_sha256":hex64('d'),"predecessor_sha256":hex64('e'),"sensitivity":"ordinary"});
    let e = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":p}),
        )
        .unwrap_err();
    assert!(e.contains("policy change is not filed"), "{e}");
}

/// a caller that cannot see a request cannot hold a place in its await cap, and the per-request cap is per class.
#[test]
fn a_box_user_cannot_hold_the_await_slots_of_a_request_it_cannot_see() {
    let r = rig(true, false);
    r.store
        .set(crate::secrets_approval::ENROLLED_MARKER, "1")
        .unwrap();
    // a root helper's request (a tunnel token): the box user may know the id, but sees nothing
    let f = r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_file","subject":tunnel_subject()}),
        )
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    for _ in 0..(AWAITS_PER_REQUEST + 3) {
        let e = r
            .at(
                SocketClass::Box,
                Some(BOX_UID),
                T0,
                json!({"op":"areq_await","id":id,"wait_ms":0}),
            )
            .unwrap_err();
        assert_eq!(
            e,
            ozbox_core::approval::NOT_FOUND,
            "it is told nothing, and holds nothing"
        );
    }
    let caps = r.svc().caps.lock().unwrap().per_request.len();
    assert_eq!(
        caps, 0,
        "no place is held for a request that cannot be seen"
    );
    // the root helper's own await is not starved
    assert!(r
        .at(
            SocketClass::Admin,
            Some(0),
            T0,
            json!({"op":"areq_await","id":id,"wait_ms":0})
        )
        .is_ok());
}

// ---- phase 2: the laptop over the sealed route, keys from the store, the markers, chat ---------------------------------------

use ozbox_core::approval::{Evidence as Ev, LaptopEvidence as LEv};

/// A laptop's decision, signed by the Ed25519 seed over the message the service built for this request and outcome.
fn laptop_decision(
    r: &Rig,
    id: &str,
    outcome: &str,
    key_id: &str,
    seed: &str,
    word: &str,
    now: u64,
) -> Value {
    let ch = r
        .at(
            SocketClass::Ingress,
            None,
            now,
            json!({"op":"areq_decide_challenge","id":id,"outcome":word}),
        )
        .unwrap();
    let msg = format!(
        "ozbox-approval-decide\n{}",
        ch["challenge"].as_str().unwrap()
    );
    json!({"op":"areq_decide","id":id,"outcome":outcome,"key_id":key_id,
           "evidence":{"laptop":{"key_id":key_id,"key_type":"ed25519","signature_format":"ed25519-message",
                                 "signed_message":to_hex(msg.as_bytes()),"signature":crate::approval_key::sign(seed, &msg).unwrap()}}})
}

fn enrol_software_key(r: &Rig, id: &str) -> String {
    let (seed, pk) = crate::approval_key::generate().unwrap();
    r.store.set(&format!("approval-key.{id}"), &pk).unwrap();
    seed.to_string()
}

#[test]
fn a_laptop_decides_over_the_sealed_route_with_a_key_the_service_loads_from_its_own_store_by_id() {
    let r = rig(true, true);
    let seed = enrol_software_key(&r, "lap");
    let t = crate::tokenmac::now_ms();
    let id = r.file_guard('a', BOX_UID, t);
    // a key that is not in the store decides nothing, whatever it signs
    let ghost = laptop_decision(&r, &id, "approve", "lap", &seed, "approve", t + 1);
    let mut no_key = ghost.clone();
    no_key["key_id"] = json!("nobody");
    no_key["evidence"]["laptop"]["key_id"] = json!("nobody");
    assert!(r
        .at(SocketClass::Ingress, None, t + 1, no_key)
        .unwrap_err()
        .contains("not enrolled"));
    // the key in the store, through the real dispatch (a sealed request opens as `Policy::Unsealed`)
    let d = r.call(Policy::Unsealed, None, ghost.clone());
    assert_eq!(d["ok"], true, "{d}");
    let dec = &d["result"]["request"]["decision"];
    assert_eq!(dec["surface"], "laptop");
    assert_eq!(dec["decider"], "lap");
    assert_eq!(dec["factor_label"], "laptop-key:lap (no user presence)");
    // the record names the key the STORE has (type, presence), not anything the laptop said
    let view = crate::approval_keystore::load_key_view(&*r.store, "lap")
        .unwrap()
        .unwrap();
    assert_eq!(view.key_type, ozbox_core::approval::KeyType::Ed25519);
    assert!(!view.presence_proved);
    // and the approval is spent by the hook that filed it, once
    let s = r.at(
        SocketClass::Box,
        Some(BOX_UID),
        t + 2,
        json!({"op":"areq_spend","id":id,"subject":guard_subject('a'),"scanned_text":clean_diff()}),
    );
    assert!(s.is_ok(), "{s:?}");
}

#[test]
fn the_box_users_sockets_cannot_reach_the_laptops_decision() {
    let r = rig(true, false);
    let seed = enrol_software_key(&r, "lap");
    let id = r.file_guard('a', BOX_UID, T0);
    let v = laptop_decision(&r, &id, "approve", "lap", &seed, "approve", T0 + 1);
    for p in [
        Policy::Box,
        Policy::BoxLocked,
        Policy::Import,
        Policy::Broker,
    ] {
        let x = r.call(p, Some(BOX_UID), v.clone());
        assert_eq!(x["ok"], false, "{p:?}");
    }
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
}

#[test]
fn a_laptop_deny_and_revoke_need_the_keys_signature_and_a_revoke_challenge_can_be_issued() {
    let r = rig(true, true);
    let seed = enrol_software_key(&r, "lap");
    let id = r.file_guard('a', BOX_UID, T0);
    // naming a key id is not enough
    let bare = json!({"op":"areq_decide","id":id,"outcome":"deny","key_id":"lap"});
    assert!(r
        .at(SocketClass::Ingress, None, T0 + 1, bare)
        .unwrap_err()
        .contains("carries its signature"));
    // a deny is signed over the deny word; the approve signature does not deny
    let wrong = laptop_decision(&r, &id, "deny", "lap", &seed, "approve", T0 + 1);
    assert!(r
        .at(SocketClass::Ingress, None, T0 + 1, wrong)
        .unwrap_err()
        .contains("another request"));
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
    // a revoke challenge is refused while the request is pending
    let e = r.at(
        SocketClass::Ingress,
        None,
        T0 + 1,
        json!({"op":"areq_decide_challenge","id":id,"outcome":"revoke"}),
    );
    assert!(e.unwrap_err().contains("nothing approved"));
    // approve, then revoke with its own challenge; an approve challenge is not offered for an approved request
    let ok = laptop_decision(&r, &id, "approve", "lap", &seed, "approve", T0 + 2);
    r.at(SocketClass::Ingress, None, T0 + 2, ok).unwrap();
    let e = r.at(
        SocketClass::Ingress,
        None,
        T0 + 3,
        json!({"op":"areq_decide_challenge","id":id,"outcome":"approve"}),
    );
    assert!(e.is_err());
    let rev = laptop_decision(&r, &id, "revoke", "lap", &seed, "revoke", T0 + 3);
    let d = r.at(SocketClass::Ingress, None, T0 + 3, rev).unwrap();
    assert_eq!(d["request"]["state"], "denied");
    assert_eq!(d["request"]["decision"]["outcome"], "revoke");
}

#[test]
fn a_chat_app_can_decide_nothing_and_no_chat_source_names_a_request_operation_that_changes_state() {
    let r = rig(true, true);
    let id = r.file_guard('a', BOX_UID, T0);
    // the supervisor socket, which is all a chat bridge could reach, refuses a decision that says it came from a chat
    for (outcome, factor) in [
        ("deny", "chat-deny"),
        ("approve", "chat-deny"),
        ("deny", "passkey"),
    ] {
        let e = r.at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_decide","id":id,"outcome":outcome,"person":"alice","role":"owner","surface":"telegram","factor":factor}),
        );
        assert!(
            e.unwrap_err().contains("only notifies"),
            "{outcome} {factor}"
        );
    }
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
    // and the sources a chat or an alert could be written in never name an operation that changes a request
    let mut checked = 0;
    for (name, src) in [
        ("chat/command.rs", include_str!("../chat/command.rs")),
        ("chat/gateway.rs", include_str!("../chat/gateway.rs")),
        ("chat/links.rs", include_str!("../chat/links.rs")),
        ("chat/slack.rs", include_str!("../chat/slack.rs")),
        ("chat/text.rs", include_str!("../chat/text.rs")),
        ("chat/whatsapp.rs", include_str!("../chat/whatsapp.rs")),
        ("chat/ws.rs", include_str!("../chat/ws.rs")),
        ("chat/mod.rs", include_str!("../chat/mod.rs")),
        ("telegram.rs", include_str!("../telegram.rs")),
        ("channels/chat.rs", include_str!("../channels/chat.rs")),
        ("channels/push.rs", include_str!("../channels/push.rs")),
        (
            "serve/chat_routes.rs",
            include_str!("../serve/chat_routes.rs"),
        ),
        ("notify.rs", include_str!("../notify.rs")),
    ] {
        for op in [
            "areq_decide",
            "areq_cancel",
            "areq_file",
            "areq_spend",
            "areq_finish",
            "areq_new_epoch",
            "areq_decider_revoked",
        ] {
            assert!(!src.contains(op), "{name} names {op}");
        }
        checked += 1;
    }
    assert_eq!(checked, 13);
    // the notification builder offers a link and no button
    let route = include_str!("../serve/approval_requests.rs");
    assert!(route.contains("approvals?request="));
    for banned in ["inline_keyboard", "callback_data", "reply_markup"] {
        assert!(
            !route.contains(banned) && !include_str!("../notify.rs").contains(banned),
            "{banned}"
        );
    }
}

#[test]
fn the_ever_had_markers_live_beside_the_epoch_and_a_new_store_does_not_reset_them() {
    let r = rig(true, false);
    assert!(!r.svc().ctx(&r.store).unwrap().0.ever_key);
    r.svc().note_key(false).unwrap();
    r.svc().note_key(true).unwrap();
    let (c, _) = r.svc().ctx(&r.store).unwrap();
    assert!(c.ever_key && c.ever_presence_key);
    // a store made again (a recovery, an adopt, a replace): a new file, a new key, nothing in it, in the same state folder
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let fresh =
        Arc::new(EncryptedSecrets::new(r.dir.path().join("fresh.json"), "box-a", p).unwrap());
    let svc = RequestService::open(
        &fresh,
        &r.dir.path().join("req2"),
        &r.sdir(),
        "box-1",
        T0 + 5,
    )
    .unwrap();
    let (c, _) = svc.ctx(&fresh).unwrap();
    assert!(
        c.ever_key && c.ever_presence_key,
        "the markers came with the state folder, not the store"
    );
    // only root clears them
    for class in [
        SocketClass::Box,
        SocketClass::Supervisor,
        SocketClass::Ingress,
    ] {
        assert!(svc
            .handle(
                &fresh,
                &r.gates,
                class,
                Some(BOX_UID),
                &json!({"op":"areq_clear_markers"}),
                T0 + 6
            )
            .is_err());
    }
    svc.handle(
        &fresh,
        &r.gates,
        SocketClass::Admin,
        None,
        &json!({"op":"areq_clear_markers"}),
        T0 + 6,
    )
    .unwrap();
    assert!(!svc.ctx(&fresh).unwrap().0.ever_key);
    // and the file survives a restart
    let again = RequestService::open(
        &fresh,
        &r.dir.path().join("req2"),
        &r.sdir(),
        "box-1",
        T0 + 7,
    )
    .unwrap();
    assert!(!again.ctx(&fresh).unwrap().0.ever_key);
}

#[test]
fn a_dashboard_decision_names_the_relying_party_and_the_service_refuses_one_it_was_not_given() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    let c = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_decide_challenge","id":id}),
        )
        .unwrap();
    let ch = unhex32(c["challenge"].as_str().unwrap());
    let wire = |rp: Value| {
        json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"member","surface":"dashboard","factor":"passkey",
               "rp":rp,"evidence":{"passkey":{"credential_id":"c1","authenticator_data":to_hex(&auth_data(0x01, 0)),
               "client_data":to_hex(&client_data(&ch)),"signature":"s1"}}})
    };
    // no relying party, another one, another origin: refused
    let mut none = wire(json!(null));
    none.as_object_mut().unwrap().remove("rp");
    assert!(r
        .at(SocketClass::Supervisor, None, T0 + 2, none)
        .unwrap_err()
        .contains("relying party is not known"));
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 2,
            wire(json!({"rp_id":"evil.test","origin":"https://x.test"})),
        )
        .unwrap_err();
    assert!(e.contains("another relying party"), "{e}");
    let e = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 2,
            wire(json!({"rp_id":"x.test","origin":"https://evil.test"})),
        )
        .unwrap_err();
    assert!(e.contains("another origin"), "{e}");
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Pending);
    r.at(
        SocketClass::Supervisor,
        None,
        T0 + 3,
        wire(json!({"rp_id":"x.test","origin":"https://x.test"})),
    )
    .unwrap();
}

#[test]
fn a_dashboard_session_may_deny_and_revoke_but_never_approve() {
    let r = rig(true, true);
    let id = r.file_guard('a', BOX_UID, T0);
    let e = r.at(
        SocketClass::Supervisor,
        None,
        T0 + 1,
        json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"owner","surface":"dashboard","factor":"session"}),
    );
    assert!(e.is_err());
    // a viewer's session decides nothing
    let e = r.at(
        SocketClass::Supervisor,
        None,
        T0 + 1,
        json!({"op":"areq_decide","id":id,"outcome":"deny","person":"vic","role":"viewer","surface":"dashboard","factor":"session"}),
    );
    assert!(e.unwrap_err().contains("viewer"));
    let d = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 2,
            json!({"op":"areq_decide","id":id,"outcome":"deny","person":"alice","role":"member","surface":"dashboard","factor":"session"}),
        )
        .unwrap();
    assert_eq!(d["request"]["state"], "denied");
    assert_eq!(
        d["request"]["decision"]["factor_label"],
        "dashboard session (no passkey)"
    );
}

#[test]
fn the_supervisor_list_says_what_each_role_may_do_from_the_same_rule_decide_applies() {
    let r = rig(true, false);
    let id = r.file_guard('a', BOX_UID, T0);
    let l = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_list","role":"viewer"}),
        )
        .unwrap();
    let card = &l["requests"][0];
    assert_eq!(card["id"], id);
    assert_eq!(card["can"]["approve"]["allowed"], false);
    assert!(card["can"]["approve"]["reason"]
        .as_str()
        .unwrap()
        .contains("viewer"));
    let l = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_list","role":"member"}),
        )
        .unwrap();
    assert_eq!(l["requests"][0]["can"]["approve"]["allowed"], true);
    assert_eq!(l["requests"][0]["can"]["deny"]["allowed"], true);
    // a dashboard with no sign-in decides nothing
    let l = r
        .at(
            SocketClass::Supervisor,
            None,
            T0 + 1,
            json!({"op":"areq_list"}),
        )
        .unwrap();
    assert!(l["requests"][0]["can"]["approve"]["reason"]
        .as_str()
        .unwrap()
        .contains("no sign-in"));
    // an import by a member needs the owner when it replaces a value: the card says so before the member tries
    let _ = (Ev::default(), None::<LEv>);
}

// ---- phase 2: an import spent by request -------------------------------------------------------------------------

const SALT: &str = "00112233445566778899aabbccddeeff";

fn import_subject(env: &str, rows: &[(&str, &str)], generation: u64) -> Value {
    let names: Vec<Value> = rows
        .iter()
        .map(|(n, v)| json!({"name": n, "classification": "secret", "value_digest": ozbox_core::approval_subject::import_value_digest(SALT, v)}))
        .collect();
    json!({"scope":"import","project":"app","environment":env,"names":names,"store_generation":generation})
}

fn import_op(id: &str, env: &str, rows: &[(&str, &str)]) -> Value {
    let lines: Vec<Value> = rows
        .iter()
        .map(|(n, v)| json!({"name": n, "value": v}))
        .collect();
    json!({"op":"import","project":"app","env":env,"request_id":id,"salt":SALT,"lines":lines})
}

/// File an import as the laptop would (the admin socket stands in for the root helper) and approve it as root.
fn approved_import(r: &Rig, env: &str, rows: &[(&str, &str)], now: u64) -> String {
    let f = r
        .at(
            SocketClass::Admin,
            Some(0),
            now,
            json!({"op":"areq_file","subject":import_subject(env, rows, 0)}),
        )
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    r.at(
        SocketClass::Admin,
        Some(0),
        now + 1,
        json!({"op":"areq_decide","id":id,"outcome":"approve"}),
    )
    .unwrap();
    id
}

#[test]
fn an_import_by_request_is_applied_once_for_exactly_the_rows_that_were_approved() {
    let r = rig(true, true);
    let t = crate::tokenmac::now_ms();
    let id = approved_import(&r, "staging", &[("API_URL", "https://example.test")], t);
    // a row changed after the approval is another digest: refused, and the approval is kept for what it was for
    let bad = r.call(
        Policy::Unsealed,
        None,
        import_op(&id, "staging", &[("API_URL", "https://evil.test")]),
    );
    assert_eq!(bad["ok"], false, "{bad}");
    assert!(
        bad["error"]
            .as_str()
            .unwrap()
            .contains("not what was approved"),
        "{bad}"
    );
    // an extra row, and another environment, are other digests too
    assert_eq!(
        r.call(
            Policy::Unsealed,
            None,
            import_op(
                &id,
                "staging",
                &[("API_URL", "https://example.test"), ("EXTRA", "x")]
            )
        )["ok"],
        false
    );
    assert_eq!(
        r.call(
            Policy::Unsealed,
            None,
            import_op(&id, "dev", &[("API_URL", "https://example.test")])
        )["ok"],
        false
    );
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Approved);
    // the rows that were approved are applied, once
    let ok = r.call(
        Policy::Unsealed,
        None,
        import_op(&id, "staging", &[("API_URL", "https://example.test")]),
    );
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(r.svc().book().get(&id).unwrap().state, State::Spent);
    assert!(r.store.exists("workload.app.staging.API_URL").unwrap());
    let again = r.call(
        Policy::Unsealed,
        None,
        import_op(&id, "staging", &[("API_URL", "https://example.test")]),
    );
    assert_eq!(again["ok"], false);
    // the salt is part of the binding: the same rows under another salt are another digest
    let id2 = approved_import(
        &r,
        "staging",
        &[("API_URL", "https://example.test")],
        t + 10,
    );
    let mut other = import_op(&id2, "staging", &[("API_URL", "https://example.test")]);
    other["salt"] = json!("ffeeddccbbaa99887766554433221100");
    assert_eq!(r.call(Policy::Unsealed, None, other)["ok"], false);
}

#[test]
fn an_import_whose_values_say_production_is_refused_where_the_service_sees_them_and_keeps_the_approval(
) {
    let r = rig(true, true);
    let t = crate::tokenmac::now_ms();
    // filed and approved as a staging import; one value is a live-mode key (the laptop's `production` flag is left off)
    let rows = [(
        "STRIPE_KEY",
        concat!("sk_", "live_0123456789abcdefghijklmn"),
    )];
    let id = approved_import(&r, "staging", &rows, t);
    let x = r.call(Policy::Unsealed, None, import_op(&id, "staging", &rows));
    assert_eq!(x["ok"], false);
    assert!(x["error"].as_str().unwrap().contains("Production"), "{x}");
    assert_eq!(
        r.svc().book().get(&id).unwrap().state,
        State::Approved,
        "refused before spending, so not burnt"
    );
    assert!(!r.store.exists("workload.app.staging.STRIPE_KEY").unwrap());
}

#[test]
fn an_import_is_bound_to_the_projects_generation_so_an_old_approval_cannot_be_replayed() {
    let r = rig(true, true);
    let t = crate::tokenmac::now_ms();
    // the service sets the generation at filing, never the filer
    let f = r
        .at(
            SocketClass::Admin,
            Some(0),
            t,
            json!({"op":"areq_file","subject":import_subject("staging", &[("A_KEY", "one")], 9)}),
        )
        .unwrap();
    assert_eq!(f["request"]["subject"]["store_generation"], 0);
    let id = f["request"]["id"].as_str().unwrap().to_string();
    r.at(
        SocketClass::Admin,
        Some(0),
        t + 1,
        json!({"op":"areq_decide","id":id,"outcome":"approve"}),
    )
    .unwrap();
    // the project's values moved on before this approval was spent, by a writer that is not an import by request (a code
    // import, a `set`, anything): the generation is derived from the rows, so no writer has to remember to move it (M4)
    let before = r.svc().import_generation(&r.store, "app", "staging");
    r.store
        .set("workload.app.staging.OTHER_KEY", "rotated")
        .unwrap();
    assert_ne!(
        r.svc().import_generation(&r.store, "app", "staging"),
        before
    );
    let late = r.call(
        Policy::Unsealed,
        None,
        import_op(&id, "staging", &[("A_KEY", "one")]),
    );
    assert_eq!(late["ok"], false, "{late}");
    assert!(
        late["error"]
            .as_str()
            .unwrap()
            .contains("not what was approved"),
        "{late}"
    );
    assert_eq!(
        r.svc().book().get(&id).unwrap().state,
        State::Approved,
        "kept for what it was for"
    );
    // a request filed now binds the new generation, and applying it moves the generation on
    let id2 = approved_import(&r, "staging", &[("A_KEY", "one")], t + 5);
    assert_eq!(r.svc().book().get(&id2).unwrap().state, State::Approved);
    // (id was superseded by id2's approval: one live approval per slot)
    assert_eq!(
        r.call(
            Policy::Unsealed,
            None,
            import_op(&id2, "staging", &[("A_KEY", "one")])
        )["ok"],
        true
    );
    assert_ne!(r.svc().import_generation(&r.store, "app", "staging"), 0);
}

#[test]
fn a_box_that_already_had_a_key_keeps_knowing_it_across_a_new_store() {
    // an upgraded box: its store holds a pinned key and the marker, and the state folder is new (M2)
    let t = tempfile::tempdir().unwrap();
    let mk = |name: &str| {
        let p: Arc<dyn crate::secrets_enc::KeyProvider> =
            Arc::new(crate::secrets_enc::LocalKekProvider::random("local").unwrap());
        Arc::new(EncryptedSecrets::new(t.path().join(name), "box-a", p).unwrap())
    };
    let store = mk("a.json");
    store.set("approval-key.laptop", &"ab".repeat(32)).unwrap();
    let (journal, state) = (t.path().join("j"), t.path().join("s"));
    let now = crate::tokenmac::now_ms();
    let svc = RequestService::open(&store, &journal, &state, "box-a", now).unwrap();
    assert!(svc.ctx(&store).unwrap().0.ever_key);
    // a recovery: a new store with no key and no marker; the state folder, opened again, still says it had one
    let fresh = mk("b.json");
    let svc2 = RequestService::open(&fresh, &journal, &state, "box-a", now + 1).unwrap();
    assert!(
        svc2.ctx(&fresh).unwrap().0.ever_key,
        "the box has had a key"
    );
}

#[test]
fn a_state_folder_opened_beside_another_store_voids_the_journal_but_keeps_what_was_spent() {
    // a recovery, an adopt or a replace puts this folder beside a store with another id
    let t = tempfile::tempdir().unwrap();
    let p: Arc<dyn crate::secrets_enc::KeyProvider> =
        Arc::new(crate::secrets_enc::LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(t.path().join("a.json"), "box-a", p).unwrap());
    let (journal, state) = (t.path().join("j"), t.path().join("s"));
    let now = crate::tokenmac::now_ms();
    let svc = RequestService::open(&store, &journal, &state, "box-a", now).unwrap();
    let gates = Gates::default();
    let f = svc
        .handle(
            &store,
            &gates,
            SocketClass::Admin,
            Some(0),
            &json!({"op":"areq_file","subject":import_subject("staging", &[("A_KEY", "one")], 0)}),
            now,
        )
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    // (a box with no approver yet approves at filing, as `bootstrap`)
    assert_eq!(svc.book().get(&id).unwrap().state, State::Approved);
    // the same folder, beside a store that holds another store id (and the same journal key, as a copied store would)
    store.set(STORE_ID, &"cd".repeat(16)).unwrap();
    let again = RequestService::open(&store, &journal, &state, "box-a", now + 2).unwrap();
    assert_ne!(again.book().epoch, svc.book().epoch, "a new epoch");
    assert_ne!(
        again.book().get(&id).map(|r| r.state),
        Some(State::Approved),
        "the approval is void"
    );
}

// ---- phase 2 re-check NM2: the refused-spend budget cannot be grown with ids the caller makes up -------------------------

fn spend_call(r: &Rig, id: &str, now: u64) -> Result<Value, String> {
    r.at(
        SocketClass::Box,
        Some(BOX_UID),
        now,
        // not a guard override, so the scan limit does not answer before the id is looked up
        json!({"op":"areq_spend","id":id,"subject":tunnel_subject()}),
    )
}

#[test]
fn a_flood_of_made_up_request_ids_leaves_the_journal_and_its_list_bounded() {
    let r = rig(true, false);
    let jpath = r.jdir().join(JOURNAL_FILE);
    // ids that are not the service's shape: refused, never counted, and the journal is not rewritten
    let before = std::fs::read(&jpath).unwrap();
    for bad in ["x", "", &"y".repeat(900_000), "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
        let e = spend_call(&r, bad, T0 + 1).unwrap_err();
        assert_eq!(e, ozbox_core::approval::NOT_FOUND);
    }
    assert_eq!(std::fs::read(&jpath).unwrap(), before, "journal rewritten");
    assert!(r.svc().book().refused_spends.is_empty());
    // well-formed but fresh ids, many more than the per-uid ceiling
    for i in 0..300u64 {
        let id = random_b32(16).unwrap();
        let e = spend_call(&r, &id, T0 + 2 + i).unwrap_err();
        assert!(
            e == ozbox_core::approval::NOT_FOUND || e.contains("too many refused spends"),
            "{e}"
        );
    }
    let n = r.svc().book().refused_spends.len();
    assert!(
        n <= ozbox_core::approval::REFUSED_SPENDS_PER_UID_PER_HOUR,
        "{n}"
    );
    // from here on a refusal changes nothing: the journal is byte for byte the same, and the size stays flat
    let full = std::fs::read(&jpath).unwrap();
    for i in 0..1_000u64 {
        let id = random_b32(16).unwrap();
        let e = spend_call(&r, &id, T0 + 400 + i).unwrap_err();
        assert_eq!(e, ozbox_core::approval::NOT_FOUND);
    }
    assert_eq!(std::fs::read(&jpath).unwrap(), full, "journal rewritten");
    assert_eq!(r.svc().book().refused_spends.len(), n);
}

#[test]
fn the_audit_line_for_a_refused_spend_carries_a_cut_id() {
    assert_eq!(log_id(&"z".repeat(5_000)).chars().count(), 26);
}

// ---- the guard hook, end to end (ADR 0041 phase 3) -----------------------------------------------------------------------

mod guard_hook {
    use super::*;
    use crate::guard::{Binding, Scanner};
    use crate::guard_hold::{pre_commit, Flow};
    use std::sync::atomic::AtomicBool;

    const STORED: &str = "SENTINEL-hook-0123456789abcdef";

    struct Svc<'a>(&'a Rig);
    impl Scanner for Svc<'_> {
        fn scan(&self, text: &str) -> Result<Vec<String>, String> {
            crate::secrets_service::scan_text(&self.0.store, None, text).map_err(|e| e.0)
        }
        fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
            Err("no code here".into())
        }
    }

    fn git(dir: &std::path::Path, a: &[&str]) {
        crate::guard::testgit::must(crate::guard::testgit::git().arg("-C").arg(dir).args(a));
    }

    fn repo_with_key() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for a in [
            &["init", "-q"][..],
            &["config", "user.email", "t@example.com"],
            &["config", "user.name", "t"],
            &["config", "commit.gpgsign", "false"],
        ] {
            git(d.path(), a);
        }
        std::fs::write(d.path().join("a.txt"), "hello\n").unwrap();
        git(d.path(), &["add", "-A"]);
        git(d.path(), &["commit", "-q", "-m", "m", "--no-verify"]);
        std::fs::write(
            d.path().join("k.ts"),
            format!("export const k = \"{STORED}\";\n"),
        )
        .unwrap();
        git(d.path(), &["add", "-A"]);
        d
    }

    /// The hook's flow wired to the real dispatch. `on_file` runs right after a request is filed (a person deciding, or not);
    /// `on_await` runs before the first wait (an edit while waiting).
    fn run(
        r: &Rig,
        repo: &std::path::Path,
        decide: bool,
        mut during_wait: impl FnMut(),
    ) -> (Result<Option<String>, String>, Vec<String>) {
        let mut first_await = true;
        let mut call = |v: &Value| -> Result<Value, String> {
            let op = v["op"].as_str().unwrap_or("").to_string();
            if op == "areq_await" && first_await {
                first_await = false;
                during_wait();
            }
            let resp = r.call(Policy::Box, Some(BOX_UID), v.clone());
            if resp["ok"] != true {
                return Err(resp["error"].as_str().unwrap_or("refused").to_string());
            }
            let res = resp["result"].clone();
            if op == "areq_file" && decide {
                let id = res["request"]["id"].as_str().unwrap().to_string();
                let ch = r.call(
                    Policy::Supervisor,
                    None,
                    json!({"op":"areq_decide_challenge","id":id}),
                );
                let d = r.call(
                    Policy::Supervisor,
                    None,
                    json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"member","surface":"dashboard","factor":"passkey",
                           "rp":{"rp_id":"x.test","origin":"https://x.test"},
                           "evidence":{"passkey":{"credential_id":"c1","authenticator_data":to_hex(&auth_data(0x01, 0)),
                                                  "client_data":to_hex(&client_data(&unhex32(ch["result"]["challenge"].as_str().unwrap()))),
                                                  "signature":"s1"}}}),
                );
                assert_eq!(d["ok"], true, "{d}");
            }
            Ok(res)
        };
        let stop = AtomicBool::new(false);
        let mut said = Vec::<String>::new();
        let mut say = |l: &str| said.push(l.to_string());
        let mut flow = Flow {
            call: &mut call,
            elapsed_ms: &|| 0,
            say: &mut say,
            stop: &stop,
            pause: &|_| {},
        };
        let out = pre_commit(repo, Some(&Svc(r)), "", Some(&mut flow));
        (out, said)
    }

    #[test]
    fn a_held_commit_files_a_request_a_person_decides_and_the_hook_spends_it_for_that_tree_once() {
        let r = rig(true, true);
        r.store.set("workload.app.staging.API_KEY", STORED).unwrap();
        let d = repo_with_key();
        let (out, said) = run(&r, d.path(), true, || {});
        assert_eq!(out, Ok(None), "an approved, unchanged tree is let through");
        let joined = said.join("\n");
        assert!(
            joined.contains("k.ts:1") && joined.contains("Waiting for approval"),
            "{joined}"
        );
        assert!(!joined.contains(STORED) && !joined.contains("API_KEY"));
        let chain = r.chain_text();
        assert!(chain.contains("request.spent") && !chain.contains(STORED));
        // the tree it let through is the one post-commit will leave standing, and only that one
        let git_dir = d.path().join(".git/ozbox-guard-approved");
        assert!(git_dir.exists());
    }

    #[test]
    fn a_tree_edited_while_waiting_is_refused_and_the_approval_is_not_spent() {
        let r = rig(true, true);
        r.store.set("workload.app.staging.API_KEY", STORED).unwrap();
        let d = repo_with_key();
        let p = d.path().to_path_buf();
        let (out, _) = run(&r, d.path(), true, || {
            std::fs::write(
                p.join("other.ts"),
                format!("export const o = \"{STORED}\";\n"),
            )
            .unwrap();
            git(&p, &["add", "-A"]);
        });
        let Some(msg) = out.unwrap() else {
            panic!("the commit should have been stopped")
        };
        assert!(msg.contains("nothing was let through"), "{msg}");
        assert!(!r.chain_text().contains("request.spent"));
        assert!(!d.path().join(".git/ozbox-guard-approved").exists());
    }

    #[test]
    fn a_request_nobody_decides_is_not_a_way_through() {
        let r = rig(true, true);
        r.store.set("workload.app.staging.API_KEY", STORED).unwrap();
        let d = repo_with_key();
        // the person stops waiting (Ctrl-C): the commit is stopped and the request stands
        let stop = AtomicBool::new(true);
        let mut call = |v: &Value| -> Result<Value, String> {
            let resp = r.call(Policy::Box, Some(BOX_UID), v.clone());
            if resp["ok"] != true {
                return Err(resp["error"].as_str().unwrap_or("refused").to_string());
            }
            Ok(resp["result"].clone())
        };
        let mut say = |_: &str| {};
        let mut flow = Flow {
            call: &mut call,
            elapsed_ms: &|| 0,
            say: &mut say,
            stop: &stop,
            pause: &|_| {},
        };
        let out = pre_commit(d.path(), Some(&Svc(&r)), "", Some(&mut flow))
            .unwrap()
            .unwrap();
        assert!(
            out.contains("stopped waiting") && out.contains("nothing was let through"),
            "{out}"
        );
        // and with no flow at all (a laptop) the hold says how to ask for a code for this change
        let none = pre_commit(d.path(), Some(&Svc(&r)), "", None)
            .unwrap()
            .unwrap();
        assert!(
            none.contains("guard-override") && none.contains("--project") && none.contains("--env"),
            "{none}"
        );
    }
}
