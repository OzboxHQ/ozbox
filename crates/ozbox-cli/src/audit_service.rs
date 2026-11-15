//! The audit service: the part of the box's secrets service that alone writes the audit chain (ADR 0028).
//!
//! The chain used to be a file the box user's own process wrote, with the seal key in a file beside it, so anything running
//! as the box user (every agent) could rewrite the whole chain and seal it again. Here the chain file belongs to the secrets
//! service's user, the seal key is a secret in the store (`audit-seal-key.<chain>`, never a file, never returned over any
//! socket), and writers hand it **events** and get back the sealed entries. The box user can read the file (it is world
//! readable: ids and action words only) and ask for it to be checked; it cannot change a line or make a seal.
//!
//! What a socket may do:
//!
//! | op | box, box-locked | supervisor | admin |
//! |---|---|---|---|
//! | `audit_append`, `audit_last_src` | yes, but not the service's own words (`secrets.`, `audit.`) | yes | yes |
//! | `audit_verify` | yes | yes | yes |
//! | `audit_seal` | no | yes | yes |
//!
//! A process of the box user can therefore still **add** a well-formed event of its own (it shares a user with the tool
//! host and the command line, which write through the same socket), but it cannot alter or remove one that is there, cannot
//! forge a seal, and cannot write an event in the service's own vocabulary.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ozbox_core::audit::{hex, AuditLog, LegacyChain, NewEvent};
use serde_json::{json, Value};

use crate::secrets::SecretStore;
use crate::secrets_service::Policy;

pub const KEY_PREFIX: &str = "audit-seal-key.";
pub const MIGRATED_PREFIX: &str = "audit-migrated.";
pub const DEFAULT_CHAIN: &str = "tasks";
const MAX_EVENTS: usize = 200;
/// The chains a client may name. Each has a seal key in the store, so the set is fixed: a client that could name any chain
/// could add a secret to the store per name, without end. The service makes the `-legacy` companion itself.
pub const CHAINS: &[&str] = &[DEFAULT_CHAIN];

/// Who an event from a socket the box user can reach is recorded as: the user the kernel says connected, never the name the
/// client sent. Only the supervisor and root may name a person.
pub fn box_actor(peer_uid: Option<u32>) -> String {
    match peer_uid {
        Some(u) => format!("uid:{u}"),
        None => "box-user".into(),
    }
}

/// Words only the service writes about itself: a client on the box socket may not send them.
pub fn reserved(action: &str) -> bool {
    action.starts_with("secrets.") || action.starts_with("audit.")
}

/// A chain the service keeps: one of [`CHAINS`], or the companion it makes itself (`<chain>-legacy`).
fn known_chain(c: &str) -> bool {
    CHAINS
        .iter()
        .any(|k| c == *k || c.strip_prefix(k).is_some_and(|r| r == "-legacy"))
}

pub fn chain_ok(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 32
        && !c.starts_with('-')
        && c.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Whether a secret's name is one of the audit service's own (the box socket may not write, delete or list these).
pub fn is_audit_secret(name: &str) -> bool {
    name.starts_with(KEY_PREFIX) || name.starts_with(MIGRATED_PREFIX)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Where the chains live and the seal keys already opened (in memory only, so an append does not open the store each time).
pub struct AuditCfg {
    pub dir: PathBuf,
    pub anchor_dir: PathBuf,
    keys: Mutex<BTreeMap<String, Arc<Vec<u8>>>>,
}

impl AuditCfg {
    pub fn new(dir: impl Into<PathBuf>, anchor_dir: impl Into<PathBuf>) -> Self {
        AuditCfg {
            dir: dir.into(),
            anchor_dir: anchor_dir.into(),
            keys: Mutex::new(BTreeMap::new()),
        }
    }

    fn chain_file(&self, chain: &str) -> PathBuf {
        self.dir.join(format!("{chain}.audit.jsonl"))
    }

    fn anchor_file(&self, chain: &str) -> PathBuf {
        self.anchor_dir.join(format!("{chain}.audit.anchor"))
    }

    /// The seal key of a chain: read from the store, made there on first use (only for a chain the service knows).
    fn key(&self, store: &dyn SecretStore, chain: &str) -> Result<Arc<Vec<u8>>, String> {
        let mut cache = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = cache.get(chain) {
            return Ok(k.clone());
        }
        let name = format!("{KEY_PREFIX}{chain}");
        let bytes = match store.get(&name).map_err(|e| e.0)? {
            Some(h) => unhex(&h).filter(|b| b.len() >= 32).ok_or_else(|| {
                "the audit seal key in the store is damaged, so nothing can be recorded".to_string()
            })?,
            None if !known_chain(chain) => {
                return Err("there is no audit chain of that name".into())
            }
            None => {
                let mut raw = [0u8; 32];
                getrandom::getrandom(&mut raw)
                    .map_err(|_| "no random numbers are available".to_string())?;
                store.set(&name, &hex(&raw)).map_err(|e| e.0)?;
                raw.to_vec()
            }
        };
        let k = Arc::new(bytes);
        cache.insert(chain.to_string(), k.clone());
        Ok(k)
    }

    fn log_named(&self, store: &dyn SecretStore, chain: &str) -> Result<AuditLog, String> {
        if !chain_ok(chain) {
            return Err("that audit chain name is not valid".into());
        }
        let key = self.key(store, chain)?;
        Ok(
            AuditLog::at(self.chain_file(chain), self.anchor_file(chain))
                .with_key_bytes(key.as_ref().clone())
                .world_readable(),
        )
    }

    /// One event the service writes about itself, into the box's main chain. Names and counts only.
    pub fn record(&self, store: &dyn SecretStore, action: &str, subject: &str, detail: &str) {
        let _ = self.try_record(store, action, subject, detail);
    }

    /// [`AuditCfg::record`], saying whether the line reached the chain. The approval requests' decided and spent lines
    /// fail closed on this (ADR 0041 §8): no chain line, no effect.
    pub fn try_record(
        &self,
        store: &dyn SecretStore,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> Result<(), String> {
        let log = self.log_named(store, DEFAULT_CHAIN)?;
        log.append(NewEvent {
            ts_ms: crate::tokenmac::now_ms(),
            actor: "secrets-service".into(),
            action: action.to_string(),
            subject: (!subject.is_empty()).then(|| subject.to_string()),
            detail: detail.to_string(),
            src: None,
        })
        .map(|_| ())
        .map_err(|_| "the audit chain could not be written".to_string())
    }

    /// Answer one audit request. `policy` is the socket it arrived on, `peer_uid` the user the kernel says sent it.
    pub fn respond(
        &self,
        store: &dyn SecretStore,
        policy: Policy,
        peer_uid: Option<u32>,
        req: &Value,
    ) -> Result<Value, String> {
        let op = req["op"].as_str().unwrap_or("");
        let chain = req["chain"].as_str().unwrap_or(DEFAULT_CHAIN);
        // a client names one of the chains the service keeps; their companions are the service's own
        if !chain_ok(chain) || !CHAINS.contains(&chain) {
            return Err("that audit chain name is not valid".into());
        }
        let trusted = matches!(policy, Policy::Supervisor | Policy::Admin);
        if !trusted && !matches!(policy, Policy::Box | Policy::BoxLocked) {
            return Err("that is not allowed on this socket".into());
        }
        // The supervisor says where its chain was before this service took it over; take it in before anything is written.
        if policy == Policy::Supervisor {
            if let Some(p) = req["legacy"].as_str() {
                self.migrate(store, chain, Path::new(p))?;
            }
        }
        let log = self.log_named(store, chain)?;
        match op {
            "audit_append" => {
                let mut events: Vec<NewEvent> = serde_json::from_value(req["events"].clone())
                    .map_err(|_| "that request is not valid".to_string())?;
                if events.len() > MAX_EVENTS {
                    return Err("that is too many events at once".into());
                }
                // a box-user client is recorded as itself: it cannot write an event in a person's name
                if !trusted {
                    let who = box_actor(peer_uid);
                    for e in &mut events {
                        if e.actor != who {
                            // what the client said is kept as what it is: a claim, in the detail
                            let claim: String = e
                                .actor
                                .chars()
                                .filter(|c| c.is_ascii_graphic())
                                .take(64)
                                .collect();
                            if !claim.is_empty() {
                                e.detail = if e.detail.is_empty() {
                                    format!("claimed-actor={claim}")
                                } else {
                                    format!("{} claimed-actor={claim}", e.detail)
                                };
                            }
                            e.actor = who.clone();
                        }
                    }
                }
                if !trusted && events.iter().any(|e| reserved(&e.action)) {
                    return Err(
                        "those words are the audit service's own: a client may not write them"
                            .into(),
                    );
                }
                let entries = log.append_many(events).map_err(|e| e.to_string())?;
                Ok(json!({"entries": entries}))
            }
            "audit_last_src" => {
                let src = log.last_src().map_err(|e| e.to_string())?;
                Ok(json!({"src": src}))
            }
            "audit_seal" if trusted => {
                let c = log
                    .seal_now(crate::tokenmac::now_ms())
                    .map_err(|e| e.to_string())?;
                Ok(json!({"checkpoint": c}))
            }
            "audit_verify" => {
                let mut r = log.verify().map_err(|e| e.to_string())?;
                // a chain kept apart at an upgrade is checked on its own, and the whole is only as good as both
                let legacy = format!("{chain}-legacy");
                if self.chain_file(&legacy).exists() {
                    let l = self
                        .log_named(store, &legacy)?
                        .verify()
                        .map_err(|e| e.to_string())?;
                    r.ok = r.ok && l.ok;
                    r.legacy = Some(Box::new(l));
                }
                Ok(json!({"report": r}))
            }
            _ => Err("that is not allowed on this socket".into()),
        }
    }

    /// Take in the chain an earlier version of the box kept as files beside the dashboard's store (see
    /// `LegacyChain`). Idempotent: once taken in, the old files are gone, and a crash between the two steps is recognised
    /// by the marker in the store and finished. Never merges: the old chain is kept whole beside the box's chain
    /// (`<chain>-legacy`), still sealed with its own key, and the box's chain gets a **new** key: the old one was a file the
    /// box user's own process wrote, so anyone who copied it could reseal a copy of every later line. The box's chain names
    /// where the old one ended, under the new key; `verify` checks each with its own.
    pub fn migrate(
        &self,
        store: &dyn SecretStore,
        chain: &str,
        legacy: &Path,
    ) -> Result<(), String> {
        let file_ok = legacy.is_absolute()
            && !legacy.components().any(|c| c.as_os_str() == "..")
            && legacy
                .file_name()
                .is_some_and(|n| n.to_string_lossy().ends_with(".audit.jsonl"));
        if !file_ok {
            return Ok(());
        }
        let Some(old) = LegacyChain::read(legacy).map_err(|e| e.to_string())? else {
            return Ok(());
        };
        // nothing that parses as a chain: there is nothing to take in, and the file is not ours to remove
        if old.entries.is_empty() && old.checkpoints.is_empty() {
            return Ok(());
        }
        let head = old
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_default();
        let marker = format!("{MIGRATED_PREFIX}{chain}");
        if store.get(&marker).map_err(|e| e.0)?.as_deref() == Some(head.as_str())
            && !head.is_empty()
        {
            old.destroy();
            return Ok(());
        }
        let report = old.report();
        let live_exists = self.log_named_unkeyed_has_entries(chain);
        let target = format!("{chain}-legacy");
        // the old key seals the old lines only, kept apart; the box's chain never uses it
        if let Some(k) = &old.key {
            store
                .set(&format!("{KEY_PREFIX}{target}"), &hex(k))
                .map_err(|e| e.0)?;
            self.keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&target);
        }
        let dest = self.log_named(store, &target)?;
        dest.adopt(&old).map_err(|e| e.to_string())?;
        let live = self.log_named(store, chain)?;
        let seq = old.entries.last().map_or(0, |e| e.seq);
        let short: String = head.chars().take(16).collect();
        live.append(NewEvent {
            ts_ms: crate::tokenmac::now_ms(),
            actor: "audit-service".into(),
            action: "audit.migrated".into(),
            subject: Some(chain.to_string()),
            detail: format!(
                "from={} seq={seq} head={short} source_ok={}",
                if live_exists {
                    "kept-apart"
                } else {
                    "kept-apart-new-key"
                },
                report.ok
            ),
            src: None,
        })
        .map_err(|e| e.to_string())?;
        store.set(&marker, &head).map_err(|e| e.0)?;
        old.destroy();
        Ok(())
    }

    fn log_named_unkeyed_has_entries(&self, chain: &str) -> bool {
        std::fs::metadata(self.chain_file(chain)).is_ok_and(|m| m.len() > 0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
    use crate::secrets_service::{listen, serve_with_audit};
    use ozbox_core::audit::{AuditLog, VerifyReport};
    use ozbox_core::audit_remote::Remote;

    struct Rig {
        store: Arc<EncryptedSecrets>,
        box_sock: PathBuf,
        sup_sock: PathBuf,
        dir: PathBuf,
        base: PathBuf,
    }

    fn rig(base: &Path) -> Rig {
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(base.join("s.json"), "box-a", p).unwrap());
        let cfg = Arc::new(AuditCfg::new(base.join("audit"), base.join("anchor")));
        let (b, s) = (base.join("b/box.sock"), base.join("s/sup.sock"));
        let ls = vec![
            (listen(&b, 0o750).unwrap(), Policy::BoxLocked),
            (listen(&s, 0o750).unwrap(), Policy::Supervisor),
        ];
        let st = store.clone();
        std::thread::spawn(move || serve_with_audit(st, ls, None, None, Some(cfg)));
        Rig {
            store,
            box_sock: b,
            sup_sock: s,
            dir: base.join("audit"),
            base: base.to_path_buf(),
        }
    }

    impl Rig {
        fn log(&self, sock: &Path, legacy: &Path) -> AuditLog {
            AuditLog::through(Remote::with_socket(
                sock.to_path_buf(),
                "tasks",
                self.dir.clone(),
                legacy.to_path_buf(),
            ))
        }
        fn box_log(&self) -> AuditLog {
            self.log(&self.box_sock, Path::new("/nonexistent/x.audit.jsonl"))
        }
        fn sup_log(&self) -> AuditLog {
            self.log(&self.sup_sock, Path::new("/nonexistent/x.audit.jsonl"))
        }
    }

    fn ev(n: u64, action: &str) -> ozbox_core::audit::NewEvent {
        ozbox_core::audit::NewEvent {
            ts_ms: 1_000 + n,
            actor: "alice".into(),
            action: action.into(),
            subject: Some(format!("t{n}")),
            detail: String::new(),
            src: None,
        }
    }

    #[test]
    fn events_go_in_over_the_socket_and_the_chain_verifies_sealed_with_a_key_that_is_no_file() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let log = r.box_log();
        for i in 1..=60 {
            log.append(ev(i, "run.queued")).unwrap();
        }
        let v = log.verify().unwrap();
        assert!(v.ok && v.seals_checked && v.entries == 60, "{v:?}");
        // the reader sees the chain as a plain file, without any help from the service
        assert_eq!(log.entries().unwrap().len(), 60);
        // no key file anywhere: the seal key is a secret in the store
        let names: Vec<String> = walk(&r.base);
        assert!(names.iter().all(|n| !n.ends_with(".key")), "{names:?}");
        assert!(r.store.get("audit-seal-key.tasks").unwrap().is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(log.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o644);
            let a = std::fs::metadata(r.base.join("anchor/tasks.audit.anchor")).unwrap();
            assert_eq!(a.permissions().mode() & 0o777, 0o600);
        }
    }

    fn walk(p: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path.to_string_lossy().into_owned());
            }
        }
        out
    }

    /// The finding this closes: a box-user client wrote `person:owner` as the actor of an approval.
    #[test]
    fn a_box_socket_event_is_recorded_as_the_user_that_sent_it_not_as_whoever_it_names() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let mut e = ev(1, "run.approved");
        e.actor = "person:owner".into();
        r.box_log().append(e).unwrap();
        let entries = r.box_log().entries().unwrap();
        let last = entries.last().unwrap();
        assert_ne!(last.actor, "person:owner");
        assert!(
            last.actor == "box-user" || last.actor.starts_with("uid:"),
            "{}",
            last.actor
        );
        assert!(last.detail.contains("claimed-actor=person:owner"));
        // the supervisor (a directory only its user may enter) may name a person
        let mut e = ev(2, "run.approved");
        e.actor = "person:owner".into();
        r.sup_log().append(e).unwrap();
        assert_eq!(
            r.sup_log().entries().unwrap().last().unwrap().actor,
            "person:owner"
        );
        assert_eq!(box_actor(Some(1500)), "uid:1500");
    }

    /// The finding this closes: one secret added to the store per chain name a client could make up.
    #[test]
    fn a_chain_the_service_does_not_keep_is_refused_and_makes_no_key() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let cfg = AuditCfg::new(r.base.join("audit"), r.base.join("anchor"));
        for chain in ["a1", "a2", "tasks-legacy", "tasks-epoch0"] {
            for p in [
                Policy::Box,
                Policy::BoxLocked,
                Policy::Supervisor,
                Policy::Admin,
            ] {
                let e = cfg
                    .respond(
                        r.store.as_ref(),
                        p,
                        None,
                        &json!({"op":"audit_verify","chain":chain}),
                    )
                    .unwrap_err();
                assert!(e.contains("not valid"), "{chain} {p:?}: {e}");
            }
        }
        let names = r.store.names(KEY_PREFIX).unwrap();
        assert!(names.is_empty(), "{names:?}");
        // the one the service keeps works
        assert!(cfg
            .respond(
                r.store.as_ref(),
                Policy::Box,
                None,
                &json!({"op":"audit_verify","chain":"tasks"})
            )
            .is_ok());
    }

    #[test]
    fn the_box_socket_can_append_and_verify_but_not_seal_or_use_the_services_words() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let b = r.box_log();
        b.append(ev(1, "run.queued")).unwrap();
        assert!(b.verify().unwrap().ok);
        // words the service writes about itself are refused, as a whole request
        for w in ["secrets.import", "audit.migrated"] {
            let e = b.append(ev(2, w)).unwrap_err().to_string();
            assert!(e.contains("service's own"), "{e}");
        }
        assert_eq!(b.entries().unwrap().len(), 1);
        // sealing is the supervisor's (and root's), never the box user's
        let e = b.seal_now(5).unwrap_err().to_string();
        assert!(e.contains("not allowed"), "{e}");
        let s = r.sup_log();
        s.append(ev(3, "secrets.import")).unwrap();
        assert!(s.seal_now(5).unwrap().is_some());
        assert!(s.verify().unwrap().ok);
    }

    #[test]
    fn nothing_is_recorded_when_the_service_cannot_be_reached_and_no_file_is_written() {
        let d = tempfile::tempdir().unwrap();
        let log = AuditLog::through(Remote::with_socket(
            d.path().join("gone.sock"),
            "tasks",
            d.path().join("audit"),
            d.path().join("x.audit.jsonl"),
        ));
        let e = log.append(ev(1, "run.queued")).unwrap_err().to_string();
        assert!(e.contains("could not be reached"), "{e}");
        assert!(!d.path().join("audit").exists());
        assert!(log.last_src().is_err() && log.verify().is_err());
    }

    #[test]
    fn any_edit_to_the_chain_file_is_named_by_the_service_even_a_consistent_rewrite() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let log = r.sup_log();
        for i in 1..=55 {
            log.append(ev(i, "run.queued")).unwrap();
        }
        assert!(log.verify().unwrap().ok);
        let text = std::fs::read_to_string(log.path()).unwrap();
        // 1. a changed field
        std::fs::write(log.path(), text.replacen("alice", "mallory", 1)).unwrap();
        let v: VerifyReport = log.verify().unwrap();
        assert!(!v.ok && !v.altered.is_empty(), "{v:?}");
        // 2. every entry rewritten consistently (hashes recomputed) while the old checkpoints stay: the seals no longer match
        let mut entries = ozbox_core::audit::AuditLog::at(log.path(), r.base.join("none"))
            .entries()
            .unwrap();
        // put the file back first, then rewrite
        std::fs::write(log.path(), &text).unwrap();
        let mut prev = ozbox_core::audit::GENESIS.to_string();
        for e in &mut entries {
            e.actor = "mallory".into();
            e.prev = prev.clone();
            e.hash = ozbox_core::audit::entry_hash(e);
            prev = e.hash.clone();
        }
        let checks: Vec<String> = text
            .lines()
            .filter(|l| l.contains("\"k\":\"c\""))
            .map(String::from)
            .collect();
        let mut out = String::new();
        for e in &entries {
            out.push_str(&serde_json::json!({"k":"e","seq":e.seq,"ts_ms":e.ts_ms,"actor":e.actor,"action":e.action,
                "subject":e.subject,"detail":e.detail,"src":e.src,"prev":e.prev,"hash":e.hash}).to_string());
            out.push('\n');
        }
        for c in checks {
            out.push_str(&c);
            out.push('\n');
        }
        std::fs::write(log.path(), out).unwrap();
        let v = log.verify().unwrap();
        assert!(!v.ok, "{v:?}");
        // 3. cutting the tail is caught against the anchor the box user cannot see
        std::fs::write(
            log.path(),
            text.lines().take(10).collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
        assert!(!log.verify().unwrap().ok);
    }

    #[test]
    fn the_box_socket_cannot_read_write_delete_or_list_the_seal_key_and_the_key_is_in_no_answer() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let log = r.box_log();
        log.append(ev(1, "run.queued")).unwrap();
        let key = r.store.get("audit-seal-key.tasks").unwrap().unwrap();
        let (_, m) = (
            0,
            Arc::new(crate::tokenmac::TokenMac::new(
                r.store.clone() as Arc<dyn SecretStore>
            )),
        );
        for op in [
            serde_json::json!({"op":"get","name":"audit-seal-key.tasks"}),
            serde_json::json!({"op":"set","name":"audit-seal-key.tasks","value":"00".repeat(32)}),
            serde_json::json!({"op":"delete","name":"audit-seal-key.tasks"}),
            serde_json::json!({"op":"set","name":"audit-migrated.tasks","value":"x"}),
        ] {
            for p in [Policy::Box, Policy::BoxLocked, Policy::Supervisor] {
                let a = crate::secrets_service::handle(&r.store, &m, p, &op.to_string());
                assert!(a.contains("\"ok\":false"), "{p:?} {op}: {a}");
                assert!(!a.contains(&key));
            }
        }
        let names = crate::secrets_service::handle(
            &r.store,
            &m,
            Policy::Box,
            r#"{"op":"names","prefix":""}"#,
        );
        assert!(!names.contains("audit-seal-key"), "{names}");
        assert!(r.store.get("audit-seal-key.tasks").unwrap().unwrap() == key);
        // the key is in nothing the socket answered, nor in the chain
        let report = serde_json::to_string(&log.verify().unwrap()).unwrap();
        assert!(!report.contains(&key));
        assert!(!std::fs::read_to_string(log.path()).unwrap().contains(&key));
    }

    /// The finding this closes: after the migration the box's chain was sealed with the key the box user's own process
    /// wrote, so whoever copied that file could reseal a copy of the chain for ever.
    #[test]
    fn a_chain_the_box_user_wrote_is_kept_whole_with_its_old_key_and_the_boxs_chain_gets_a_new_one()
    {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        // the old way: files beside the store, key file beside them
        let old_dir = d.path().join("old");
        let old = AuditLog::beside(&old_dir.join("tasks.json"));
        assert!(!old.is_remote());
        for i in 1..=55 {
            old.append(ev(i, "run.queued")).unwrap();
        }
        old.seal_now(9_000).unwrap();
        let before = old.entries().unwrap();
        let old_key = std::fs::read(old_dir.join("tasks.audit.key")).unwrap();
        let legacy = old_dir.join("tasks.audit.jsonl");
        let sup = r.log(&r.sup_sock, &legacy);
        sup.append(ev(100, "run.started")).unwrap();
        let v = sup.verify().unwrap();
        assert!(v.ok && v.seals_checked, "{v:?}");
        // every old entry is kept, unchanged and in order, apart, and checked with the old key
        let kept = v.legacy.as_ref().unwrap();
        assert!(
            kept.ok && kept.entries == 55 && kept.seals_checked,
            "{kept:?}"
        );
        let apart = AuditLog::at(r.dir.join("tasks-legacy.audit.jsonl"), r.base.join("x"))
            .entries()
            .unwrap();
        assert_eq!(apart, before);
        // the box's chain starts with the boundary entry, then the new one
        let after = sup.entries().unwrap();
        assert_eq!(after[0].action, "audit.migrated");
        assert!(
            after[0].detail.contains("from=kept-apart-new-key")
                && after[0].detail.contains("source_ok=true")
        );
        assert_eq!(after[1].action, "run.started");
        // the key that seals the box's chain is not the old key file's
        let live = unhex(&r.store.get("audit-seal-key.tasks").unwrap().unwrap()).unwrap();
        assert_ne!(live, old_key);
        let kept_key =
            unhex(&r.store.get("audit-seal-key.tasks-legacy").unwrap().unwrap()).unwrap();
        assert_eq!(kept_key, old_key);
        // the old files and the old key are gone
        for f in ["tasks.audit.jsonl", "tasks.audit.anchor", "tasks.audit.key"] {
            assert!(!old_dir.join(f).exists(), "{f}");
        }
        // idempotent: another call changes nothing
        sup.append(ev(101, "run.finished")).unwrap();
        assert_eq!(sup.entries().unwrap().len(), 3);
        assert!(sup.verify().unwrap().ok);
    }

    #[test]
    fn an_old_chain_met_after_the_new_one_started_is_kept_whole_beside_it_and_checked_too() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        // the tool host wrote first
        r.box_log().append(ev(1, "tool.call")).unwrap();
        let old_dir = d.path().join("old");
        let old = AuditLog::beside(&old_dir.join("tasks.json"));
        for i in 1..=5 {
            old.append(ev(i, "run.queued")).unwrap();
        }
        let sup = r.log(&r.sup_sock, &old_dir.join("tasks.audit.jsonl"));
        sup.append(ev(2, "run.started")).unwrap();
        let v = sup.verify().unwrap();
        assert!(v.ok, "{v:?}");
        let legacy = v.legacy.unwrap();
        assert!(legacy.ok && legacy.entries == 5 && legacy.seals_checked);
        let entries = sup.entries().unwrap();
        assert_eq!(entries[0].action, "tool.call");
        assert_eq!(entries[1].action, "audit.migrated");
        assert!(entries[1].detail.contains("from=kept-apart"));
        assert!(r.dir.join("tasks-legacy.audit.jsonl").exists());
    }

    #[test]
    fn only_the_supervisors_socket_may_name_an_old_chain_to_take_in() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let old_dir = d.path().join("old");
        let old = AuditLog::beside(&old_dir.join("tasks.json"));
        old.append(ev(1, "run.queued")).unwrap();
        // the box socket ignores the hint
        let b = r.log(&r.box_sock, &old_dir.join("tasks.audit.jsonl"));
        b.append(ev(2, "run.started")).unwrap();
        assert!(old_dir.join("tasks.audit.jsonl").exists());
        assert_eq!(b.entries().unwrap().len(), 1);
    }

    #[test]
    fn a_file_that_is_not_a_chain_is_never_copied() {
        let d = tempfile::tempdir().unwrap();
        let r = rig(d.path());
        let f = d.path().join("old/passwd.audit.jsonl");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "root:x:0:0:SENTINEL-not-a-chain\n").unwrap();
        let sup = r.log(&r.sup_sock, &f);
        sup.append(ev(1, "run.started")).unwrap();
        for e in walk(&r.base) {
            if e.contains("/audit/") || e.contains("/anchor/") {
                assert!(!std::fs::read_to_string(&e)
                    .unwrap_or_default()
                    .contains("SENTINEL-not-a-chain"));
            }
        }
    }
}
