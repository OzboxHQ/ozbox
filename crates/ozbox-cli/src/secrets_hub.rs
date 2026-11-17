//! The secrets service's end of the hub's channel keys (ADR 0042 section 1).
//!
//! Each box's service makes its own channel identity the first time a `hub_` operation is asked for: the four purpose keys and
//! the token MAC key, stored under names that begin with `hub-key-` (the box socket can neither read, write, delete nor list
//! them, and the content scan skips them). What each socket may ask for is decided by `ozbox_hubd::keys::handle`:
//!
//! * the **supervisor** socket signs worker-channel envelopes and enrolment proofs, and opens message bodies;
//! * the **hub** socket (`ozbox-hubd`'s user) signs the handshake and tags enrolment tokens;
//! * the **admin** socket reads the public identity;
//! * every other socket (the box user's, the broker's, the runner's, the import and ingress routes) gets nothing.

use std::sync::Arc;

use ozbox_hubd::keys::{Caller, HubKeys, KeyStore};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::secrets::SecretStore;
use crate::secrets_service::{Gates, Policy};

struct Adapter<'a>(&'a dyn SecretStore);

impl KeyStore for Adapter<'_> {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        self.0
            .get(name)
            .map(|v| v.map(Zeroizing::new))
            .map_err(|e| e.0)
    }
    fn set(&self, name: &str, value: &str) -> Result<(), String> {
        self.0.set(name, value).map_err(|e| e.0)
    }
    fn delete(&self, name: &str) -> Result<(), String> {
        self.0.delete(name).map_err(|e| e.0)
    }
}

/// Which of the hub's callers a socket is.
pub fn caller(policy: Policy) -> Caller {
    match policy {
        Policy::Supervisor => Caller::Supervisor,
        Policy::Hub => Caller::Hub,
        Policy::Admin => Caller::Admin,
        _ => Caller::Other,
    }
}

fn keys(store: &dyn SecretStore, gates: &Gates) -> Result<Arc<HubKeys>, String> {
    let mut held = gates
        .hub_keys
        .lock()
        .map_err(|_| "the hub's keys are not usable".to_string())?;
    if let Some(k) = held.as_ref() {
        return Ok(k.clone());
    }
    let made = !names_present(store);
    let k = Arc::new(HubKeys::load_or_create(&Adapter(store))?);
    if made {
        gates.audit_event(
            store,
            "hub.keys.created",
            &k.identity().identity_fp(),
            "the channel identity was made",
        );
    }
    *held = Some(k.clone());
    Ok(k)
}

fn names_present(store: &dyn SecretStore) -> bool {
    ozbox_hubd::keys::NAMES
        .iter()
        .any(|n| store.exists(n).unwrap_or(false))
}

/// Answer one `hub_` operation for the socket it came in on. A socket that may ask nothing is refused before any key is made.
pub fn answer(
    store: &dyn SecretStore,
    gates: &Gates,
    policy: Policy,
    req: &Value,
) -> Result<Value, String> {
    let who = caller(policy);
    if who == Caller::Other {
        return Err("that is not allowed on this socket".into());
    }
    let k = keys(store, gates)?;
    ozbox_hubd::keys::handle_with_store(&k, &Adapter(store), who, req)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets_enc::EncryptedSecrets;
    use crate::secrets_service::{handle_with, Gates, Policy};
    use crate::tokenmac::TokenMac;
    use ozbox_core::channel::wire::hex;
    use ozbox_hubd::identity::tag_prefix;
    use ozbox_hubd::keys::HUB_ENVELOPE_TAG;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Arc<EncryptedSecrets>, TokenMac, Gates) {
        let d = tempfile::tempdir().unwrap();
        let p: Arc<dyn crate::secrets_enc::KeyProvider> =
            Arc::new(crate::secrets_enc::LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(d.path().join("s.json"), "box-a", p).unwrap());
        let mac = TokenMac::new(store.clone() as Arc<dyn SecretStore>);
        (d, store, mac, Gates::default())
    }

    fn ask(store: &EncryptedSecrets, mac: &TokenMac, gates: &Gates, p: Policy, v: Value) -> Value {
        serde_json::from_str(&handle_with(store, mac, gates, p, &v.to_string())).unwrap()
    }

    #[test]
    fn the_supervisor_signs_envelopes_the_hub_socket_signs_the_handshake_and_the_box_socket_gets_nothing(
    ) {
        let (_d, store, mac, gates) = fixture();
        let mut env = tag_prefix(HUB_ENVELOPE_TAG);
        env.push(1);
        let sign = |p, purpose: &str| {
            ask(
                &store,
                &mac,
                &gates,
                p,
                json!({"op": "hub_sign", "purpose": purpose, "data": hex(&env)}),
            )
        };
        // the box socket is refused before any key exists
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Runner,
            Policy::Import,
            Policy::Broker,
        ] {
            let v = ask(&store, &mac, &gates, p, json!({"op": "hub_identity"}));
            assert_eq!(v["ok"], false, "{p:?}");
        }
        assert!(!store.exists(ozbox_hubd::keys::NAMES[0]).unwrap());
        assert_eq!(sign(Policy::Supervisor, "envelope")["ok"], true);
        assert_eq!(sign(Policy::Hub, "envelope")["ok"], false);
        // the keys were made once, and the identity is the same on every socket that may read it
        let a = ask(
            &store,
            &mac,
            &gates,
            Policy::Supervisor,
            json!({"op": "hub_identity"}),
        );
        let b = ask(
            &store,
            &mac,
            &gates,
            Policy::Hub,
            json!({"op": "hub_identity"}),
        );
        let c = ask(
            &store,
            &mac,
            &gates,
            Policy::Admin,
            json!({"op": "hub_identity"}),
        );
        assert_eq!(a["result"], b["result"]);
        assert_eq!(a["result"], c["result"]);
    }

    #[test]
    fn the_hubs_keys_are_reserved_names_the_box_socket_cannot_read_write_delete_or_list() {
        let (_d, store, mac, gates) = fixture();
        ask(
            &store,
            &mac,
            &gates,
            Policy::Supervisor,
            json!({"op": "hub_identity"}),
        );
        let secrets: Vec<String> = ozbox_hubd::keys::NAMES
            .iter()
            .map(|n| store.get(n).unwrap().unwrap())
            .collect();
        for n in ozbox_hubd::keys::NAMES {
            assert!(!crate::secrets_service::box_may_write(n));
            assert!(!crate::secrets_service::box_may_get(n));
            assert!(crate::secrets_service::is_system_name(n));
            for p in [Policy::Box, Policy::Supervisor] {
                let set = ask(
                    &store,
                    &mac,
                    &gates,
                    p,
                    json!({"op": "set", "name": n, "value": "x"}),
                );
                assert_eq!(set["ok"], false, "{p:?} set {n}");
                let del = ask(&store, &mac, &gates, p, json!({"op": "delete", "name": n}));
                assert_eq!(del["ok"], false, "{p:?} delete {n}");
                let get = ask(&store, &mac, &gates, p, json!({"op": "get", "name": n}));
                assert_eq!(get["ok"], false, "{p:?} get {n}");
            }
        }
        let names = ask(
            &store,
            &mac,
            &gates,
            Policy::Box,
            json!({"op": "names", "prefix": ""}),
        );
        assert!(!names.to_string().contains("hub-key-"));
        // the sentinel: no private value appears in any answer a socket gives
        let mut answers = String::new();
        for p in [Policy::Box, Policy::Supervisor, Policy::Hub, Policy::Admin] {
            answers
                .push_str(&ask(&store, &mac, &gates, p, json!({"op": "hub_identity"})).to_string());
            answers.push_str(
                &ask(
                    &store,
                    &mac,
                    &gates,
                    p,
                    json!({"op": "names", "prefix": ""}),
                )
                .to_string(),
            );
        }
        for s in &secrets {
            assert!(!answers.contains(s.as_str()));
        }
        // and nothing was changed
        for (n, s) in ozbox_hubd::keys::NAMES.iter().zip(&secrets) {
            assert_eq!(&store.get(n).unwrap().unwrap(), s);
        }
    }
}
