//! This computer's end of the ingress route (ADR 0029, Amendment 9): `ozbox secrets ... --box` and friends reach a box's secrets
//! service as the `ozbox-ingress` account, every request sealed to the service's key.
//!
//! * **Pins.** The service's public key is pinned the first time this computer talks to a box, through the ingress route (a
//!   route no process of the box user is on), and the pin is kept in this program's own state file, not in `~/.ssh`. Every
//!   later request is sealed to the pinned key and carries its fingerprint; a box whose key is not the pinned one answers
//!   `key_changed` and nothing is sent in the clear. Changing a pin is explicit (`ozbox secrets ingress pin --replace`),
//!   shows both fingerprints and needs a person at a terminal.
//! * **Sealing.** The request (what the old route sent as plain text) is sealed with HPKE to the pinned key, with the
//!   operation, project, environment, box, key fingerprint, time and a one-time id as authenticated data.
//! * **Old boxes.** A box made before the ingress account does not have it: the route is refused with a plain sentence that
//!   says what to do. The old route is never used as a fallback: that would be silently weaker.

use std::path::PathBuf;

use ozbox_core::{CommandRunner, CommandSpec};
use serde_json::{json, Value};

use crate::messages::t;
use crate::run::CliError;

/// A box's pinned service key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub public_hex: String,
    pub fingerprint: String,
}

/// Where pins are kept.
pub trait Pins {
    fn get(&self, box_name: &str) -> Option<Pin>;
    fn put(&self, box_name: &str, pin: &Pin) -> Result<(), String>;
}

/// Pins in a file of this program's own state, `0600`, one JSON object keyed by box name.
pub struct FilePins(pub PathBuf);

impl FilePins {
    pub fn default_path() -> PathBuf {
        if let Some(p) = std::env::var_os("OZBOX_INGRESS_PINS").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ozbox")
            .join("ingress-pins.json")
    }

    fn read(&self) -> serde_json::Map<String, Value> {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default()
    }

    fn write(&self, m: &serde_json::Map<String, Value>) -> Result<(), String> {
        let io = |_| "the pin could not be saved".to_string();
        if let Some(d) = self.0.parent() {
            std::fs::create_dir_all(d).map_err(io)?;
        }
        let tmp = self.0.with_extension("tmp");
        std::fs::write(&tmp, Value::Object(m.clone()).to_string()).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
        }
        std::fs::rename(&tmp, &self.0).map_err(io)
    }
}

impl FilePins {
    /// The box and store ids this computer first saw for a box (ADR 0041): what it recomputes a decision's
    /// challenge from. Kept in the box's pin entry, so `ingress pin --replace` clears them with the key.
    pub fn ids_get(&self, box_name: &str) -> Option<(String, String)> {
        let m = self.read();
        let e = m.get(box_name)?.get("ids")?;
        Some((
            e["box_id"].as_str()?.to_string(),
            e["store_id"].as_str()?.to_string(),
        ))
    }

    pub fn ids_put(&self, box_name: &str, box_id: &str, store_id: &str) -> Result<(), String> {
        let mut m = self.read();
        let entry = m
            .get_mut(box_name)
            .and_then(Value::as_object_mut)
            .ok_or("this box has no pin yet")?;
        entry.insert(
            "ids".into(),
            json!({"box_id": box_id, "store_id": store_id}),
        );
        self.write(&m)
    }
}

impl Pins for FilePins {
    fn get(&self, box_name: &str) -> Option<Pin> {
        let m = self.read();
        let e = m.get(box_name)?;
        let public_hex = e["public"].as_str()?.to_string();
        let fingerprint = e["fingerprint"].as_str()?.to_string();
        // a pin whose fingerprint does not match its key is damaged, and is treated as no pin (never trusted)
        let raw = ozbox_seal::public_from_hex(&public_hex).ok()?;
        (ozbox_seal::fingerprint(&raw) == fingerprint).then_some(Pin {
            public_hex,
            fingerprint,
        })
    }

    fn put(&self, box_name: &str, pin: &Pin) -> Result<(), String> {
        let mut m = self.read();
        m.insert(
            box_name.to_string(),
            json!({"public": pin.public_hex, "fingerprint": pin.fingerprint}),
        );
        self.write(&m)
    }
}

/// Why a request to the ingress route did not give an answer.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// ssh did not log in as the ingress account: the box has none for this computer.
    NoIngress,
    /// The route did not work (the box is off, the tunnel is down).
    Unreachable(String),
    /// The box answered, and said no. `code` is the service's word for why.
    Refused { code: String, message: String },
}

impl Failure {
    pub fn into_cli(self, box_name: &str) -> CliError {
        CliError::Msg(match self {
            Failure::NoIngress => t("ingress.no_ingress", &[("box", box_name)]),
            Failure::Unreachable(why) => {
                t("ingress.unreachable", &[("box", box_name), ("why", &why)])
            }
            Failure::Refused { code, message } if code == "key_changed" => t(
                "ingress.key_changed",
                &[("box", box_name), ("why", &message)],
            ),
            Failure::Refused { message, .. } => message,
        })
    }
}

/// One request line over the route, as the ingress account. The line goes on standard input: the account's forced command
/// reads it, and nothing is put on the command line (the account runs one program whatever is asked).
fn send(runner: &dyn CommandRunner, box_name: &str, line: &str) -> Result<Value, Failure> {
    let spec = CommandSpec::new("ssh")
        .args([
            "-T".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::ingress_alias(box_name),
        ])
        .stdin(format!("{line}\n").into_bytes());
    let out = runner
        .run(&spec)
        .map_err(|e| Failure::Unreachable(e.to_string()))?;
    if out.status != Some(0) {
        let why = out.stderr.trim();
        // the box has no such account (made before the ingress route), or does not have this computer's key for it
        if why.contains("Permission denied") || why.contains("publickey") {
            return Err(Failure::NoIngress);
        }
        return Err(Failure::Unreachable(why.chars().take(300).collect()));
    }
    let v: Value = serde_json::from_str(out.stdout.trim())
        .map_err(|_| Failure::Unreachable(t("ingress.bad_answer", &[])))?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        Err(Failure::Refused {
            code: v["code"].as_str().unwrap_or("").to_string(),
            message: v["error"]
                .as_str()
                .unwrap_or("the request was refused")
                .to_string(),
        })
    }
}

/// Ask the box for its service key. Only a public key comes back, so nothing about this call is secret.
pub fn fetch_key(runner: &dyn CommandRunner, box_name: &str) -> Result<Pin, Failure> {
    let v = send(runner, box_name, &json!({"op": "service_key"}).to_string())?;
    let r = &v["result"];
    let bad = || Failure::Unreachable(t("ingress.bad_answer", &[]));
    let public_hex = r["public"].as_str().ok_or_else(bad)?.to_string();
    let raw = ozbox_seal::public_from_hex(&public_hex).map_err(|_| bad())?;
    // the fingerprint is worked out here, never taken from the box's word
    let fingerprint = ozbox_seal::fingerprint(&raw);
    if r["fingerprint"].as_str() != Some(fingerprint.as_str())
        || r["box"].as_str() != Some(box_name)
    {
        return Err(bad());
    }
    Ok(Pin {
        public_hex,
        fingerprint,
    })
}

/// The pin for a box: the one kept, or (the first time) the key the box gives through the ingress route, pinned and said.
pub fn pin_for(
    runner: &dyn CommandRunner,
    pins: &dyn Pins,
    box_name: &str,
    say: &mut dyn FnMut(String),
) -> Result<Pin, CliError> {
    if let Some(p) = pins.get(box_name) {
        return Ok(p);
    }
    let pin = fetch_key(runner, box_name).map_err(|f| f.into_cli(box_name))?;
    pins.put(box_name, &pin).map_err(CliError::Msg)?;
    say(t(
        "ingress.pinned",
        &[("box", box_name), ("fingerprint", &pin.fingerprint)],
    ));
    Ok(pin)
}

/// Seal `inner` to the box's pinned key and send it. Returns the box's answer (what the old route returned).
pub fn exchange(
    runner: &dyn CommandRunner,
    pins: &dyn Pins,
    box_name: &str,
    inner: &Value,
    now_ms: u64,
    id: &str,
    say: &mut dyn FnMut(String),
) -> Result<Value, CliError> {
    let pin = pin_for(runner, pins, box_name, say)?;
    let public = ozbox_seal::public_from_hex(&pin.public_hex)
        .map_err(|_| CliError::Msg(t("ingress.pin_damaged", &[("box", box_name)])))?;
    let sealed = crate::secrets_ingress::seal_request(
        &public,
        box_name,
        &pin.fingerprint,
        inner,
        now_ms,
        id,
    )
    .map_err(CliError::Msg)?;
    // the box reads one line of at most MAX_LINE_BYTES, the newline included: a longer one is refused here, never sent
    let line = sealed.to_string();
    if line.len() as u64 + 1 > crate::secrets_ingress::MAX_LINE_BYTES {
        return Err(CliError::Msg(t("secrets.import_too_big", &[])));
    }
    send(runner, box_name, &line).map_err(|f| f.into_cli(box_name))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn random_id() -> Result<String, CliError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| CliError::Msg(t("ingress.no_random", &[])))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// The pins in use: this program's own state file; under test, a table in memory that opens what was sent.
#[cfg(not(test))]
fn default_pins() -> Box<dyn Pins> {
    Box::new(FilePins(FilePins::default_path()))
}

/// Send one request to a box's secrets service through the ingress route (the real clock, the real pin file).
pub fn call(runner: &dyn CommandRunner, box_name: &str, inner: &Value) -> Result<Value, CliError> {
    let pins = default_pins();
    exchange(
        runner,
        pins.as_ref(),
        box_name,
        inner,
        now_ms(),
        &random_id()?,
        &mut |m| eprintln!("{m}"),
    )
}

/// Put the owner's copy of a box's store key back while the box's secrets service is down: through the ingress account, which
/// leaves it where only the secrets user can read it. The key travels over the SSH route to that account, which no process
/// of the box user is on; the service takes it only if it really opens the store. The key is never echoed.
pub fn place_kek(runner: &dyn CommandRunner, box_name: &str, kek: &str) -> Result<(), String> {
    send(
        runner,
        box_name,
        &json!({"op": "kek_place", "kek": kek}).to_string(),
    )
    .map(|_| ())
    .map_err(|f| match f.into_cli(box_name) {
        CliError::Msg(m) => m,
        other => other.to_string(),
    })
}

/// Put the pin in place on purpose. With `replace`, an existing pin is changed after showing both fingerprints and a typed
/// confirmation; without it an existing pin is only reported (and checked against the box).
pub fn pin_command(
    runner: &dyn CommandRunner,
    pins: &dyn Pins,
    box_name: &str,
    replace: bool,
    confirm: &mut dyn FnMut(&str) -> bool,
    json: bool,
) -> Result<(), CliError> {
    let fresh = fetch_key(runner, box_name).map_err(|f| f.into_cli(box_name))?;
    let old = pins.get(box_name);
    let (state, shown): (&str, &Pin) = match (&old, replace) {
        (Some(o), _) if o == &fresh => ("unchanged", o),
        (Some(o), false) => {
            return Err(CliError::Msg(t(
                "ingress.pin_differs",
                &[
                    ("box", box_name),
                    ("pinned", &o.fingerprint),
                    ("now", &fresh.fingerprint),
                ],
            )))
        }
        (Some(o), true) => {
            let word = box_name.to_string();
            if !confirm(&t(
                "ingress.pin_replace_prompt",
                &[
                    ("box", box_name),
                    ("pinned", &o.fingerprint),
                    ("now", &fresh.fingerprint),
                    ("word", &word),
                ],
            )) {
                return Err(CliError::Msg(t("ingress.pin_not_confirmed", &[])));
            }
            pins.put(box_name, &fresh).map_err(CliError::Msg)?;
            ("replaced", &fresh)
        }
        (None, _) => {
            pins.put(box_name, &fresh).map_err(CliError::Msg)?;
            ("pinned", &fresh)
        }
    };
    if json {
        println!(
            "{}",
            json!({"box": box_name, "state": state, "fingerprint": shown.fingerprint})
        );
    } else {
        println!(
            "{}",
            t(
                "ingress.pin_done",
                &[
                    ("box", box_name),
                    ("state", state),
                    ("fingerprint", &shown.fingerprint)
                ]
            )
        );
    }
    Ok(())
}

/// What a test of any caller needs: a box's service key made on the spot, pinned in memory, so the test can open what the
/// caller sent and check what it did not.
#[cfg(test)]
pub mod testing {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    thread_local! {
        static KEYS: RefCell<HashMap<String, ozbox_seal::ServiceKey>> = RefCell::new(HashMap::new());
        static PINS: RefCell<HashMap<String, Pin>> = RefCell::new(HashMap::new());
    }

    pub struct MemoryPins;

    impl Pins for MemoryPins {
        fn get(&self, b: &str) -> Option<Pin> {
            PINS.with(|p| p.borrow().get(b).cloned())
        }
        fn put(&self, b: &str, pin: &Pin) -> Result<(), String> {
            PINS.with(|p| p.borrow_mut().insert(b.to_string(), pin.clone()));
            Ok(())
        }
    }

    pub fn default_pins() -> Box<dyn Pins> {
        Box::new(MemoryPins)
    }

    /// The box's service key for this test, pinned. Made once per box and thread.
    pub fn install(box_name: &str) -> ozbox_seal::ServiceKey {
        let existing = KEYS.with(|k| {
            k.borrow().get(box_name).map(|k| {
                ozbox_seal::ServiceKey::from_secret_bytes(&k.secret_bytes()[..])
                    .unwrap_or_else(|_| unreachable!("a stored key is valid"))
            })
        });
        let key = existing.unwrap_or_else(|| {
            let k = ozbox_seal::ServiceKey::generate().unwrap_or_else(|_| unreachable!());
            KEYS.with(|m| {
                m.borrow_mut().insert(
                    box_name.to_string(),
                    ozbox_seal::ServiceKey::from_secret_bytes(&k.secret_bytes()[..])
                        .unwrap_or_else(|_| unreachable!()),
                )
            });
            k
        });
        let _ = MemoryPins.put(
            box_name,
            &Pin {
                public_hex: ozbox_seal::public_to_hex(&key.public()),
                fingerprint: key.fingerprint(),
            },
        );
        key
    }

    /// Open a sealed request a test caller sent (a call's standard input), as the box's service would. Panics if it
    /// cannot be opened: a test that sent something else wants to know.
    pub fn open_sent(box_name: &str, stdin: &[u8]) -> Value {
        let key = install(box_name);
        let line = String::from_utf8(stdin.to_vec()).unwrap_or_default();
        let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
        assert_eq!(v["op"], "sealed", "what was sent was not a sealed request");
        let aad = crate::secrets_ingress::Ingress::aad_for(
            box_name,
            &key.fingerprint(),
            v["iop"].as_str().unwrap_or(""),
            v["project"].as_str().unwrap_or(""),
            v["env"].as_str().unwrap_or(""),
            v["ts"].as_u64().unwrap_or(0),
            v["id"].as_str().unwrap_or(""),
        );
        let plain = key
            .open(
                &ozbox_seal::info("ingress", box_name),
                &aad,
                &crate::serve::auth::b64::decode_std(v["enc"].as_str().unwrap_or(""))
                    .unwrap_or_default(),
                &crate::serve::auth::b64::decode_std(v["ct"].as_str().unwrap_or(""))
                    .unwrap_or_default(),
            )
            .unwrap_or_else(|_| panic!("what was sent could not be opened by the box's key"));
        serde_json::from_slice(&plain).unwrap_or(Value::Null)
    }
}

#[cfg(test)]
fn default_pins() -> Box<dyn Pins> {
    testing::default_pins()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    const SENTINEL: &str = "SENTINEL-client-0123456789";
    const NOW: u64 = 1_800_000_000_000;
    const ID: &str = "00112233445566778899aabbccddeeff";

    fn reply(r: &RecordingRunner, status: i32, stdout: &str, stderr: &str) {
        r.reply(Output {
            status: Some(status),
            stdout: stdout.into(),
            stderr: stderr.into(),
        });
    }
    fn key_answer(k: &ozbox_seal::ServiceKey, b: &str) -> String {
        json!({"ok": true, "result": {"v": 1, "box": b, "public": ozbox_seal::public_to_hex(&k.public()),
            "fingerprint": k.fingerprint(), "suite": ozbox_seal::SUITE}})
        .to_string()
    }
    fn memory() -> testing::MemoryPins {
        testing::MemoryPins
    }

    #[test]
    fn the_first_request_pins_the_boxs_key_and_every_later_one_is_sealed_to_it() {
        let box_name = "first-box";
        let k = ozbox_seal::ServiceKey::generate().unwrap();
        let r = RecordingRunner::new();
        reply(&r, 0, &key_answer(&k, box_name), "");
        reply(&r, 0, &json!({"ok": true, "names": ["A"]}).to_string(), "");
        let mut said = Vec::new();
        let v = exchange(
            &r,
            &memory(),
            box_name,
            &json!({"op": "import", "project": "app", "env": "staging", "lines": [{"name": "A", "value": SENTINEL}]}),
            NOW,
            ID,
            &mut |m| said.push(m),
        )
        .unwrap();
        assert_eq!(v["names"][0], "A");
        assert!(
            said[0].contains(&k.fingerprint()),
            "the person is told what was pinned"
        );
        let calls = r.calls();
        assert_eq!(calls.len(), 2);
        for c in &calls {
            assert_eq!(c.program, "ssh");
            // the ingress alias, no command, no terminal; nothing of the request on the command line
            assert_eq!(
                c.args,
                ["-T", "-o", "BatchMode=yes", "ozbox-first-box-ingress"]
            );
        }
        // the request that carried the value is sealed: the value is nowhere in what was sent
        let sent = String::from_utf8(calls[1].stdin.clone().unwrap()).unwrap();
        assert!(!sent.contains(SENTINEL) && !sent.contains("\"lines\""));
        let v: Value = serde_json::from_str(sent.trim()).unwrap();
        assert_eq!(v["op"], "sealed");
        assert_eq!(v["fp"], k.fingerprint());
        // and the box's key opens it, with the label the sender gave
        let aad = crate::secrets_ingress::Ingress::aad_for(
            box_name,
            &k.fingerprint(),
            "import",
            "app",
            "staging",
            NOW,
            ID,
        );
        let plain = k
            .open(
                &ozbox_seal::info("ingress", box_name),
                &aad,
                &crate::serve::auth::b64::decode_std(v["enc"].as_str().unwrap()).unwrap(),
                &crate::serve::auth::b64::decode_std(v["ct"].as_str().unwrap()).unwrap(),
            )
            .unwrap();
        assert!(String::from_utf8_lossy(&plain).contains(SENTINEL));
        // the second request needs no key fetch
        let r2 = RecordingRunner::new();
        reply(&r2, 0, &json!({"ok": true}).to_string(), "");
        exchange(
            &r2,
            &memory(),
            box_name,
            &json!({"op": "approval_keys"}),
            NOW,
            "ffeeddccbbaa99887766554433221100",
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(r2.calls().len(), 1);
    }

    #[test]
    fn a_box_whose_key_is_not_the_pinned_one_is_refused_and_nothing_readable_is_sent() {
        let box_name = "changed-box";
        let k = testing::install(box_name);
        let r = RecordingRunner::new();
        reply(
            &r,
            0,
            &json!({"ok": false, "code": "key_changed", "error": "this box's key is not the one this computer pinned"}).to_string(),
            "",
        );
        let e = exchange(&r, &memory(), box_name, &json!({"op": "import", "project": "a", "env": "b", "lines": [{"name": "K", "value": SENTINEL}]}), NOW, ID, &mut |_| {}).unwrap_err();
        let CliError::Msg(m) = e else { panic!() };
        assert!(m.contains("changed") && m.contains("ingress pin"));
        let sent = String::from_utf8(r.calls()[0].stdin.clone().unwrap()).unwrap();
        assert!(!sent.contains(SENTINEL));
        drop(k);
    }

    #[test]
    fn a_key_the_box_describes_wrongly_is_never_pinned() {
        let k = ozbox_seal::ServiceKey::generate().unwrap();
        for (name, answer) in [
            (
                "a fingerprint that is not the key's",
                json!({"ok": true, "result": {"box": "bad-fp", "public": ozbox_seal::public_to_hex(&k.public()), "fingerprint": "00000000-00000000-00000000-00000000"}}),
            ),
            (
                "another box's name",
                json!({"ok": true, "result": {"box": "other", "public": ozbox_seal::public_to_hex(&k.public()), "fingerprint": k.fingerprint()}}),
            ),
            (
                "a key that is not a key",
                json!({"ok": true, "result": {"box": "bad-fp", "public": "zz", "fingerprint": "x"}}),
            ),
        ] {
            let r = RecordingRunner::new();
            reply(&r, 0, &answer.to_string(), "");
            assert!(fetch_key(&r, "bad-fp").is_err(), "{name}");
        }
        assert!(memory().get("bad-fp").is_none());
    }

    #[test]
    fn an_old_box_is_refused_with_a_sentence_and_the_plain_route_is_never_used() {
        let r = RecordingRunner::new();
        reply(
            &r,
            255,
            "",
            "ozbox-ingress@127.0.0.1: Permission denied (publickey).",
        );
        let e = exchange(
            &r,
            &memory(),
            "old-box",
            &json!({"op": "import"}),
            NOW,
            ID,
            &mut |_| {},
        )
        .unwrap_err();
        let CliError::Msg(m) = e else { panic!() };
        assert!(m.contains("old-box") && m.contains("ingress"));
        // it says the way forward and its one cost, for both providers, and offers no second route
        assert!(m.contains("`ozbox upgrade old-box`"), "{m}");
        assert!(m.contains("AWS") && m.contains("Hetzner"), "{m}");
        assert!(
            m.contains("new, empty store") && m.contains("--accept-new-secrets-store"),
            "{m}"
        );
        for stale in ["make a new box", "move /work", "(AWS) gives"] {
            assert!(!m.contains(stale), "{m}");
        }
        // one attempt, as the ingress account; nothing was sent as the box user
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0]
            .args
            .iter()
            .all(|a| a != "ozbox-old-box" && !a.contains("secrets")));
    }

    #[test]
    fn a_placed_key_goes_to_the_ingress_account_alone_and_is_not_in_an_error() {
        let r = RecordingRunner::new();
        reply(&r, 0, &json!({"ok": true, "placed": true}).to_string(), "");
        place_kek(&r, "kek-box", "KEK-SENTINEL-xyz").unwrap();
        let c = &r.calls()[0];
        assert_eq!(c.args.last().unwrap(), "ozbox-kek-box-ingress");
        assert!(c.args.iter().all(|a| !a.contains("KEK-SENTINEL")));
        // a refusal says why and does not repeat the key
        let r = RecordingRunner::new();
        reply(
            &r,
            0,
            &json!({"ok": false, "error": "that is not a store key"}).to_string(),
            "",
        );
        let e = place_kek(&r, "kek-box", "KEK-SENTINEL-xyz").unwrap_err();
        assert!(!e.contains("KEK-SENTINEL"));
    }

    #[test]
    fn a_pin_file_keeps_pins_by_box_privately_and_ignores_a_damaged_one() {
        let d = tempfile::tempdir().unwrap();
        let f = FilePins(d.path().join("conf/ingress-pins.json"));
        let k = ozbox_seal::ServiceKey::generate().unwrap();
        let pin = Pin {
            public_hex: ozbox_seal::public_to_hex(&k.public()),
            fingerprint: k.fingerprint(),
        };
        assert!(f.get("dev").is_none());
        f.put("dev", &pin).unwrap();
        f.put("other", &pin).unwrap();
        assert_eq!(f.get("dev").unwrap(), pin);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&f.0).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // an entry whose fingerprint does not match its key is not a pin
        let mut m = f.read();
        m.insert(
            "bad".into(),
            json!({"public": pin.public_hex, "fingerprint": "nope"}),
        );
        f.write(&m).unwrap();
        assert!(f.get("bad").is_none() && f.get("dev").is_some());
        assert!(f.get("other").is_some());
    }

    #[test]
    fn pinning_on_purpose_reports_a_changed_key_and_replaces_it_only_with_a_typed_confirmation() {
        let box_name = "pin-box";
        let old = ozbox_seal::ServiceKey::generate().unwrap();
        let new = ozbox_seal::ServiceKey::generate().unwrap();
        let p = memory();
        let run = |k: &ozbox_seal::ServiceKey, replace, ok: bool| {
            let r = RecordingRunner::new();
            reply(&r, 0, &key_answer(k, box_name), "");
            let mut asked = Vec::new();
            let res = pin_command(
                &r,
                &p,
                box_name,
                replace,
                &mut |q| {
                    asked.push(q.to_string());
                    ok
                },
                true,
            );
            (res, asked)
        };
        assert!(run(&old, false, false).0.is_ok());
        assert_eq!(p.get(box_name).unwrap().fingerprint, old.fingerprint());
        // the same key again: reported unchanged, no question
        let (r, asked) = run(&old, false, false);
        assert!(r.is_ok() && asked.is_empty());
        // a different key is refused without --replace, and the pin stays
        assert!(run(&new, false, true).0.is_err());
        assert_eq!(p.get(box_name).unwrap().fingerprint, old.fingerprint());
        // with --replace the person is shown both and must confirm
        let (r, asked) = run(&new, true, false);
        assert!(r.is_err());
        assert!(asked[0].contains(&old.fingerprint()) && asked[0].contains(&new.fingerprint()));
        assert_eq!(p.get(box_name).unwrap().fingerprint, old.fingerprint());
        assert!(run(&new, true, true).0.is_ok());
        assert_eq!(p.get(box_name).unwrap().fingerprint, new.fingerprint());
    }
}
