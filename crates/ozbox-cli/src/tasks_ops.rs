//! What `ozbox tasks` does, as operations on one endpoint's store: the same code runs in the command line on a laptop (one user, the
//! person's own files) and inside the box's router service (`tasks serve`, a system user of its own), so there is one behaviour and
//! two places it can run. Every operation takes JSON in and gives JSON back; nothing here prints.
//!
//! The key file, the state and the audit log belong to whoever runs this. On a box that is the service user, which agents cannot
//! read: they reach it only through the sockets in [`crate::tasks_service`].

use std::path::Path;

use ozbox_core::agent_mesh::model::{Act, Label, Part, State as TState, Task, TaskKind};
use ozbox_core::agent_mesh::node::Node;
use ozbox_core::agent_mesh::state::{FindError, NewTask, State};
use ozbox_core::agent_mesh::{printable, printable_line, Screen};
use ozbox_core::audit::AuditLog;
use ozbox_core::channel::ring_crypto::{generate, RingSigner, RingVerifier};
use ozbox_core::channel::store::Store;
use ozbox_core::channel::wire::{
    fingerprint, hex, normalize_hex, unhex, word_ok, Crypto, Sealed, Sealer, WireError,
};
use ozbox_core::fence::{fenced, random_fence};
use ozbox_seal::ServiceKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::secrets::SecretStore;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Who is asking. Decides which operations are offered, never what an operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// An agent on a box: submit, reply, inbox, status, why, cancel and the public identity.
    Agent,
    /// The keyless relay a person's `ssh` reaches: one operation, `exchange`, that carries opaque envelope bytes.
    Relay,
    /// The owner (root on a box, or the person on a laptop): everything, including `init`, `pin` and `restored`.
    Admin,
}

/// The identity file. Mode 0600, in a directory of mode 0700. In the router's own directory (a user agents cannot read as) it holds
/// the private keys. On a laptop it holds only `key_id`: the private keys are in the operating system's keychain (the secret store),
/// under `tasks-sign-<key_id>` and `tasks-seal-<key_id>`, read when the channel is opened and never kept on disk.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sign_pkcs8: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    seal_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    key_id: String,
}

/// Where an endpoint's private keys live.
#[derive(Clone, Copy)]
pub enum KeyHome<'a> {
    /// In the identity file, in a directory only the router's own user may enter (`tasks serve` on a box).
    RouterFile,
    /// In the secret store (the keychain on a laptop). An identity file that still holds keys is moved into it when opened.
    Store(&'a dyn SecretStore),
}

/// The secret-store names of an endpoint's two private keys.
pub fn key_names(key_id: &str) -> (String, String) {
    (
        format!("tasks-sign-{key_id}"),
        format!("tasks-seal-{key_id}"),
    )
}

fn new_key_id() -> Result<String, String> {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).map_err(|_| err("no random numbers"))?;
    Ok(hex(&b))
}

fn store_keys(st: &dyn SecretStore, key_id: &str, sign: &str, seal: &str) -> Result<(), String> {
    let (sn, en) = key_names(key_id);
    st.set(&sn, sign)
        .and_then(|()| st.set(&en, seal))
        .map_err(|e| {
            let _ = st.delete(&sn);
            err(format!(
                "the channel's keys could not be kept in {}: {}",
                st.label(),
                e.0
            ))
        })
}

/// What is shared with the other side. Public halves only, in lower-case hex, with the fingerprints a person compares.
#[derive(Serialize, Deserialize)]
pub struct Offer {
    pub name: String,
    pub sign_public: String,
    pub seal_public: String,
    pub epoch: u64,
    #[serde(default)]
    pub sign_fingerprint: String,
    #[serde(default)]
    pub seal_fingerprint: String,
}

impl Offer {
    /// Whether the offer is well formed, and the same keys in their one stored form.
    pub fn checked(&self) -> Option<Offer> {
        let sign = normalize_hex(&self.sign_public).filter(|h| h.len() == 64)?;
        let seal = normalize_hex(&self.seal_public)?;
        ozbox_seal::public_from_hex(&seal).ok()?;
        (word_ok(&self.name) && self.epoch != 0).then(|| Offer {
            name: self.name.clone(),
            sign_fingerprint: unhex(&sign).map(|b| fingerprint(&b)).unwrap_or_default(),
            seal_fingerprint: unhex(&seal).map(|b| fingerprint(&b)).unwrap_or_default(),
            sign_public: sign,
            seal_public: seal,
            epoch: self.epoch,
        })
    }
}

struct SealCrypto {
    key: ServiceKey,
}

fn info_for(pk: &[u8; 32]) -> Vec<u8> {
    ozbox_seal::info("mesh-body", &ozbox_seal::fingerprint(pk))
}

impl Sealer for SealCrypto {
    fn seal(&self, receiver_hex: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, WireError> {
        let pk = ozbox_seal::public_from_hex(receiver_hex).map_err(|_| WireError::SealFailed)?;
        let (enc, ct) =
            ozbox_seal::seal(&pk, &info_for(&pk), aad, plain).map_err(|_| WireError::SealFailed)?;
        let mut out = enc;
        out.extend(ct);
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        if sealed.len() < 32 {
            return Err(WireError::BadSeal);
        }
        let (enc, ct) = sealed.split_at(32);
        self.key
            .open(&info_for(&self.key.public()), aad, enc, ct)
            .map(|z| z.to_vec())
            .map_err(|_| WireError::BadSeal)
    }
}

/// Finds key-shaped text with the same screen agent memory uses.
struct MemScreen;

impl Screen for MemScreen {
    fn find(&self, text: &str) -> Option<&'static str> {
        ozbox_memory::secret_shape::find_secret(text)
    }
}

pub struct Ends {
    store: Store<State>,
    signer: RingSigner,
    verifier: RingVerifier,
    sealer: SealCrypto,
    audit: AuditLog,
    clock: Box<dyn Fn() -> u64>,
}

fn err(m: impl Into<String>) -> String {
    m.into()
}

impl Ends {
    /// Open an initialised channel directory, reading the private keys from where `home` says they live.
    pub fn open(dir: &Path, home: KeyHome<'_>) -> Result<Ends, String> {
        let store: Store<State> = Store::new(dir);
        if !store.exists() {
            return Err(err("not-initialised"));
        }
        let path = dir.join("identity.json");
        let raw = std::fs::read(&path).map_err(|_| err("the identity file could not be read"))?;
        let mut id: IdentityFile =
            serde_json::from_slice(&raw).map_err(|_| err("the identity file is damaged"))?;
        let (sign, seal) = match (home, id.key_id.is_empty()) {
            (KeyHome::RouterFile, true) => (
                Zeroizing::new(id.sign_pkcs8.clone()),
                Zeroizing::new(id.seal_secret.clone()),
            ),
            (KeyHome::RouterFile, false) => {
                return Err(err(
                    "this channel's keys are in a secret store, not in the router's directory",
                ))
            }
            (KeyHome::Store(st), false) => {
                let (sn, en) = key_names(&id.key_id);
                let get = |n: &str| {
                    st.get(n)
                        .map_err(|e| {
                            err(format!(
                                "the channel's keys could not be read from {}: {}",
                                st.label(),
                                e.0
                            ))
                        })?
                        .map(Zeroizing::new)
                        .ok_or_else(|| {
                            err(format!(
                                "the channel's keys are not in {}; this endpoint cannot be used",
                                st.label()
                            ))
                        })
                };
                (get(&sn)?, get(&en)?)
            }
            (KeyHome::Store(st), true) => {
                // an identity written before the keys moved to the secret store: move them, then rewrite the file without them
                let key_id = new_key_id()?;
                store_keys(st, &key_id, &id.sign_pkcs8, &id.seal_secret)?;
                let moved = IdentityFile {
                    name: id.name.clone(),
                    sign_pkcs8: String::new(),
                    seal_secret: String::new(),
                    key_id,
                };
                replace_private(
                    &path,
                    &serde_json::to_vec(&moved).map_err(|e| e.to_string())?,
                )?;
                (
                    Zeroizing::new(id.sign_pkcs8.clone()),
                    Zeroizing::new(id.seal_secret.clone()),
                )
            }
        };
        drop(Zeroizing::new(raw));
        id.sign_pkcs8.zeroize();
        id.seal_secret.zeroize();
        let signer = RingSigner::from_pkcs8(&Zeroizing::new(unhex(&sign).unwrap_or_default()))
            .map_err(err)?;
        let key = ServiceKey::from_secret_bytes(&Zeroizing::new(unhex(&seal).unwrap_or_default()))
            .map_err(|_| err("the sealing key is not valid"))?;
        Ok(Ends {
            store,
            signer,
            verifier: RingVerifier,
            sealer: SealCrypto { key },
            audit: AuditLog::beside(&dir.join("mesh.json")),
            clock: Box::new(now_ms),
        })
    }

    pub fn node(&self) -> Node<'_> {
        Node {
            store: &self.store,
            crypto: Crypto {
                signer: &self.signer,
                verifier: &self.verifier,
                sealer: &self.sealer,
            },
            screen: &MemScreen,
            audit: &self.audit,
            clock: &*self.clock,
        }
    }

    pub fn state(&self) -> Result<State, String> {
        self.store.read().map_err(|e| e.to_string())
    }

    /// Refuse to go on when the audit log is ahead of this store (it was rolled back without being acknowledged).
    pub fn guard(&self) -> Result<(), String> {
        self.node().guard().map_err(|e| e.to_string())
    }

    pub fn store(&self) -> &Store<State> {
        &self.store
    }
}

/// Create an endpoint's identity in `dir`, its private keys where `home` says. Refuses to replace one.
pub fn init(dir: &Path, name: &str, home: KeyHome<'_>) -> Result<Value, String> {
    if !word_ok(name) {
        return Err(err("bad-name"));
    }
    let store: Store<State> = Store::new(dir);
    if store.exists() {
        return Err(err("already-initialised"));
    }
    let (pkcs8, sign_public) = generate().map_err(err)?;
    let key = ServiceKey::generate().map_err(|_| err("no random numbers"))?;
    let sign = Zeroizing::new(hex(&pkcs8));
    let seal = Zeroizing::new(hex(&key.secret_bytes()[..]));
    let file = match home {
        KeyHome::RouterFile => IdentityFile {
            name: name.to_string(),
            sign_pkcs8: sign.to_string(),
            seal_secret: seal.to_string(),
            key_id: String::new(),
        },
        KeyHome::Store(st) => {
            let key_id = new_key_id()?;
            store_keys(st, &key_id, &sign, &seal)?;
            IdentityFile {
                name: name.to_string(),
                sign_pkcs8: String::new(),
                seal_secret: String::new(),
                key_id,
            }
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    write_private(
        &dir.join("identity.json"),
        &serde_json::to_vec(&file).map_err(|e| e.to_string())?,
    )?;
    store
        .create(&State::new(
            name,
            &sign_public,
            &ozbox_seal::public_to_hex(&key.public()),
        ))
        .map_err(|e| e.to_string())?;
    Ok(json!({"name": name}))
}

/// Replace a private file atomically: a new 0600 file beside it, then a rename over it.
fn replace_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("json.new");
    let _ = std::fs::remove_file(&tmp);
    write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| e.to_string())
}

fn str_arg<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(Value::as_str)
}

fn need<'a>(a: &'a Value, k: &str) -> Result<&'a str, String> {
    str_arg(a, k).ok_or_else(|| format!("missing:{k}"))
}

fn flag(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn refused(e: impl std::fmt::Display) -> String {
    format!("refused: {e}")
}

/// A task as a person or a program reads it. Text from a peer is **never** passed as if it were this end's own: each message says
/// where it came from (`provenance`), that it is `untrusted`, and what its sender `claimed_label`. With `for_model`, every piece of
/// peer-written text (the title, the message parts, the reason, the artifact names) is wrapped in one fenced untrusted block
/// with a fence the sender could not have known, so a model reads it as data.
pub fn task_view(st: &State, t: &Task, for_model: bool, writable_by_agents: bool) -> Value {
    let fence = random_fence();
    let peer_text = |s: &str, from_peer: bool| -> String {
        if for_model && from_peer {
            fenced("PEER TEXT", &fence, &printable(s))
        } else {
            printable(s)
        }
    };
    let from_peer = t.from != st.me();
    let msgs: Vec<Value> = t
        .messages
        .iter()
        .map(|m| {
            let parts: Vec<Value> = m
                .parts
                .iter()
                .map(|p| match p {
                    Part::Text { text } => json!({"type": "text", "text": peer_text(text, m.untrusted)}),
                    Part::Data { schema, json: j } => json!({
                        "type": "data",
                        "schema": printable_line(schema),
                        "json": if for_model && m.untrusted { Value::String(fenced("PEER TEXT", &fence, &printable(&j.to_string()))) } else { j.clone() },
                    }),
                })
                .collect();
            json!({
                "id": printable_line(&m.id),
                "from": printable_line(&m.from),
                "ts_ms": m.ts_ms,
                "provenance": if m.provenance.is_empty() { "unknown".to_string() } else { printable_line(&m.provenance) },
                "untrusted": m.untrusted || m.provenance.is_empty(),
                "claimed_label": m.label,
                "parts": parts,
            })
        })
        .collect();
    json!({
        "key": format!("{}/{}", t.from, t.id),
        "id": t.id,
        "from": printable_line(&t.from),
        "to": printable_line(&t.to),
        "kind": t.kind.name(),
        "state": t.state.name(),
        "reason": t.reason.as_deref().map(|r| peer_text(&printable_line(r), from_peer || t.state != TState::Held)),
        "title": if for_model && from_peer { Value::String(fenced("PEER TEXT", &fence, &printable_line(&t.title))) } else { Value::String(printable_line(&t.title)) },
        "unread": t.unread,
        "cancel_requested": t.cancel_requested,
        "created_ms": t.created_ms,
        "updated_ms": t.updated_ms,
        "messages": msgs,
        "artifacts": t.artifacts.iter().map(|a| json!({"name": if for_model { Value::String(fenced("PEER TEXT", &fence, &printable_line(&a.name))) } else { Value::String(printable_line(&a.name)) }, "hash": a.hash})).collect::<Vec<_>>(),
        // While the store sits where an agent's own user can write it, this says so: nothing in a task can then be told apart from
        // something an agent wrote straight into the file. A box runs the channel as a service user and this is false.
        "store_writable_by_agents": writable_by_agents,
    })
}

fn needs_you(me: &str, t: &Task) -> bool {
    t.unread || (t.to == me && !t.state.terminal())
}

fn parse_state(s: &str) -> Option<TState> {
    TState::parse(s).filter(|x| {
        matches!(
            x,
            TState::Working
                | TState::InputRequired
                | TState::Completed
                | TState::Failed
                | TState::Canceled
        )
    })
}

/// One operation. `Err` is a message that is safe to show: it names a code, never a secret or a peer's text.
pub fn dispatch(
    ends: &Ends,
    policy: Policy,
    req: &Value,
    writable_by_agents: bool,
) -> Result<Value, String> {
    let op = need(req, "op")?;
    // What each socket may do is a list of what it MAY, so an operation added later is closed to agents until someone opens it.
    let allowed = match (policy, op) {
        (Policy::Admin, _) => true,
        (Policy::Relay, "exchange") => true,
        (Policy::Relay, _) => false,
        (
            Policy::Agent,
            "identity" | "peers" | "inbox" | "task" | "send" | "push_ref" | "reply" | "cancel"
            | "why",
        ) => true,
        (Policy::Agent, _) => false,
    };
    if !allowed {
        return Err(err("not-allowed-here"));
    }
    // the guard refuses everything once the store looks restored from a backup, except the one thing that acknowledges it
    if op != "restored" {
        ends.guard()?;
    }
    let node = ends.node();
    match op {
        "identity" => {
            let st = ends.state()?;
            Ok(serde_json::to_value(Offer {
                name: st.me().to_string(),
                sign_public: st.sign_public().to_string(),
                seal_public: st.seal_public().to_string(),
                epoch: st.epoch(),
                sign_fingerprint: st.sign_fingerprint(),
                seal_fingerprint: st.seal_fingerprint(),
            })
            .map_err(|e| e.to_string())?)
        }
        "peers" => {
            let st = ends.state()?;
            serde_json::to_value(st.peers()).map_err(|e| e.to_string())
        }
        "inbox" => {
            let st = ends.state()?;
            let all = flag(req, "all");
            let for_model = flag(req, "for_model");
            let mut tasks: Vec<&Task> = st
                .tasks
                .values()
                .filter(|x| all || needs_you(st.me(), x))
                .collect();
            tasks.sort_by_key(|x| x.created_ms);
            Ok(Value::Array(
                tasks
                    .into_iter()
                    .map(|t| task_view(&st, t, for_model, writable_by_agents))
                    .collect(),
            ))
        }
        "task" => {
            let id = need(req, "id")?;
            let st = ends.state()?;
            let view = match st.find(id) {
                Ok(t) => task_view(&st, t, flag(req, "for_model"), writable_by_agents),
                Err(FindError::NoSuchTask) => return Err(err("unknown-task")),
                Err(FindError::Ambiguous(k)) => {
                    return Err(format!("ambiguous-id: name it as one of {}", k.join(", ")))
                }
            };
            // showing a task marks it read; if that cannot be written the person still sees the task
            let _ = ends.store().update(|s| s.mark_read(id));
            Ok(view)
        }
        "send" => {
            let to = need(req, "to")?.to_string();
            let now = now_ms();
            let minutes = req.get("minutes").and_then(Value::as_u64);
            let id = node
                .submit(NewTask {
                    to,
                    kind: if flag(req, "note") {
                        TaskKind::Note
                    } else {
                        TaskKind::Question
                    },
                    title: need(req, "title")?.to_string(),
                    parts: vec![Part::Text {
                        text: need(req, "text")?.to_string(),
                    }],
                    // an end never claims a person wrote it
                    label: Label::Fleet,
                    act: None,
                    parent: None,
                    deadline_ms: minutes
                        .map(|m| now.saturating_add(m.min(60 * 24 * 365).saturating_mul(60_000))),
                })
                .map_err(refused)?;
            Ok(json!({"id": id}))
        }
        "push_ref" => {
            let r = need(req, "ref")?;
            let id = node
                .submit(NewTask {
                    to: need(req, "to")?.to_string(),
                    kind: TaskKind::LaptopAct,
                    title: format!("push {}", printable_line(r)),
                    parts: vec![Part::Text {
                        text: "Please push this commit.".into(),
                    }],
                    label: Label::Fleet,
                    act: Some(Act::PushRef {
                        repo: need(req, "repo")?.to_string(),
                        remote: need(req, "remote")?.to_string(),
                        r#ref: r.to_string(),
                        sha: need(req, "sha")?.to_string(),
                        env: need(req, "env")?.to_string(),
                    }),
                    parent: None,
                    deadline_ms: None,
                })
                .map_err(refused)?;
            Ok(json!({"id": id}))
        }
        "reply" => {
            let id = need(req, "id")?;
            let text = str_arg(req, "text").unwrap_or("");
            let to_state = match str_arg(req, "state") {
                None => None,
                Some(s) => match parse_state(s) {
                    Some(x) => Some((x, str_arg(req, "reason").map(str::to_string))),
                    None => return Err(format!("bad-state:{s}")),
                },
            };
            if text.is_empty() && to_state.is_none() {
                return Err(err("text-needed"));
            }
            let parts = if text.is_empty() {
                Vec::new()
            } else {
                vec![Part::Text {
                    text: text.to_string(),
                }]
            };
            node.reply(id, parts, to_state).map_err(refused)?;
            Ok(json!({"id": id}))
        }
        "cancel" => {
            node.cancel(need(req, "id")?).map_err(refused)?;
            Ok(json!({"id": need(req, "id")?}))
        }
        "why" => {
            let st = ends.state()?;
            Ok(
                json!({"lines": st.why(need(req, "id")?, now_ms()).iter().map(|l| printable_line(l)).collect::<Vec<_>>()}),
            )
        }
        "exchange" => {
            let peer = need(req, "peer")?;
            let inbound: Vec<Sealed> = serde_json::from_str(need(req, "inbound")?)
                .map_err(|_| err("not a task channel request"))?;
            let (_, out) = node
                .serve(peer, &inbound)
                .map_err(|e| printable_line(&e.to_string()))?;
            Ok(json!({"outbound": serde_json::to_string(&out).map_err(|e| e.to_string())?}))
        }
        "pin" => {
            let offer: Offer =
                serde_json::from_value(req.get("offer").cloned().unwrap_or(Value::Null))
                    .map_err(|_| err("pin-bad"))?;
            let offer = offer.checked().ok_or_else(|| err("pin-bad"))?;
            let via: Option<Vec<String>> = req.get("via").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            });
            let st = ends.state()?;
            if offer.name == st.me() || offer.sign_public == st.sign_public() {
                return Err(err("pin-self"));
            }
            if let Some(old) = st.core.links.get(&offer.name) {
                let same = old.sign_key == offer.sign_public
                    && old.seal_key == offer.seal_public
                    && old.epoch == offer.epoch;
                if !same && !flag(req, "replace") {
                    return Err(format!("pin-exists:{}", offer.name));
                }
            }
            let now = now_ms();
            let change = ends
                .store()
                .update(|s| {
                    s.pin(
                        now,
                        &offer.name,
                        &offer.sign_public,
                        &offer.seal_public,
                        offer.epoch,
                        via,
                    )
                })
                .map_err(|e| e.to_string())?
                .map_err(|c| c.to_string())?;
            node.drain_audit().map_err(|e| e.to_string())?;
            Ok(json!({
                "name": offer.name,
                "keys_changed": change.keys_changed,
                "epoch_changed": change.epoch_changed,
                "via_changed": change.via_changed,
                "via": change.via,
            }))
        }
        "restored" => {
            node.restore().map_err(|e| e.to_string())?;
            Ok(json!({"epoch": ends.state()?.epoch()}))
        }
        _ => Err(err("unknown-op")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod key_home_tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    /// Every file under `dir`, as text, for a sentinel check.
    fn everything_in(dir: &Path) -> String {
        let mut all = String::new();
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                all.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
            }
        }
        all
    }

    fn keys_of(st: &MemorySecrets, dir: &Path) -> (String, String) {
        let id: IdentityFile =
            serde_json::from_slice(&std::fs::read(dir.join("identity.json")).unwrap()).unwrap();
        assert!(!id.key_id.is_empty());
        let (sn, en) = key_names(&id.key_id);
        (st.get(&sn).unwrap().unwrap(), st.get(&en).unwrap().unwrap())
    }

    #[test]
    fn on_a_laptop_the_private_keys_are_in_the_secret_store_and_in_no_file_or_answer() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("channel");
        let st = MemorySecrets::default();
        init(&dir, "laptop", KeyHome::Store(&st)).unwrap();
        let (sign, seal) = keys_of(&st, &dir);
        assert!(sign.len() > 64 && seal.len() == 64);
        let ends = Ends::open(&dir, KeyHome::Store(&st)).unwrap();
        // what the endpoint keeps about itself is public halves only (an answer is built from it)
        let said = serde_json::to_string(&ends.state().unwrap()).unwrap();
        let files = everything_in(&dir);
        for v in [&sign, &seal] {
            assert!(
                !files.contains(v.as_str()),
                "a private key is in a file of the channel"
            );
            assert!(
                !said.contains(v.as_str()),
                "a private key is in the endpoint's state"
            );
        }
        assert!(!files.contains("sign_pkcs8") && !files.contains("seal_secret"));
    }

    #[test]
    fn a_laptop_identity_written_with_its_keys_in_the_file_is_moved_to_the_store_and_the_file_loses_them(
    ) {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("channel");
        // the old shape: the keys in the file (what every laptop endpoint had before)
        init(&dir, "laptop", KeyHome::RouterFile).unwrap();
        let old: IdentityFile =
            serde_json::from_slice(&std::fs::read(dir.join("identity.json")).unwrap()).unwrap();
        let (sign, seal) = (old.sign_pkcs8.clone(), old.seal_secret.clone());
        assert!(!sign.is_empty() && !seal.is_empty());
        let st = MemorySecrets::default();
        let before = Ends::open(&dir, KeyHome::Store(&st)).unwrap();
        let ident = serde_json::to_string(&before.state().unwrap()).unwrap();
        // the same keys, now only in the store
        assert_eq!(keys_of(&st, &dir), (sign.clone(), seal.clone()));
        let files = everything_in(&dir);
        assert!(!files.contains(sign.as_str()) && !files.contains(seal.as_str()));
        assert!(!dir.join("identity.json.new").exists());
        // and it opens again from the store, as the same endpoint
        let after = Ends::open(&dir, KeyHome::Store(&st)).unwrap();
        assert_eq!(
            serde_json::to_string(&after.state().unwrap()).unwrap(),
            ident
        );
    }

    #[test]
    fn keys_missing_from_the_store_are_a_refusal_never_a_new_identity() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("channel");
        let st = MemorySecrets::default();
        init(&dir, "laptop", KeyHome::Store(&st)).unwrap();
        let other = MemorySecrets::default();
        assert!(Ends::open(&dir, KeyHome::Store(&other)).is_err());
        // the router's directory never reads keys from a store, and a store identity is not opened as a router file
        assert!(Ends::open(&dir, KeyHome::RouterFile).is_err());
    }

    #[test]
    fn a_store_that_cannot_keep_the_keys_leaves_no_identity_behind() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("channel");
        let st = crate::secrets::UnavailableSecrets("no keychain");
        assert!(init(&dir, "laptop", KeyHome::Store(&st)).is_err());
        assert!(!dir.join("identity.json").exists());
        assert!(!Store::<State>::new(&dir).exists());
    }
}
