//! The secrets service's end of the ingress route (ADR 0029, Amendment 6 section 3 and Amendment 9).
//!
//! The ingress socket is entered only by the secrets user and the `ozbox-ingress` account (see `ingress_guard`), and answers
//! two things:
//!
//! * `service_key`: the public half of this service's key, its fingerprint and the box it belongs to. A public key; the
//!   person's computer pins it and checks it on every later request.
//! * `sealed`: a request sealed to that key (HPKE, `ozbox-seal`) with the operation, the project, the environment, the box,
//!   the key's fingerprint, a time and a one-time id as authenticated data. The service opens it, checks the label against
//!   what was inside, and answers it as the same request would have been answered on a socket of its own, under
//!   [`Policy::Unsealed`]: the import, the policy, a signer's enrolment, an approval's challenge and signature, the
//!   first-time dashboard code, and the escrow of the store's key. Anything else is refused.
//!
//! So the bytes that carry a key or a signature are never readable by the process that relays them, a message made for one
//! box cannot be opened by another, one made for one operation cannot be replayed as another, and none can be replayed at all.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ozbox_seal::ServiceKey;
use serde_json::{json, Value};

use crate::secrets::{SecretError, SecretStore};
use crate::secrets_service::Gates;
use crate::serve::auth::b64::{decode_std, encode_std};

/// Where the service key's private half is kept: in the encrypted store, under a name the box socket can neither write nor
/// read, and the content scan skips.
pub const KEY_NAME: &str = "ingress-seal-key";
/// The envelope's version.
pub const VERSION: u64 = 1;
/// How far a request's time may be from the service's own (milliseconds), and so how long an id is remembered.
pub const WINDOW_MS: u64 = 5 * 60_000;
const MAX_SEEN: usize = 4096;

/// The longest request line (the newline included) the box reads on the ingress route: the ingress account's forced command
/// and the service's socket both stop here, and the laptop refuses to send a sealed line over it. One constant, so the three
/// cannot drift apart.
pub const MAX_LINE_BYTES: u64 = (1 << 20) + 4096;

/// The operations a sealed request may carry. Everything else is refused, whatever it is labelled.
pub const SEALED_OPS: &[&str] = &[
    "import",
    "capabilities",
    "policy",
    "approval_keys",
    "approval_key_enroll",
    "approval_key_revoke",
    "approval_challenge",
    "approval_redeem",
    "enrolled",
    "setup_code",
    "kek_export",
    // the approval requests (ADR 0041 phase 2): the laptop files, reads, waits, decides and withdraws over the sealed route
    "areq_capabilities",
    "areq_file",
    "areq_get",
    "areq_list",
    "areq_await",
    "areq_decide_challenge",
    "areq_decide",
    "areq_cancel",
    // a key's enrolment challenge, and the enrolment itself with its attestation
    "approval_key_enrol_challenge",
    // `ozbox chat lock|unlink --box`: a Telegram link made less able, for the dashboard to apply (ADR 0050 §1c)
    "chat_link_request",
];

pub fn is_reserved(name: &str) -> bool {
    name == KEY_NAME
}

/// The service key, the box it speaks for, and the ids it has already opened.
pub struct Ingress {
    key: ServiceKey,
    box_id: String,
    seen: Mutex<Vec<(String, u64)>>,
}

fn err(m: &str) -> SecretError {
    SecretError(m.to_string())
}

impl Ingress {
    /// The service key from the store, made (and stored) the first time. A key that is stored but damaged is an error, never
    /// replaced: a new key would silently invalidate every computer's pin.
    pub fn load_or_create(store: &dyn SecretStore, box_id: &str) -> Result<Ingress, SecretError> {
        let key = match store.get(KEY_NAME)? {
            Some(hex) => {
                let raw = unhex(hex.trim()).ok_or_else(|| err("the ingress key is damaged"))?;
                ServiceKey::from_secret_bytes(&raw)
                    .map_err(|_| err("the ingress key is damaged"))?
            }
            None => {
                let k = ServiceKey::generate().map_err(|e| err(&e.to_string()))?;
                let hex = hex(&k.secret_bytes()[..]);
                store.set(KEY_NAME, &hex)?;
                k
            }
        };
        Ok(Ingress {
            key,
            box_id: box_id.to_string(),
            seen: Mutex::new(Vec::new()),
        })
    }

    #[cfg(test)]
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint()
    }

    /// What `service_key` answers.
    pub fn describe(&self) -> Value {
        json!({
            "v": VERSION,
            "box": self.box_id,
            "public": ozbox_seal::public_to_hex(&self.key.public()),
            "fingerprint": self.key.fingerprint(),
            "suite": ozbox_seal::SUITE,
        })
    }

    /// The authenticated data of a request, in the order both ends use. Pure.
    pub fn aad_for(
        box_id: &str,
        fp: &str,
        iop: &str,
        project: &str,
        env: &str,
        ts: u64,
        id: &str,
    ) -> Vec<u8> {
        ozbox_seal::aad(&[
            "sealed/1",
            box_id,
            fp,
            iop,
            project,
            env,
            &ts.to_string(),
            id,
        ])
    }

    /// Open one sealed request: check its labels, its time and its id, open it, and check what was inside against the label.
    /// Returns the inner request as one line of JSON. The error is a sentence for a person and a code for a program.
    pub fn open(&self, v: &Value, now_ms: u64) -> Result<(String, String), (String, String)> {
        let bad = |code: &str, m: &str| (code.to_string(), m.to_string());
        let s = |k: &str| v[k].as_str().unwrap_or("");
        if v["v"].as_u64() != Some(VERSION) {
            return Err(bad(
                "version",
                "that request is sealed in a way this box does not read: update ozbox on this computer",
            ));
        }
        if s("box") != self.box_id {
            return Err(bad("wrong_box", "that request was sealed for another box"));
        }
        if s("fp") != self.key.fingerprint() {
            return Err(bad(
                "key_changed",
                "this box's key is not the one this computer pinned (the box's secrets store was made again, or this is not the same box): check that this is the box you meant, then pin the new key",
            ));
        }
        let (iop, project, env, id) = (s("iop"), s("project"), s("env"), s("id"));
        let ts = v["ts"].as_u64().unwrap_or(0);
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("bad_request", "that request is not valid"));
        }
        if ts.abs_diff(now_ms) > WINDOW_MS {
            return Err(bad(
                "clock",
                "that request is too old or too new: check this computer's clock and the box's",
            ));
        }
        if !SEALED_OPS.contains(&iop) {
            return Err(bad("not_allowed", "that is not allowed on this socket"));
        }
        {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|(_, t)| now_ms.saturating_sub(*t) <= WINDOW_MS);
            if seen.iter().any(|(i, _)| i == id) {
                return Err(bad("replayed", "that request was already used"));
            }
            if seen.len() >= MAX_SEEN {
                return Err(bad("busy", "too many requests: wait a minute"));
            }
            // remembered before it is opened: a request that fails to open cannot be tried again with the same id either
            seen.push((id.to_string(), now_ms));
        }
        let (enc, ct) = (
            decode_std(s("enc")).ok_or_else(|| bad("bad_request", "that request is not valid"))?,
            decode_std(s("ct")).ok_or_else(|| bad("bad_request", "that request is not valid"))?,
        );
        let aad = Self::aad_for(
            &self.box_id,
            &self.key.fingerprint(),
            iop,
            project,
            env,
            ts,
            id,
        );
        let plain = self
            .key
            .open(&ozbox_seal::info("ingress", &self.box_id), &aad, &enc, &ct)
            .map_err(|_| {
                bad(
                    "cannot_open",
                    "that request could not be opened: it was changed on the way",
                )
            })?;
        let line = String::from_utf8(plain.to_vec())
            .map_err(|_| bad("bad_request", "that request is not valid"))?;
        // what was sealed must be what the label says, or a relay could pair a label it likes with a body it was handed
        let inner: Value = serde_json::from_str(&line)
            .map_err(|_| bad("bad_request", "that request is not valid"))?;
        let same = inner["op"].as_str() == Some(iop)
            && inner["project"].as_str().unwrap_or("") == project
            && inner["env"].as_str().unwrap_or("") == env;
        if !same {
            return Err(bad(
                "label_mismatch",
                "that request does not match its label",
            ));
        }
        Ok((line, iop.to_string()))
    }
}

/// Answer one line on the ingress socket. `dispatch` answers the opened request as a socket of its own would, under
/// [`Policy::Unsealed`].
pub fn handle_outer(
    store: &dyn SecretStore,
    gates: &Gates,
    line: &str,
    now_ms: u64,
    dispatch: &dyn Fn(&str) -> String,
) -> String {
    let fail = |code: &str, m: &str| json!({"ok": false, "error": m, "code": code}).to_string();
    let Some(ing) = gates.ingress.get() else {
        return fail(
            "no_ingress",
            "this box's secrets service has no ingress key",
        );
    };
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return fail("bad_request", "that request is not valid");
    };
    match v["op"].as_str().unwrap_or("") {
        "service_key" => json!({"ok": true, "result": ing.describe()}).to_string(),
        "sealed" => match ing.open(&v, now_ms) {
            Ok((inner, iop)) => {
                let out = dispatch(&inner);
                gates.audit_event(store, "secrets.ingress.request", &iop, "sealed=yes");
                out
            }
            Err((code, m)) => {
                gates.audit_event(store, "secrets.ingress.refused", "", &format!("why={code}"));
                fail(&code, &m)
            }
        },
        _ => fail("not_allowed", "that is not allowed on this socket"),
    }
}

/// The first-time dashboard code the supervisor handed over, with when it stops being good (milliseconds).
#[derive(Default)]
pub struct SetupCode(Mutex<Option<(zeroize::Zeroizing<String>, u64)>>);

impl SetupCode {
    pub fn put(&self, code: &str, expires_ms: u64, now_ms: u64) -> Result<(), &'static str> {
        let shaped = code.len() <= 32
            && !code.is_empty()
            && code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !shaped || expires_ms <= now_ms || expires_ms - now_ms > 60 * 60_000 {
            return Err("that setup code is not valid");
        }
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((zeroize::Zeroizing::new(code.to_string()), expires_ms));
        Ok(())
    }

    pub fn get(&self, now_ms: u64) -> Option<String> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_ref() {
            Some((c, exp)) if *exp > now_ms => Some(c.to_string()),
            Some(_) => {
                *g = None;
                None
            }
            None => None,
        }
    }
}

/// Telegram links the owner's computer asked, over the sealed route, to lock or cut: held until the dashboard takes them. Only
/// `lock:<link>`, `unlink:<link>`, `lock:*` and `unlink:*` are kept, so a request here can only make a chat less able.
#[derive(Default)]
pub struct ChatLinkRequests(Mutex<Vec<(String, u64)>>);

/// The most requests held at once.
const CHAT_LINK_REQUESTS_MAX: usize = 50;

impl ChatLinkRequests {
    pub fn shaped(v: &str) -> bool {
        let Some((act, link)) = v.split_once(':') else {
            return false;
        };
        matches!(act, "lock" | "unlink")
            && (link == "*"
                || (!link.is_empty()
                    && link.len() <= 64
                    && link
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')))
    }

    pub fn put(&self, v: &str, now_ms: u64) -> Result<(), &'static str> {
        if !Self::shaped(v) {
            return Err("that is not a lock or an unlink of a link");
        }
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= CHAT_LINK_REQUESTS_MAX {
            return Err("too many requests are waiting for the dashboard");
        }
        g.push((v.to_string(), now_ms));
        Ok(())
    }

    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .map(|(v, _)| v)
            .collect()
    }
}

/// The lock and unlink requests waiting for this dashboard, taken from the secrets service (once each). Only on a box whose
/// dashboard runs as the supervisor (the unit sets the socket); anywhere else, none.
#[cfg(unix)]
pub fn take_chat_link_requests() -> Vec<String> {
    let Some(sock) = std::env::var_os("OZBOX_SUPERVISOR_SOCKET").filter(|p| !p.is_empty()) else {
        return Vec::new();
    };
    crate::secrets_service::SocketSecrets::new(PathBuf::from(sock))
        .call(json!({"op": "chat_link_take"}))
        .ok()
        .and_then(|v| v["value"].as_str().map(str::to_string))
        .map(|s| {
            s.lines()
                .filter(|l| ChatLinkRequests::shaped(l))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(unix))]
pub fn take_chat_link_requests() -> Vec<String> {
    Vec::new()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// How long the dashboard's first-time code lasts (30 minutes), as the dashboard says.
pub const SETUP_CODE_MS: u64 = 30 * 60_000;

/// Give the supervisor's first-time code to the secrets service, to be read back only through the ingress route. True when
/// the service took it. Only on a box whose dashboard runs as the supervisor user (the unit sets the socket); anywhere else
/// it does nothing, and the caller prints the code on its own console as before.
#[cfg(unix)]
pub fn hand_over_setup_code(code: &str, now_ms: u64) -> bool {
    let Some(sock) = std::env::var_os("OZBOX_SUPERVISOR_SOCKET").filter(|p| !p.is_empty()) else {
        return false;
    };
    crate::secrets_service::SocketSecrets::new(PathBuf::from(sock))
        .call(json!({"op": "setup_code_put", "value": code, "msg": (now_ms + SETUP_CODE_MS).to_string()}))
        .is_ok()
}

#[cfg(not(unix))]
pub fn hand_over_setup_code(_: &str, _: u64) -> bool {
    false
}

/// What happened to a store key waiting in the inbox at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbox {
    /// There was none.
    Empty,
    /// It was used: the store's key file is back.
    Placed,
    /// It was removed and not used (the key was not the store's, was not a key, or the box did not need one).
    Discarded,
}

/// The store's key, placed by its owner through the ingress account while the service was down (`ozbox upgrade` puts a
/// key kept in the owner's keychain back this way). Used only when the box keeps its key in a file, the store is there and
/// the file is not, and only when the key really opens that store; **always removed**, so a stale one never lingers. `opens`
/// says whether a key text opens the store. Pure apart from the files.
pub fn take_inbox(
    inbox: &Path,
    key_file: &Path,
    needed: bool,
    opens: &dyn Fn(&str) -> bool,
) -> Inbox {
    let file = inbox.join("kek");
    let Ok(meta) = std::fs::symlink_metadata(&file) else {
        return Inbox::Empty;
    };
    let text = if meta.is_file() && meta.len() <= 4096 {
        std::fs::read_to_string(&file).ok()
    } else {
        None
    };
    let _ = std::fs::remove_file(&file);
    let Some(text) = text.map(zeroize::Zeroizing::new) else {
        return Inbox::Discarded;
    };
    if !needed || key_file.exists() || !opens(text.trim()) {
        return Inbox::Discarded;
    }
    use std::io::Write;
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(key_file)
    };
    #[cfg(not(unix))]
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(key_file);
    match opened.and_then(|mut f| {
        f.write_all(text.trim().as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    }) {
        Ok(()) => Inbox::Placed,
        Err(_) => Inbox::Discarded,
    }
}

/// Where the inbox is (`OZBOX_KEK_INBOX` for a test; the ingress account's folder otherwise).
pub fn inbox_dir() -> PathBuf {
    std::env::var_os("OZBOX_KEK_INBOX")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::ingress_guard::KEK_INBOX))
}

/// Whether `kek_text` opens the store at `store_path`: it opens every secret in it (an empty store is opened by any key).
pub fn kek_opens_store(store_path: &Path, scope: &str, kek_text: &str) -> bool {
    use crate::secrets_enc::{EncryptedSecrets, LocalKekProvider};
    let Ok(p) = LocalKekProvider::from_text("file", kek_text) else {
        return false;
    };
    let Ok(s) = EncryptedSecrets::new(
        store_path.to_path_buf(),
        scope,
        std::sync::Arc::new(p) as std::sync::Arc<dyn crate::secrets_enc::KeyProvider>,
    ) else {
        return false;
    };
    match s.names("") {
        Ok(names) => names.iter().all(|n| matches!(s.get(n), Ok(Some(_)))),
        Err(_) => false,
    }
}

/// Put the owner's copy of the store's key in the inbox, for the secrets service to use when it starts. Runs as the ingress
/// account, which can write the inbox and cannot read the store. Refused when the service is up (it already has its key, and
/// would ignore this), when the text is not a key, and when the inbox is not there.
pub fn place_kek(inbox: &Path, kek: &str, service_up: bool) -> Result<(), String> {
    if service_up {
        return Err(
            "the secrets service is running, so it has its key: nothing was placed".to_string(),
        );
    }
    if kek.len() > 4096
        || crate::secrets_enc::LocalKekProvider::from_text("file", kek.trim()).is_err()
    {
        return Err("that is not a store key".to_string());
    }
    if !inbox.is_dir() {
        return Err("this box has no place for a key to wait: it was made before the ingress account (rebuild it, or run `ozbox upgrade`)".to_string());
    }
    let tmp = inbox.join(".kek.tmp");
    let target = inbox.join("kek");
    #[cfg(unix)]
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(&tmp)
    };
    #[cfg(not(unix))]
    let f = std::fs::File::create(&tmp);
    use std::io::Write;
    f.and_then(|mut f| {
        f.write_all(kek.trim().as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    })
    .and_then(|()| std::fs::rename(&tmp, &target))
    .map_err(|_| "the key could not be placed".to_string())
}

/// Seal a request the way the person's computer does, for the tests of this and the laptop's module. Pure.
pub fn seal_request(
    public: &[u8; 32],
    box_id: &str,
    fp: &str,
    inner: &Value,
    ts: u64,
    id: &str,
) -> Result<Value, String> {
    let iop = inner["op"].as_str().unwrap_or("");
    let project = inner["project"].as_str().unwrap_or("");
    let env = inner["env"].as_str().unwrap_or("");
    let aad = Ingress::aad_for(box_id, fp, iop, project, env, ts, id);
    let (enc, ct) = ozbox_seal::seal(
        public,
        &ozbox_seal::info("ingress", box_id),
        &aad,
        inner.to_string().as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    Ok(
        json!({"op": "sealed", "v": VERSION, "box": box_id, "fp": fp, "iop": iop,
        "project": project, "env": env, "ts": ts, "id": id,
        "enc": encode_std(&enc), "ct": encode_std(&ct)}),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    const NOW: u64 = 1_800_000_000_000;
    const ID: &str = "00112233445566778899aabbccddeeff";

    fn ing() -> (Ingress, MemorySecrets) {
        let s = MemorySecrets::default();
        (Ingress::load_or_create(&s, "dev").unwrap(), s)
    }
    fn pubkey(i: &Ingress) -> [u8; 32] {
        ozbox_seal::public_from_hex(i.describe()["public"].as_str().unwrap()).unwrap()
    }
    fn req(i: &Ingress, inner: Value, id: &str, ts: u64) -> Value {
        seal_request(&pubkey(i), "dev", &i.fingerprint(), &inner, ts, id).unwrap()
    }
    fn import() -> Value {
        json!({"op": "import", "project": "app", "env": "staging", "lines": [{"name": "K", "value": "SENTINEL-ing-0123456789"}]})
    }

    #[test]
    fn the_key_is_made_once_kept_in_the_store_and_the_same_key_comes_back() {
        let s = MemorySecrets::default();
        let a = Ingress::load_or_create(&s, "dev").unwrap();
        assert!(s.get(KEY_NAME).unwrap().is_some());
        let b = Ingress::load_or_create(&s, "dev").unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        // a damaged key is an error, never replaced by a new one that would break every pin
        s.set(KEY_NAME, "nothex").unwrap();
        assert!(Ingress::load_or_create(&s, "dev").is_err());
        assert_eq!(s.get(KEY_NAME).unwrap().unwrap(), "nothex");
        assert!(is_reserved(KEY_NAME) && !is_reserved("email-api-key"));
    }

    #[test]
    fn a_sealed_request_opens_and_the_value_is_not_in_what_travels() {
        let (i, _) = ing();
        let r = req(&i, import(), ID, NOW);
        assert!(!r.to_string().contains("SENTINEL-ing"));
        let (line, iop) = i.open(&r, NOW).unwrap();
        assert_eq!(iop, "import");
        assert!(line.contains("SENTINEL-ing-0123456789"));
    }

    #[test]
    fn a_request_cannot_be_moved_to_another_box_key_operation_project_or_environment() {
        let (i, _) = ing();
        let (other, _) = ing();
        let r = req(&i, import(), ID, NOW);
        // another box's service, with the same box name and a different key
        assert_eq!(other.open(&r, NOW).unwrap_err().0, "key_changed");
        // each change is made to a request of its own: an id is spent by the first try
        for (n, (k, v, code)) in [
            ("box", "other", "wrong_box"),
            ("iop", "policy", "cannot_open"),
            ("project", "evil", "cannot_open"),
            ("env", "prod", "cannot_open"),
            ("ts", "x", "cannot_open"),
        ]
        .into_iter()
        .enumerate()
        {
            let mut m = req(&i, import(), &format!("{:032x}", n + 1), NOW);
            m[k] = if k == "ts" { json!(NOW + 1) } else { json!(v) };
            assert_eq!(i.open(&m, NOW).unwrap_err().0, code, "changing {k}");
        }
        // a label the body does not match: sealed as import, labelled by the body of another project
        let sneaky = seal_request(
            &pubkey(&i),
            "dev",
            &i.fingerprint(),
            &json!({"op": "import", "project": "evil", "env": "staging"}),
            NOW,
            "ffeeddccbbaa99887766554433221100",
        )
        .unwrap();
        let mut m = sneaky.clone();
        m["project"] = json!("app");
        assert_eq!(i.open(&m, NOW).unwrap_err().0, "cannot_open");
    }

    #[test]
    fn a_request_is_used_once_and_only_inside_the_window() {
        let (i, _) = ing();
        let r = req(&i, import(), ID, NOW);
        assert!(i.open(&r, NOW).is_ok());
        assert_eq!(i.open(&r, NOW + 1).unwrap_err().0, "replayed");
        let old = req(
            &i,
            import(),
            "11112222333344445555666677778888",
            NOW - WINDOW_MS - 1,
        );
        assert_eq!(i.open(&old, NOW).unwrap_err().0, "clock");
        let future = req(
            &i,
            import(),
            "99992222333344445555666677778888",
            NOW + WINDOW_MS + 1,
        );
        assert_eq!(i.open(&future, NOW).unwrap_err().0, "clock");
        // an id is remembered only for the window: after it, the cache does not grow without end
        let again = req(&i, import(), ID, NOW + WINDOW_MS + 10);
        assert!(i.open(&again, NOW + WINDOW_MS + 10).is_ok());
        let short = req(&i, import(), "abc", NOW);
        assert_eq!(i.open(&short, NOW).unwrap_err().0, "bad_request");
    }

    #[test]
    fn only_the_listed_operations_can_be_sealed_and_a_damaged_message_is_refused() {
        let (i, _) = ing();
        for op in ["get", "set", "audit_checkpoint", "box_load", "recover"] {
            let r = req(
                &i,
                json!({"op": op}),
                "aaaa2222333344445555666677778888",
                NOW,
            );
            assert_eq!(i.open(&r, NOW).unwrap_err().0, "not_allowed", "{op}");
        }
        let mut r = req(&i, import(), "bbbb2222333344445555666677778888", NOW);
        let mut ct = decode_std(r["ct"].as_str().unwrap()).unwrap();
        ct[3] ^= 1;
        r["ct"] = json!(encode_std(&ct));
        assert_eq!(i.open(&r, NOW).unwrap_err().0, "cannot_open");
        let mut r = req(&i, import(), "cccc2222333344445555666677778888", NOW);
        r["v"] = json!(2);
        assert_eq!(i.open(&r, NOW).unwrap_err().0, "version");
    }

    #[test]
    fn the_outer_socket_answers_the_public_key_and_sealed_requests_and_nothing_else() {
        let (i, store) = ing();
        let gates = Gates::default();
        let _ = gates.ingress.set(std::sync::Arc::new(i));
        let i = gates.ingress.get().unwrap();
        let echo = |line: &str| json!({"ok": true, "saw": line.len()}).to_string();
        let a: Value = serde_json::from_str(&handle_outer(
            &store,
            &gates,
            r#"{"op":"service_key"}"#,
            NOW,
            &echo,
        ))
        .unwrap();
        assert_eq!(a["result"]["box"], "dev");
        assert_eq!(a["result"]["fingerprint"], i.fingerprint());
        // the private half is nowhere in the answer
        assert!(!a
            .to_string()
            .contains(&store.get(KEY_NAME).unwrap().unwrap()));
        let sealed = req(i, import(), ID, NOW).to_string();
        let ok: Value =
            serde_json::from_str(&handle_outer(&store, &gates, &sealed, NOW, &echo)).unwrap();
        assert_eq!(ok["ok"], true);
        for plain in [
            r#"{"op":"import","project":"a","env":"b","lines":[]}"#,
            r#"{"op":"get","name":"x"}"#,
            "not json",
        ] {
            let r: Value =
                serde_json::from_str(&handle_outer(&store, &gates, plain, NOW, &echo)).unwrap();
            assert_eq!(r["ok"], false, "{plain}");
        }
        // a replay of the sealed request is refused with a code
        let r: Value =
            serde_json::from_str(&handle_outer(&store, &gates, &sealed, NOW, &echo)).unwrap();
        assert_eq!(r["code"], "replayed");
    }

    #[test]
    fn a_service_with_no_ingress_key_says_so() {
        let store = MemorySecrets::default();
        let r: Value = serde_json::from_str(&handle_outer(
            &store,
            &Gates::default(),
            r#"{"op":"service_key"}"#,
            NOW,
            &|_| String::new(),
        ))
        .unwrap();
        assert_eq!(r["code"], "no_ingress");
    }

    #[test]
    fn the_setup_code_is_held_until_it_expires_and_a_bad_one_is_refused() {
        let c = SetupCode::default();
        assert!(c.get(NOW).is_none());
        c.put("ABCDE-23456", NOW + 1000, NOW).unwrap();
        assert_eq!(c.get(NOW).as_deref(), Some("ABCDE-23456"));
        assert!(c.get(NOW + 1000).is_none());
        assert!(c.get(NOW).is_none(), "an expired code is forgotten");
        for (code, exp) in [
            ("", NOW + 5),
            ("has space", NOW + 5),
            ("A", NOW),
            ("A", NOW + 10 * 3_600_000),
        ] {
            assert!(c.put(code, exp, NOW).is_err());
        }
    }

    #[test]
    fn an_inbox_key_is_used_only_when_needed_and_it_opens_the_store_and_is_always_removed() {
        let d = tempfile::tempdir().unwrap();
        let inbox = d.path().join("inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let key = d.path().join("kek.key");
        let put = |t: &str| std::fs::write(inbox.join("kek"), t).unwrap();
        let yes = |_: &str| true;
        assert_eq!(take_inbox(&inbox, &key, true, &yes), Inbox::Empty);
        // used: needed, the file is absent, and the key opens the store
        put("KEKTEXT\n");
        assert_eq!(take_inbox(&inbox, &key, true, &yes), Inbox::Placed);
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "KEKTEXT\n");
        assert!(!inbox.join("kek").exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // a live key is never replaced
        put("OTHER");
        assert_eq!(take_inbox(&inbox, &key, true, &yes), Inbox::Discarded);
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "KEKTEXT\n");
        assert!(!inbox.join("kek").exists());
        std::fs::remove_file(&key).unwrap();
        // not needed (the box keeps its key elsewhere), a key that does not open the store, an oversize file
        put("KEKTEXT");
        assert_eq!(take_inbox(&inbox, &key, false, &yes), Inbox::Discarded);
        put("WRONG");
        assert_eq!(take_inbox(&inbox, &key, true, &|_| false), Inbox::Discarded);
        std::fs::write(inbox.join("kek"), vec![b'a'; 5000]).unwrap();
        assert_eq!(take_inbox(&inbox, &key, true, &yes), Inbox::Discarded);
        assert!(!key.exists() && !inbox.join("kek").exists());
        // a link is not followed
        std::os::unix::fs::symlink("/etc/hosts", inbox.join("kek")).unwrap();
        assert_eq!(take_inbox(&inbox, &key, true, &yes), Inbox::Discarded);
        assert!(!key.exists());
    }

    #[test]
    fn a_key_is_placed_only_while_the_service_is_down_and_only_if_it_is_a_key() {
        use crate::secrets_enc::LocalKekProvider;
        let d = tempfile::tempdir().unwrap();
        let kek = LocalKekProvider::random("file")
            .unwrap()
            .kek_text()
            .to_string();
        assert!(place_kek(d.path(), &kek, true)
            .unwrap_err()
            .contains("running"));
        assert!(place_kek(d.path(), "not a key", false).is_err());
        assert!(place_kek(&d.path().join("missing"), &kek, false).is_err());
        assert!(!d.path().join("kek").exists());
        place_kek(d.path(), &kek, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("kek"))
                .unwrap()
                .trim(),
            kek.trim()
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(d.path().join("kek"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        // what was placed is what the service takes, once
        let key = d.path().join("kek.key");
        assert_eq!(take_inbox(d.path(), &key, true, &|_| true), Inbox::Placed);
    }

    #[test]
    fn a_key_opens_a_store_only_if_it_is_the_stores_own() {
        use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("secrets.json");
        let p = LocalKekProvider::random("file").unwrap();
        let text = p.kek_text().to_string();
        let store = EncryptedSecrets::new(
            path.clone(),
            "dev",
            std::sync::Arc::new(p) as std::sync::Arc<dyn KeyProvider>,
        )
        .unwrap();
        store.set("a-secret", "value").unwrap();
        assert!(kek_opens_store(&path, "dev", &text));
        let other = LocalKekProvider::random("file")
            .unwrap()
            .kek_text()
            .to_string();
        assert!(!kek_opens_store(&path, "dev", &other));
        assert!(!kek_opens_store(&path, "dev", "not a key"));
    }

    // ---- end to end through the service's own handler and a real socket ----

    fn service() -> (
        tempfile::TempDir,
        std::sync::Arc<crate::secrets_enc::EncryptedSecrets>,
        std::sync::Arc<Gates>,
    ) {
        use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
        let d = tempfile::tempdir().unwrap();
        let p: std::sync::Arc<dyn KeyProvider> =
            std::sync::Arc::new(LocalKekProvider::random("file").unwrap());
        let store =
            std::sync::Arc::new(EncryptedSecrets::new(d.path().join("s.json"), "dev", p).unwrap());
        let gates = std::sync::Arc::new(Gates::default());
        let ing = Ingress::load_or_create(store.as_ref(), "dev").unwrap();
        let _ = gates.ingress.set(std::sync::Arc::new(ing));
        (d, store, gates)
    }

    fn mac(
        store: &std::sync::Arc<crate::secrets_enc::EncryptedSecrets>,
    ) -> crate::tokenmac::TokenMac {
        crate::tokenmac::TokenMac::new(store.clone() as std::sync::Arc<dyn SecretStore>)
    }

    #[test]
    fn a_sealed_import_over_the_ingress_policy_stores_the_key_and_the_box_users_socket_cannot_do_it(
    ) {
        use crate::secrets_service::{handle_from, Policy};
        let (_d, store, gates) = service();
        let mac = mac(&store);
        let ing = gates.ingress.get().unwrap().clone();
        let sealed = req(&ing, import(), ID, crate::tokenmac::now_ms()).to_string();
        let out = handle_from(&store, &mac, &gates, Policy::Ingress, None, &sealed);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], true, "{out}");
        assert_eq!(v["names"], json!(["K"]));
        assert!(!out.contains("SENTINEL-ing"));
        // the value is in the store, under the project's name, and nowhere in the answer
        assert!(store
            .names("workload")
            .unwrap()
            .iter()
            .any(|n| n.ends_with(".K")));
        // the same words, unsealed, on the box user's import socket or on the outer ingress socket: refused
        for p in [
            Policy::Import,
            Policy::Ingress,
            Policy::Box,
            Policy::BoxLocked,
        ] {
            let o = handle_from(&store, &mac, &gates, p, None, &import().to_string());
            assert!(
                o.contains("\"ok\":false"),
                "{p:?} took an unsealed import: {o}"
            );
        }
        // the answer is audited by name and operation only
        let a: Value = serde_json::from_str(&handle_from(
            &store,
            &mac,
            &gates,
            Policy::Ingress,
            None,
            r#"{"op":"service_key"}"#,
        ))
        .unwrap();
        assert_eq!(a["ok"], true);
    }

    #[test]
    fn the_setup_code_goes_in_on_the_supervisor_socket_and_comes_out_only_sealed_and_once_valid() {
        use crate::secrets_service::{handle_from, Policy};
        let (_d, store, gates) = service();
        let mac = mac(&store);
        let ing = gates.ingress.get().unwrap().clone();
        let now = crate::tokenmac::now_ms();
        let ask_code = |id: &str| {
            let r = req(&ing, json!({"op": "setup_code"}), id, now).to_string();
            serde_json::from_str::<Value>(&handle_from(
                &store,
                &mac,
                &gates,
                Policy::Ingress,
                None,
                &r,
            ))
            .unwrap()
        };
        assert_eq!(
            ask_code("aaaa0000bbbb1111cccc2222dddd3333")["ok"],
            false,
            "none yet"
        );
        // only the supervisor may put one in
        let put = json!({"op": "setup_code_put", "value": "ABCDE-23456", "msg": (now + 60_000).to_string()}).to_string();
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Import,
            Policy::Ingress,
            Policy::Unsealed,
            Policy::Runner,
        ] {
            let o = handle_from(&store, &mac, &gates, p, None, &put);
            assert!(o.contains("\"ok\":false"), "{p:?}: {o}");
        }
        let o: Value = serde_json::from_str(&handle_from(
            &store,
            &mac,
            &gates,
            Policy::Supervisor,
            None,
            &put,
        ))
        .unwrap();
        assert_eq!(o["ok"], true);
        // and nothing but a sealed request reads it back
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Import,
            Policy::Supervisor,
            Policy::Runner,
            Policy::Ingress,
        ] {
            let o = handle_from(&store, &mac, &gates, p, None, r#"{"op":"setup_code"}"#);
            assert!(!o.contains("ABCDE-23456"), "{p:?} read the code: {o}");
        }
        assert_eq!(
            ask_code("bbbb0000bbbb1111cccc2222dddd3333")["value"],
            "ABCDE-23456"
        );
    }

    #[test]
    fn the_store_key_is_exported_only_sealed_only_for_a_file_kept_key_and_only_to_the_owner() {
        use crate::secrets_service::{handle_from, Policy};
        let (d, store, gates) = service();
        let mac = mac(&store);
        let ing = gates.ingress.get().unwrap().clone();
        let now = crate::tokenmac::now_ms();
        let ask = |id: &str| {
            let r = req(&ing, json!({"op": "kek_export"}), id, now).to_string();
            serde_json::from_str::<Value>(&handle_from(
                &store,
                &mac,
                &gates,
                Policy::Ingress,
                None,
                &r,
            ))
            .unwrap()
        };
        // a box whose key is not in a file has nothing to escrow
        assert_eq!(ask("cccc0000bbbb1111cccc2222dddd3333")["ok"], false);
        let key = d.path().join("kek.key");
        std::fs::write(&key, "KEK-SENTINEL-abcdef\n").unwrap();
        let _ = gates.kek_file.set(key);
        // before any second factor exists the SSH key alone does not take the store key
        let early = ask("dddd0000bbbb1111cccc2222dddd3333");
        assert_eq!(early["ok"], false, "{early}");
        assert!(!early.to_string().contains("SENTINEL"));
        store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let code = gates
            .approvals
            .mint("kek-export", "", "", "dashboard-stepup", now, 60_000)
            .unwrap();
        let ask = |id: &str| {
            let r = req(&ing, json!({"op": "kek_export", "approval": code}), id, now).to_string();
            serde_json::from_str::<Value>(&handle_from(
                &store,
                &mac,
                &gates,
                Policy::Ingress,
                None,
                &r,
            ))
            .unwrap()
        };
        assert_eq!(
            ask("dddd0000bbbb1111cccc2222dddd3334")["value"],
            "KEK-SENTINEL-abcdef"
        );
        // not on any other socket, and not unsealed
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Import,
            Policy::Supervisor,
            Policy::Runner,
            Policy::Ingress,
        ] {
            let o = handle_from(&store, &mac, &gates, p, None, r#"{"op":"kek_export"}"#);
            assert!(!o.contains("KEK-SENTINEL"), "{p:?}: {o}");
        }
    }

    /// the SSH key alone (the ingress account's) is not enough to take the store key or the first-time code once the
    /// box has a second factor: each needs an approval from the owner's approval key, spent once.
    #[test]
    fn once_a_second_factor_exists_the_store_key_and_the_setup_code_need_an_approval_good_once() {
        use crate::secrets_service::{handle_from, Policy};
        let (d, store, gates) = service();
        let mac = mac(&store);
        let ing = gates.ingress.get().unwrap().clone();
        let now = crate::tokenmac::now_ms();
        let key = d.path().join("kek.key");
        std::fs::write(&key, "KEK-SENTINEL-abcdef\n").unwrap();
        let _ = gates.kek_file.set(key);
        // the supervisor hands a setup code over
        let put = json!({"op": "setup_code_put", "value": "ABCDE-23456", "msg": (now + 60_000).to_string()}).to_string();
        assert!(
            handle_from(&store, &mac, &gates, Policy::Supervisor, None, &put)
                .contains("\"ok\":true")
        );
        store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let ask = |op: &str, approval: &str, id: &str| -> Value {
            let r = req(&ing, json!({"op": op, "approval": approval}), id, now).to_string();
            serde_json::from_str(&handle_from(
                &store,
                &mac,
                &gates,
                Policy::Ingress,
                None,
                &r,
            ))
            .unwrap()
        };
        for (op, scope, id) in [
            ("kek_export", "kek-export", "f1f1"),
            ("setup_code", "setup-code", "f2f2"),
        ] {
            let id1 = format!("{id}{:028}", 1);
            let no = ask(op, "", &id1);
            assert_eq!(no["ok"], false, "{op} with no approval: {no}");
            assert!(!no.to_string().contains("SENTINEL") && !no.to_string().contains("ABCDE"));
            // an approval for another scope does not do
            let other = gates
                .approvals
                .mint("import", "app", "dev", "dashboard-stepup", now, 60_000)
                .unwrap();
            assert_eq!(ask(op, &other, &format!("{id}{:028}", 2))["ok"], false);
            let code = gates
                .approvals
                .mint(scope, "", "", "dashboard-stepup", now, 60_000)
                .unwrap();
            let yes = ask(op, &code, &format!("{id}{:028}", 3));
            assert_eq!(yes["ok"], true, "{op}: {yes}");
            // good once
            assert_eq!(ask(op, &code, &format!("{id}{:028}", 4))["ok"], false);
        }
    }

    #[test]
    fn a_real_ingress_socket_answers_the_public_key_and_a_sealed_import_and_refuses_the_rest() {
        use crate::secrets_service::{listen, serve_gates, Policy};
        use std::io::{BufRead, Write};
        let (d, store, gates) = service();
        let sock = d.path().join("ingress/ingress.sock");
        let l = listen(&sock, 0o750).unwrap();
        let ing = gates.ingress.get().unwrap().clone();
        let g2 = gates.clone();
        let s2 = store.clone();
        std::thread::spawn(move || serve_gates(s2, vec![(l, Policy::Ingress)], None, g2));
        let ask = |line: &str| -> Value {
            let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
            c.write_all(format!("{line}\n").as_bytes()).unwrap();
            let mut out = String::new();
            std::io::BufReader::new(&c).read_line(&mut out).unwrap();
            serde_json::from_str(&out).unwrap()
        };
        let k = ask(r#"{"op":"service_key"}"#);
        assert_eq!(k["result"]["fingerprint"], ing.fingerprint());
        let r = ask(&req(
            &ing,
            import(),
            "eeee0000bbbb1111cccc2222dddd3333",
            crate::tokenmac::now_ms(),
        )
        .to_string());
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["names"], json!(["K"]));
        assert_eq!(ask(r#"{"op":"set","name":"x","value":"y"}"#)["ok"], false);
        assert_eq!(ask(r#"{"op":"names","prefix":""}"#)["ok"], false);
    }
}
