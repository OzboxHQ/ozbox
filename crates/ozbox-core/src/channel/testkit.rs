//! Test doubles for the channel: a tiny profile and state, a fake sealer and the real HPKE one, an audit sink, and a network that
//! can drop, duplicate and reorder. Signatures are real Ed25519.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Mutex;

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::audit::{change, drain, AuditSink, HasCore};
use super::flow::{receive_round, seal_drafts, RoundReport};
use super::ring_crypto::{generate, RingSigner, RingVerifier};
use super::session::{Core, DraftOpts, Link};
use super::store::Store;
use super::wire::{fingerprint, hex, unhex, Crypto, Profile, Sealed, Sealer, WireError};
use crate::audit::NewEvent;

pub static TEST_PROFILE: Profile = Profile {
    tag: "ozbox-test-channel",
    audit: "test",
    kinds: &["note", "ask"],
    max_body: 4096,
    check_ext: |_, ext| ext.len() <= 64,
};

/// The state a test end keeps beside the core: what was applied, in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TState {
    pub core: Core,
    pub applied: Vec<String>,
}

impl HasCore for TState {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}

pub struct FakeSealer {
    pub me: String,
}

fn pad(aad: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut c = 0u32;
    while out.len() < n {
        let mut v = aad.to_vec();
        v.extend_from_slice(&c.to_be_bytes());
        out.extend_from_slice(digest(&SHA256, &v).as_ref());
        c += 1;
    }
    out.truncate(n);
    out
}

fn mac(aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut v = aad.to_vec();
    v.extend_from_slice(plain);
    digest(&SHA256, &v).as_ref().to_vec()
}

impl Sealer for FakeSealer {
    fn seal(&self, receiver: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, WireError> {
        let mut out = vec![u8::try_from(receiver.len()).unwrap_or(255)];
        out.extend_from_slice(receiver.as_bytes());
        out.extend_from_slice(&mac(aad, plain));
        out.extend(plain.iter().zip(pad(aad, plain.len())).map(|(a, b)| a ^ b));
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        let n = usize::from(*sealed.first().ok_or(WireError::BadSeal)?);
        if sealed.get(1..=n) != Some(self.me.as_bytes()) {
            return Err(WireError::BadSeal);
        }
        let rest = sealed.get(n + 1..).ok_or(WireError::BadSeal)?;
        let (tag, rest) = rest.split_at_checked(32).ok_or(WireError::BadSeal)?;
        let plain: Vec<u8> = rest
            .iter()
            .zip(pad(aad, rest.len()))
            .map(|(a, b)| a ^ b)
            .collect();
        if mac(aad, &plain) != tag {
            return Err(WireError::BadSeal);
        }
        Ok(plain)
    }
}

/// The real thing: HPKE through `ozbox-seal`, the info bound to the receiver's fingerprint.
pub struct HpkeSealer {
    pub key: ozbox_seal::ServiceKey,
}

fn hpke_info(pk: &[u8; 32]) -> Vec<u8> {
    ozbox_seal::info("channel-body", &ozbox_seal::fingerprint(pk))
}

impl Sealer for HpkeSealer {
    fn seal(&self, receiver_hex: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, WireError> {
        let pk = ozbox_seal::public_from_hex(receiver_hex).map_err(|_| WireError::SealFailed)?;
        let (enc, ct) = ozbox_seal::seal(&pk, &hpke_info(&pk), aad, plain)
            .map_err(|_| WireError::SealFailed)?;
        let mut out = enc;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        if sealed.len() < 32 {
            return Err(WireError::BadSeal);
        }
        let (enc, ct) = sealed.split_at(32);
        self.key
            .open(&hpke_info(&self.key.public()), aad, enc, ct)
            .map(|z| z.to_vec())
            .map_err(|_| WireError::BadSeal)
    }
}

#[derive(Default)]
pub struct VecSink {
    pub events: Mutex<Vec<NewEvent>>,
    seen: Mutex<BTreeSet<(String, u64)>>,
    last: Mutex<Option<(String, u64)>>,
}

impl AuditSink for VecSink {
    fn record_many(&self, evs: Vec<NewEvent>) -> std::io::Result<()> {
        for ev in evs {
            if let Some(src) = &ev.src {
                if !self.seen.lock().unwrap().insert(src.clone()) {
                    continue;
                }
                *self.last.lock().unwrap() = Some(src.clone());
            }
            self.events.lock().unwrap().push(ev);
        }
        Ok(())
    }

    fn last_src(&self) -> std::io::Result<Option<(String, u64)>> {
        Ok(self.last.lock().unwrap().clone())
    }
}

impl VecSink {
    pub fn actions(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .map(|x| x.action.clone())
            .collect()
    }
}

pub const T0: u64 = 1_800_000_000_000;

/// One end in a test: a temp dir, a store, keys, a shared clock.
pub struct End {
    pub name: String,
    pub dir: tempfile::TempDir,
    pub store: Store<TState>,
    pub signer: RingSigner,
    pub verifier: RingVerifier,
    pub sealer: Box<dyn Sealer>,
    pub sink: VecSink,
    pub clock: Rc<Cell<u64>>,
    pub seal_public: String,
    pub sign_public: String,
}

impl End {
    pub fn new(name: &str, clock: &Rc<Cell<u64>>, real_seal: bool) -> End {
        let dir = tempfile::tempdir().expect("tempdir");
        let (pkcs8, sign_public) = generate().expect("key");
        let (sealer, seal_public): (Box<dyn Sealer>, String) = if real_seal {
            let key = ozbox_seal::ServiceKey::generate().expect("seal key");
            let public = ozbox_seal::public_to_hex(&key.public());
            (Box::new(HpkeSealer { key }), public)
        } else {
            let public = hex(digest(&SHA256, name.as_bytes()).as_ref());
            (
                Box::new(FakeSealer {
                    me: public.clone(),
                }),
                public,
            )
        };
        let fp = fingerprint(&unhex(&seal_public).unwrap());
        let store = Store::new(dir.path().join("chan"));
        store
            .create(&TState {
                core: Core::new(name, &sign_public, &seal_public, &fp, 1),
                applied: Vec::new(),
            })
            .expect("create");
        End {
            name: name.to_string(),
            dir,
            store,
            signer: RingSigner::from_pkcs8(&pkcs8).expect("signer"),
            verifier: RingVerifier,
            sealer,
            sink: VecSink::default(),
            clock: Rc::clone(clock),
            seal_public,
            sign_public,
        }
    }

    pub fn cx(&self) -> Crypto<'_> {
        Crypto {
            signer: &self.signer,
            verifier: &self.verifier,
            sealer: self.sealer.as_ref(),
        }
    }

    pub fn now(&self) -> u64 {
        self.clock.get()
    }

    pub fn pin(&self, other: &End) {
        let fp = fingerprint(&unhex(&other.seal_public).unwrap());
        let link = Link::new(&other.name, &other.sign_public, &other.seal_public, &fp, 1);
        self.store.update(|s| s.core.pin(link)).expect("pin");
    }

    pub fn state(&self) -> TState {
        self.store.read().expect("read")
    }

    pub fn send(&self, to: &str, text: &str) -> u64 {
        change(&self.store, &self.sink, |s| {
            s.core
                .enqueue(&TEST_PROFILE, to, "note", Vec::new(), text.as_bytes().to_vec())
        })
        .expect("change")
        .expect("enqueue")
    }

    /// The sealed envelopes this end owes `peer` now (a hello first, the whole window).
    pub fn outbound(&self, peer: &str) -> Vec<Sealed> {
        let st = self.state();
        let d = st.core.drafts(
            peer,
            self.now(),
            DraftOpts {
                hello: true,
                ack: false,
                resend: true,
            },
        );
        seal_drafts(&TEST_PROFILE, &self.cx(), &d).expect("seal")
    }

    /// Take a batch from `peer` in one write, apply what is deliverable, and drain the audit.
    pub fn take(&self, msgs: &[Sealed]) -> RoundReport {
        let now = self.now();
        let cx = self.cx();
        let admit = |_: &str, _: &[u8], plain: &[u8]| {
            if String::from_utf8_lossy(plain).contains("sk_live_") {
                Err("key-shaped-content")
            } else {
                Ok(())
            }
        };
        let r = change(&self.store, &self.sink, |s| {
            s.core.tick(now);
            let r = receive_round(&mut s.core, &TEST_PROFILE, &cx, &admit, now, msgs);
            for d in &r.deliveries {
                s.applied.push(match &d.body {
                    Ok(b) => String::from_utf8_lossy(b).into_owned(),
                    Err(c) => format!("REFUSED:{c}"),
                });
            }
            r
        })
        .expect("change");
        drain(&self.store, &self.sink).expect("drain");
        r
    }
}

#[derive(Default, Clone, Copy)]
pub struct Faults {
    pub drop_out: bool,
    pub drop_back: bool,
    pub duplicate: bool,
    pub reverse: bool,
}

fn shape(mut v: Vec<Sealed>, f: Faults) -> Vec<Sealed> {
    if f.duplicate {
        let c = v.clone();
        v.extend(c);
    }
    if f.reverse {
        v.reverse();
    }
    v
}

pub struct Net {
    pub captured: RefCell<Vec<Sealed>>,
}

impl Net {
    pub fn new() -> Net {
        Net {
            captured: RefCell::new(Vec::new()),
        }
    }

    /// One request and its reply: `a` sends what it owes `b`, `b` takes it and answers with what it owes `a`, `a` takes that.
    pub fn round(&self, a: &End, b: &End, f: Faults) -> (RoundReport, RoundReport) {
        let out = a.outbound(&b.name);
        self.captured.borrow_mut().extend(out.iter().cloned());
        let sent = if f.drop_out { Vec::new() } else { shape(out, f) };
        let rb = b.take(&sent);
        let back = b.outbound(&a.name);
        self.captured.borrow_mut().extend(back.iter().cloned());
        let got = if f.drop_back { Vec::new() } else { shape(back, f) };
        let ra = a.take(&got);
        (ra, rb)
    }

    pub fn settle(&self, a: &End, b: &End) {
        for _ in 0..4 {
            self.round(a, b, Faults::default());
        }
    }
}

pub fn pair(real_seal: bool) -> (End, End, Rc<Cell<u64>>) {
    let clock = Rc::new(Cell::new(T0));
    let a = End::new("laptop", &clock, real_seal);
    let b = End::new("main", &clock, real_seal);
    a.pin(&b);
    b.pin(&a);
    (a, b, clock)
}
