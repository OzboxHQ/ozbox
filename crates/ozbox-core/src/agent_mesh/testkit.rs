//! Test doubles: a fake sealer (reversible, checks the receiver), a screen, an audit sink, and a network that can drop,
//! duplicate and reorder. Signatures are real Ed25519.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Mutex;

use ring::digest::{digest, SHA256};

use super::crypto::{self, RingSigner, RingVerifier};
use super::model::{Label, Part};
use super::node::Node;
use super::state::{NewTask, State};
use super::store::Store;
use super::wire::{Sealed, Sealer, Transport};
use super::{AuditSink, Screen};
use crate::audit::NewEvent;

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
    fn seal(&self, receiver: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = vec![u8::try_from(receiver.len()).unwrap_or(255)];
        out.extend_from_slice(receiver.as_bytes());
        out.extend_from_slice(&mac(aad, plain));
        out.extend(plain.iter().zip(pad(aad, plain.len())).map(|(a, b)| a ^ b));
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
        let n = usize::from(*sealed.first().ok_or("short")?);
        if sealed.get(1..=n) != Some(self.me.as_bytes()) {
            return Err("not for this end".into());
        }
        let rest = sealed.get(n + 1..).ok_or("short")?;
        let (tag, rest) = rest.split_at_checked(32).ok_or("short")?;
        let plain: Vec<u8> = rest
            .iter()
            .zip(pad(aad, rest.len()))
            .map(|(a, b)| a ^ b)
            .collect();
        if mac(aad, &plain) != tag {
            return Err("not authentic".into());
        }
        Ok(plain)
    }
}

pub struct TestScreen;

impl Screen for TestScreen {
    fn find(&self, text: &str) -> Option<&'static str> {
        if text.contains("sk_live_") || text.contains("-----BEGIN") {
            Some("a key")
        } else {
            None
        }
    }
}

pub struct NoScreen;

impl Screen for NoScreen {
    fn find(&self, _: &str) -> Option<&'static str> {
        None
    }
}

#[derive(Default)]
pub struct VecSink {
    pub events: Mutex<Vec<NewEvent>>,
    seen: Mutex<BTreeSet<(String, u64)>>,
}

impl AuditSink for VecSink {
    fn record(&self, ev: NewEvent) -> std::io::Result<()> {
        if let Some(src) = &ev.src {
            if let Ok(mut s) = self.seen.lock() {
                if !s.insert(src.clone()) {
                    return Ok(());
                }
            }
        }
        if let Ok(mut e) = self.events.lock() {
            e.push(ev);
        }
        Ok(())
    }
}

impl VecSink {
    pub fn actions(&self) -> Vec<String> {
        self.events
            .lock()
            .map(|e| e.iter().map(|x| x.action.clone()).collect())
            .unwrap_or_default()
    }

    pub fn details(&self) -> String {
        self.events
            .lock()
            .map(|e| {
                e.iter()
                    .map(|x| {
                        format!(
                            "{} {} {}",
                            x.action,
                            x.subject.clone().unwrap_or_default(),
                            x.detail
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

/// One endpoint in a test: a temp dir, a store, keys, a shared clock.
pub struct End {
    pub name: String,
    pub dir: tempfile::TempDir,
    pub store: Store,
    pub signer: RingSigner,
    pub verifier: RingVerifier,
    pub sealer: FakeSealer,
    pub screen: Box<dyn Screen>,
    pub sink: VecSink,
    pub clock: Rc<Cell<u64>>,
    pub seal_public: String,
    pub sign_public: String,
    tick: Box<dyn Fn() -> u64>,
}

pub const T0: u64 = 1_800_000_000_000;

impl End {
    pub fn new(name: &str, clock: &Rc<Cell<u64>>) -> End {
        let dir = tempfile::tempdir().expect("tempdir");
        let (pkcs8, sign_public) = crypto::generate().expect("key");
        let seal_public = crypto::to_hex(digest(&SHA256, name.as_bytes()).as_ref());
        let store = Store::new(dir.path().join("mesh"));
        store
            .create(&State::new(name, &sign_public, &seal_public, clock.get()))
            .expect("create");
        let c = Rc::clone(clock);
        End {
            name: name.to_string(),
            dir,
            store,
            signer: RingSigner::from_pkcs8(&pkcs8).expect("signer"),
            verifier: RingVerifier,
            sealer: FakeSealer {
                me: seal_public.clone(),
            },
            screen: Box::new(TestScreen),
            sink: VecSink::default(),
            clock: Rc::clone(clock),
            seal_public,
            sign_public,
            tick: Box::new(move || c.get()),
        }
    }

    pub fn node(&self) -> Node<'_> {
        Node {
            store: &self.store,
            signer: &self.signer,
            verifier: &self.verifier,
            sealer: &self.sealer,
            screen: self.screen.as_ref(),
            audit: &self.sink,
            clock: &*self.tick,
        }
    }

    pub fn pin(&self, other: &End) {
        let (sp, sl, n) = (
            other.sign_public.clone(),
            other.seal_public.clone(),
            other.name.clone(),
        );
        self.store
            .update(|s| {
                let epoch = 1;
                s.peers.insert(
                    n.clone(),
                    super::state::Peer::new(&n, &sp, &sl, epoch, Vec::new()),
                );
            })
            .expect("pin");
    }

    pub fn state(&self) -> State {
        self.store.read().expect("read")
    }

    pub fn ask(&self, to: &str, title: &str, text: &str) -> String {
        self.node()
            .submit(NewTask {
                to: to.to_string(),
                kind: super::model::TaskKind::Question,
                title: title.to_string(),
                parts: vec![Part::Text {
                    text: text.to_string(),
                }],
                label: Label::Person,
                act: None,
                parent: None,
                deadline_ms: None,
            })
            .expect("submit")
    }
}

/// Two pinned endpoints on one clock.
pub fn pair() -> (End, End, Rc<Cell<u64>>) {
    let clock = Rc::new(Cell::new(T0));
    let a = End::new("laptop", &clock);
    let b = End::new("main", &clock);
    a.pin(&b);
    b.pin(&a);
    (a, b, clock)
}

#[derive(Default, Clone, Copy)]
pub struct Faults {
    pub drop_out: bool,
    pub drop_back: bool,
    pub duplicate: bool,
    pub reverse: bool,
    pub fail: bool,
}

/// A network between `from` (the caller) and `to` (the answerer), carrying sealed messages through `faults`.
pub struct Net<'a> {
    pub to: &'a End,
    pub caller_name: String,
    pub faults: RefCell<Faults>,
    pub captured: RefCell<Vec<Sealed>>,
}

impl<'a> Net<'a> {
    pub fn new(to: &'a End, caller: &str) -> Net<'a> {
        Net {
            to,
            caller_name: caller.to_string(),
            faults: RefCell::new(Faults::default()),
            captured: RefCell::new(Vec::new()),
        }
    }
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

impl Transport for Net<'_> {
    fn exchange(&self, _peer: &str, outbound: &[Sealed]) -> Result<Vec<Sealed>, String> {
        let f = *self.faults.borrow();
        if f.fail {
            return Err("network down".into());
        }
        self.captured.borrow_mut().extend(outbound.iter().cloned());
        let out = if f.drop_out {
            Vec::new()
        } else {
            shape(outbound.to_vec(), f)
        };
        let (_, back) = self
            .to
            .node()
            .serve(&self.caller_name, &out)
            .map_err(|e| e.to_string())?;
        self.captured.borrow_mut().extend(back.iter().cloned());
        Ok(if f.drop_back {
            Vec::new()
        } else {
            shape(back, f)
        })
    }
}

impl End {
    /// The first draft of a kind for a peer, edited by `f`, then sealed and signed as this endpoint: a sender that is honest in
    /// every way except the field the test changed.
    pub fn forge(
        &self,
        peer: &str,
        kind: super::wire::Kind,
        f: impl FnOnce(&mut super::wire::Envelope),
    ) -> Sealed {
        use super::wire::Signer;
        let st = self.state();
        let (mut e, plain) = st
            .drafts(peer, self.clock.get())
            .into_iter()
            .find(|(e, _)| e.kind == kind)
            .expect("draft");
        f(&mut e);
        e.body = Vec::new();
        e.body = self.sealer_to(&st.peers[peer].seal_public, &e.aad(), &plain);
        let signature = self.signer.sign(&e.canonical()).expect("sign");
        Sealed {
            envelope: e,
            signature,
        }
    }

    fn sealer_to(&self, to: &str, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        FakeSealer {
            me: self.seal_public.clone(),
        }
        .seal(to, aad, plain)
        .expect("seal")
    }
}
