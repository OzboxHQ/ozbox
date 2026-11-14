//! Test doubles for the mesh: an endpoint with its own temp store and keys on a shared clock, a screen, and a network that can drop,
//! duplicate and reorder. Signatures are real Ed25519; the sealer is the channel's fake unless a test asks for the real one.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use ring::digest::{digest, SHA256};

use super::model::{Label, Part, TaskKind};
use super::node::{Node, Transport};
use super::state::{NewTask, State};
use super::Screen;
use crate::channel::ring_crypto::{generate, RingSigner, RingVerifier};
use crate::channel::store::Store;
use crate::channel::testkit::{FakeSealer, VecSink};
use crate::channel::wire::{hex, Crypto, Sealed, Sealer};

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

pub const T0: u64 = 1_800_000_000_000;

/// One endpoint in a test.
pub struct End {
    pub name: String,
    pub dir: tempfile::TempDir,
    pub store: Store<State>,
    pub signer: RingSigner,
    pub verifier: RingVerifier,
    pub sealer: Box<dyn Sealer>,
    pub screen: Box<dyn Screen>,
    pub sink: VecSink,
    pub clock: Rc<Cell<u64>>,
    pub seal_public: String,
    pub sign_public: String,
    tick: Box<dyn Fn() -> u64>,
}

impl End {
    pub fn new(name: &str, clock: &Rc<Cell<u64>>) -> End {
        let dir = tempfile::tempdir().expect("tempdir");
        let (pkcs8, sign_public) = generate().expect("key");
        let seal_public = hex(digest(&SHA256, name.as_bytes()).as_ref());
        let store = Store::new(dir.path().join("mesh"));
        store
            .create(&State::new(name, &sign_public, &seal_public))
            .expect("create");
        let c = Rc::clone(clock);
        End {
            name: name.to_string(),
            dir,
            store,
            signer: RingSigner::from_pkcs8(&pkcs8).expect("signer"),
            verifier: RingVerifier,
            sealer: Box::new(FakeSealer {
                me: seal_public.clone(),
            }),
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
            crypto: Crypto {
                signer: &self.signer,
                verifier: &self.verifier,
                sealer: self.sealer.as_ref(),
            },
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
        let now = self.clock.get();
        self.store
            .update(|s| {
                s.pin(now, &n, &sp, &sl, 1, None).expect("pin");
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
                kind: TaskKind::Question,
                title: title.to_string(),
                parts: vec![Part::Text {
                    text: text.to_string(),
                }],
                label: Label::Fleet,
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

/// A network between the caller and `to` (the answerer), carrying sealed messages through `faults`.
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
