//! An in-memory transport and test crypto for the hub, so the whole hand-off runs without a network.
//!
//! The crypto here is **not** crypto: the "seal" is a reversible wrapper that checks the receiver, and the "signature" is a keyed
//! digest. It exists so the hub's decisions (who may send what, what is refused, what is audited) can be tested. The real signer
//! and sealer are the secrets service's operations and `ozbox-seal`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use ring::digest::{digest, SHA256};

use super::wire::{Sealed, Sealer, Signer, Transport, Verifier};

/// One queue per receiver. Delivery is a function call; ordering is the queue's.
#[derive(Default)]
pub struct MemTransport {
    queues: Mutex<BTreeMap<String, VecDeque<Sealed>>>,
    /// Every message that ever crossed, for a test that captures the channel.
    pub capture: Mutex<Vec<Sealed>>,
}

impl Transport for MemTransport {
    fn send(&self, to: &str, msg: Sealed) {
        if let Ok(mut c) = self.capture.lock() {
            c.push(msg.clone());
        }
        if let Ok(mut q) = self.queues.lock() {
            q.entry(to.to_string()).or_default().push_back(msg);
        }
    }

    fn recv(&self, who: &str) -> Option<Sealed> {
        self.queues.lock().ok()?.get_mut(who)?.pop_front()
    }
}

impl MemTransport {
    pub fn pending(&self, who: &str) -> usize {
        self.queues
            .lock()
            .ok()
            .and_then(|q| q.get(who).map(VecDeque::len))
            .unwrap_or(0)
    }
}

/// A keyed digest standing in for a signature: `sha256(secret || message)`.
pub struct TestKey(pub String);

fn tag(secret: &str, msg: &[u8]) -> Vec<u8> {
    let mut v = secret.as_bytes().to_vec();
    v.extend_from_slice(msg);
    digest(&SHA256, &v).as_ref().to_vec()
}

impl Signer for TestKey {
    fn sign(&self, canonical: &[u8]) -> Vec<u8> {
        tag(&self.0, canonical)
    }
}

/// Verifies against the secrets the roster holds per sender.
#[derive(Default)]
pub struct TestRoster(pub BTreeMap<String, String>);

impl Verifier for TestRoster {
    fn verify(&self, sender: &str, canonical: &[u8], signature: &[u8]) -> bool {
        self.0
            .get(sender)
            .is_some_and(|k| tag(k, canonical) == signature)
    }
}

/// A reversible wrapper: the receiver's name, then the plaintext xor a pad from the aad. Opens only with the same aad.
pub struct TestSealer {
    pub me: String,
}

fn pad(aad: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < n {
        let mut v = aad.to_vec();
        v.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(digest(&SHA256, &v).as_ref());
        counter += 1;
    }
    out.truncate(n);
    out
}

impl Sealer for TestSealer {
    fn seal(&self, receiver: &str, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = vec![u8::try_from(receiver.len()).unwrap_or(u8::MAX)];
        out.extend_from_slice(receiver.as_bytes());
        out.extend(plain.iter().zip(pad(aad, plain.len())).map(|(a, b)| a ^ b));
        out
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        let n = usize::from(*sealed.first()?);
        let to = sealed.get(1..=n)?;
        if to != self.me.as_bytes() {
            return None;
        }
        let rest = sealed.get(n + 1..)?;
        Some(
            rest.iter()
                .zip(pad(aad, rest.len()))
                .map(|(a, b)| a ^ b)
                .collect(),
        )
    }
}
