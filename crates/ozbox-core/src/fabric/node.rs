//! The two ends of the fabric: [`HubFabric`] on `main`, which holds the mailboxes, and [`BoxFabric`] on a worker, which holds a
//! replica of its own agents' mailboxes and queues what they send.
//!
//! On one box an agent calls its box's end directly (through the tool host behind the supervisor's agent socket, ADR 0043). Between
//! boxes the ends speak the fabric's profile of the channel, sealed and signed through the channel's seams (the real signer and
//! sealer are the secrets service and `ozbox-seal`), over the hub's transport under `<box>.fabric` endpoints.
//!
//! A worker speaks only for the agents homed on it, and the hub checks that on every frame: a worker cannot register, post as, read
//! for or propose as another box's agent. Every change is made under one lock, written to the store (when there is one) **before**
//! anything is pushed, and then pushed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::addr::{Address, Participant};
use super::mailbox::{receipt, Mailboxes, Sent};
use super::model::{
    new_id, Batch, DeliveryState, Message, ParticipantView, Post, PostReceipt, MAX_WAIT_MS,
};
use super::policy::Reach;
use super::walls::{NewProposal, Proposal, Wall, WallSource, Walls};
use super::wire::{
    box_of, endpoint, Deliver, Directory, PostFrame, ProposeFrame, Read, Register, StateFrame,
    WallFrame, EXT, K_DELIVER, K_DIRECTORY, K_POST, K_PROPOSE, K_READ, K_REGISTER, K_STATE,
    K_WALLS, PROFILE, TO_HUB,
};
use super::{FabricApi, FabricError};
use crate::agent_mesh::Screen;
use crate::channel::audit::{AuditSink, HasCore};
use crate::channel::flow::{receive_round, seal_drafts};
use crate::channel::session::{Core, Link};
use crate::channel::store::Store;
use crate::channel::wire::{Crypto, Sealed, Sealer, Signer, Verifier};
use crate::hub::wire::Transport;

/// The epoch every fabric end starts at; it moves only when a store is restored.
pub const EPOCH: u64 = 1;
/// How many message copies one `fabric.deliver` carries (16 of the largest fit well inside the body cap).
const DELIVER_CHUNK: usize = 16;
/// How often the hub reads the memory and skills stores again for the workers' walls.
pub const WALLS_EVERY_MS: u64 = 60_000;

/// The seams an end needs: the channel's crypto, the transport, the screen and the audit sink.
#[derive(Clone)]
pub struct Seams {
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub sealer: Arc<dyn Sealer>,
    pub net: Arc<dyn Transport>,
    pub screen: Arc<dyn Screen>,
    /// Where audit events go. `None` drops them (tests and the fake fleet only).
    pub audit: Option<Arc<dyn AuditSink>>,
}

impl Seams {
    fn cx(&self) -> Crypto<'_> {
        Crypto {
            signer: self.signer.as_ref(),
            verifier: self.verifier.as_ref(),
            sealer: self.sealer.as_ref(),
        }
    }
}

fn unavailable() -> FabricError {
    FabricError::Unavailable("the fabric's state could not be used".into())
}

fn enqueue<T: Serialize>(
    core: &mut Core,
    peer: &str,
    kind: &str,
    body: &T,
) -> Result<(), FabricError> {
    let b = serde_json::to_vec(body).map_err(|_| unavailable())?;
    core.enqueue(&PROFILE, peer, kind, EXT.to_vec(), b)
        .map(|_| ())
        .map_err(|c| FabricError::Limit(format!("the message could not be queued: {c}")))
}

/// Push what a peer is owed. A transport that cannot take it is noted; the outbox keeps it for the next push.
fn flush(seams: &Seams, core: &mut Core, peer: &str, now: u64) {
    let opts = core.push_opts(peer, now);
    let drafts = core.drafts(peer, now, opts);
    if drafts.is_empty() {
        return;
    }
    let sent = seal_drafts(&PROFILE, &seams.cx(), &drafts)
        .map_err(|e| e.code())
        .and_then(|sealed| {
            sealed
                .into_iter()
                .try_for_each(|m| seams.net.send(peer, m).map_err(|e| e.to_string()))
        });
    match sent {
        Ok(()) => core.pushed(peer, now, &drafts),
        Err(_) => core.note(now, "fabric.send-failed", None, format!("peer={peer}")),
    }
}

/// Take every waiting envelope through the channel's checks, per sender. Returns `(sender endpoint, kind, body)` per delivery.
fn take(seams: &Seams, core: &mut Core, me: &str, now: u64) -> Vec<(String, String, Vec<u8>)> {
    let mut by: BTreeMap<String, Vec<Sealed>> = BTreeMap::new();
    while let Some(m) = seams.net.recv(me) {
        by.entry(m.envelope.from.clone()).or_default().push(m);
    }
    let cx = seams.cx();
    let mut out = Vec::new();
    for (from, msgs) in by {
        core.tick(now);
        let r = receive_round(core, &PROFILE, &cx, &|_, _, _| Ok(()), now, &msgs);
        for d in r.deliveries {
            if let Ok(b) = d.body {
                out.push((from.clone(), d.kind, b));
            }
        }
    }
    out
}

fn drain(seams: &Seams, core: &mut Core) {
    match &seams.audit {
        Some(sink) => {
            let Ok(last) = sink.last_src() else { return };
            core.trim_logged(last.as_ref());
            if !core.audit.is_empty() && sink.record_many(core.audit.clone()).is_ok() {
                if let Ok(last) = sink.last_src() {
                    core.trim_logged(last.as_ref());
                }
            }
        }
        None => core.audit.clear(),
    }
}

fn parse<T: DeserializeOwned>(b: &[u8]) -> Option<T> {
    serde_json::from_slice(b).ok()
}

fn wait_for<'a, S>(
    lock: &'a Mutex<S>,
    cv: &'a Condvar,
    wait_ms: u64,
    mut ready: impl FnMut(&mut S) -> bool,
) -> Result<MutexGuard<'a, S>, FabricError> {
    let mut g = lock.lock().map_err(|_| unavailable())?;
    let deadline = Instant::now() + Duration::from_millis(wait_ms.min(MAX_WAIT_MS));
    while !ready(&mut g) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        g = cv.wait_timeout(g, left).map_err(|_| unavailable())?.0;
    }
    Ok(g)
}

fn has_after(mail: &Mailboxes, me: &Address, after: u64) -> bool {
    mail.boxes
        .get(me)
        .is_some_and(|b| b.msgs.iter().any(|m| m.seq > after))
}

// ---- the hub ------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubFabricState {
    pub core: Core,
    pub mail: Mailboxes,
    /// The highest mailbox position of each worker-homed participant already queued to its box.
    #[serde(default)]
    pub pushed: BTreeMap<Address, u64>,
    /// Per box: the version of each sent record its box was last told.
    #[serde(default)]
    pub told: BTreeMap<String, BTreeMap<String, u64>>,
    /// Per box: posts it queued that the hub refused, waiting to be said.
    #[serde(default)]
    pub refusals: BTreeMap<String, Vec<(String, String)>>,
    #[serde(default)]
    pub dir_digest: BTreeMap<String, String>,
    #[serde(default)]
    pub wall_digest: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub walls_ms: u64,
    /// Workers whose walls must be sent again at the next pump (a registration changed them).
    #[serde(default)]
    pub walls_due: BTreeSet<String>,
}

impl HasCore for HubFabricState {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}

/// `main`'s end: the authoritative mailboxes.
pub struct HubFabric {
    pub hub_box: String,
    pub my_fp: String,
    /// The workers this hub reaches: box name to the key fingerprint its enrolment attested (the worker channel's roster).
    pub roster: BTreeMap<String, String>,
    pub seams: Seams,
    pub walls: Option<Arc<dyn WallSource>>,
    pub store: Option<Store<HubFabricState>>,
    state: Mutex<HubFabricState>,
    cv: Condvar,
}

impl HubFabric {
    pub fn new(
        hub_box: &str,
        my_fp: &str,
        roster: BTreeMap<String, String>,
        seams: Seams,
        walls: Option<Arc<dyn WallSource>>,
    ) -> HubFabric {
        let core = Core::new(&endpoint(hub_box), my_fp, my_fp, my_fp, EPOCH);
        HubFabric {
            hub_box: hub_box.into(),
            my_fp: my_fp.into(),
            roster,
            seams,
            walls,
            store: None,
            state: Mutex::new(HubFabricState {
                core,
                mail: Mailboxes::default(),
                pushed: BTreeMap::new(),
                told: BTreeMap::new(),
                refusals: BTreeMap::new(),
                dir_digest: BTreeMap::new(),
                wall_digest: BTreeMap::new(),
                walls_ms: 0,
                walls_due: BTreeSet::new(),
            }),
            cv: Condvar::new(),
        }
    }

    /// Persist through a store, starting from what it holds (a restart keeps every mailbox and every unacknowledged frame).
    pub fn with_store(mut self, store: Store<HubFabricState>) -> Result<HubFabric, FabricError> {
        if store.exists() {
            let st = store
                .read()
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
            self.state = Mutex::new(st);
        } else {
            let st = self.state.lock().map_err(|_| unavailable())?.clone();
            store
                .create(&st)
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
        }
        self.store = Some(store);
        Ok(self)
    }

    /// A copy of the state, for the dashboard and tests.
    pub fn snapshot(&self) -> Option<HubFabricState> {
        self.state.lock().ok().map(|s| s.clone())
    }

    fn pins(&self, st: &mut HubFabricState) {
        for (b, fp) in &self.roster {
            let ep = endpoint(b);
            let current = st.core.links.get(&ep).is_some_and(|l| &l.sign_key == fp);
            if !current {
                st.core.pin(Link::new(&ep, fp, fp, fp, EPOCH));
            }
        }
    }

    /// Run a change: route, persist, push, drain the audit, wake waiting fetches.
    fn change<T>(
        &self,
        now: u64,
        f: impl FnOnce(&HubFabric, &mut HubFabricState) -> Result<T, FabricError>,
    ) -> Result<T, FabricError> {
        let mut st = self.state.lock().map_err(|_| unavailable())?;
        self.pins(&mut st);
        let out = f(self, &mut st);
        self.route(&mut st, now);
        if let Some(store) = &self.store {
            store
                .update(|disk| *disk = st.clone())
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
        }
        let peers: Vec<String> = st.core.links.keys().cloned().collect();
        for p in peers {
            flush(&self.seams, &mut st.core, &p, now);
        }
        drain(&self.seams, &mut st.core);
        drop(st);
        self.cv.notify_all();
        out
    }

    /// One round with the workers: take what they sent, apply it, refresh their walls when due, push what they are owed.
    pub fn pump(&self, now: u64) -> Result<usize, FabricError> {
        self.change(now, |me, st| {
            let got = take(&me.seams, &mut st.core, &endpoint(&me.hub_box), now);
            let n = got.len();
            for (from, kind, body) in got {
                me.apply(st, &from, &kind, &body, now);
            }
            st.mail.sweep(now);
            if now >= st.walls_ms.saturating_add(WALLS_EVERY_MS) {
                st.walls_ms = now;
                st.walls_due.extend(me.roster.keys().cloned());
            }
            let due = std::mem::take(&mut st.walls_due);
            for b in due {
                me.send_walls(st, &b, now);
            }
            Ok(n)
        })
    }

    /// Send the workers' walls again at the next pump (after a person approved or forgot a note, or approved a skill).
    pub fn walls_changed(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.walls_due.extend(self.roster.keys().cloned());
        }
    }

    /// Apply one frame as if the worker `from_box` sent it, through the same checks a real one passes after the channel's.
    #[cfg(test)]
    pub(super) fn take_frame(&self, from_box: &str, kind: &str, body: &[u8], now: u64) {
        let _ = self.change(now, |me, st| {
            me.apply(st, &endpoint(from_box), kind, body, now);
            Ok(())
        });
    }

    fn homed_on<'a>(
        st: &'a HubFabricState,
        b: &'a str,
    ) -> impl Iterator<Item = &'a Participant> + 'a {
        st.mail
            .participants
            .values()
            .filter(move |p| p.home == b && matches!(p.address, Address::Agent { .. }))
    }

    fn apply(&self, st: &mut HubFabricState, from: &str, kind: &str, body: &[u8], now: u64) {
        let Some(b) = box_of(from)
            .filter(|b| self.roster.contains_key(*b))
            .map(str::to_string)
        else {
            return;
        };
        let refuse = |st: &mut HubFabricState, why: &str| {
            st.core.note(
                now,
                "fabric.rejected",
                None,
                format!("box={b} kind={kind} reason={why}"),
            );
        };
        if !TO_HUB.contains(&kind) {
            return refuse(st, "hub-only-kind");
        }
        // what a worker says about a participant counts only for one homed on that worker
        let homed = |st: &HubFabricState, a: &Address| {
            st.mail
                .participants
                .get(a)
                .is_some_and(|p| p.home == b && matches!(p.address, Address::Agent { .. }))
        };
        match kind {
            K_REGISTER => {
                let Some(r) = parse::<Register>(body) else {
                    return refuse(st, "malformed");
                };
                for p in r.participants {
                    let ok = matches!(&p.address, Address::Agent { box_name, .. } if *box_name == b)
                        && p.home == b
                        // a worker may not take over a participant another box registered
                        && st.mail.participants.get(&p.address).is_none_or(|q| q.home == b);
                    if !ok {
                        refuse(st, "not-homed-here");
                        continue;
                    }
                    if st.mail.register(p).is_err() {
                        refuse(st, "invalid-participant");
                    }
                }
                st.walls_due.insert(b.clone());
            }
            K_POST => {
                let Some(f) = parse::<PostFrame>(body) else {
                    return refuse(st, "malformed");
                };
                if !homed(st, &f.by) {
                    return refuse(st, "not-homed-here");
                }
                let person = st.mail.participants.get(&f.by).map(|p| p.person.clone());
                let by = Reach {
                    me: f.by.clone(),
                    person: person.unwrap_or_default(),
                    projects: Vec::new(),
                    box_name: None,
                    delegated: Vec::new(),
                };
                match st
                    .mail
                    .post(self.seams.screen.as_ref(), &by, f.post, f.id.clone(), now)
                {
                    Ok(r) => st.core.note(
                        now,
                        "fabric.post",
                        Some(&f.id),
                        format!("box={b} recipients={}", r.recipients.len()),
                    ),
                    Err(e) => {
                        st.refusals
                            .entry(b.clone())
                            .or_default()
                            .push((f.id.clone(), e.message().to_string()));
                        st.core
                            .note(now, "fabric.post-refused", Some(&f.id), format!("box={b}"));
                    }
                }
            }
            K_READ => {
                let Some(r) = parse::<Read>(body) else {
                    return refuse(st, "malformed");
                };
                for (a, id) in r.delivered {
                    if homed(st, &a) {
                        if let Some(m) = st
                            .mail
                            .boxes
                            .get_mut(&a)
                            .and_then(|bx| bx.msgs.iter_mut().find(|m| m.id == id))
                        {
                            if m.state == DeliveryState::Accepted {
                                m.state = DeliveryState::Delivered;
                            }
                        }
                        st.mail.set_state(&a, &id, DeliveryState::Delivered);
                    }
                }
                let mut by: BTreeMap<Address, Vec<String>> = BTreeMap::new();
                for (a, id) in r.read {
                    if homed(st, &a) {
                        by.entry(a).or_default().push(id);
                    }
                }
                for (a, ids) in by {
                    let reach = Reach {
                        me: a,
                        person: String::new(),
                        projects: Vec::new(),
                        box_name: None,
                        delegated: Vec::new(),
                    };
                    st.mail.ack(&reach, &ids);
                }
            }
            K_PROPOSE => {
                let Some(f) = parse::<ProposeFrame>(body) else {
                    return refuse(st, "malformed");
                };
                let mut p = f.proposal;
                let Some(reg) = st.mail.participants.get(&p.by).filter(|_| homed(st, &p.by)) else {
                    return refuse(st, "not-homed-here");
                };
                // who and where come from the registry and the channel, never from the frame
                p.person = reg.person.clone();
                p.from_box = b.clone();
                if !Reach::of(reg).reads_wall(&p.note.scope) {
                    return refuse(st, "wall-not-bound");
                }
                match &self.walls {
                    Some(w) => match w.propose(&p, now) {
                        Ok(id) => st.core.note(
                            now,
                            "fabric.propose",
                            Some(&id),
                            format!("box={b} scope={}", p.note.scope),
                        ),
                        Err(_) => refuse(st, "proposal-refused"),
                    },
                    None => refuse(st, "no-memory"),
                }
            }
            _ => {}
        }
    }

    /// Queue for every worker what it is owed: new copies for its agents, what changed about what they sent, refusals, and its
    /// directory when that changed.
    fn route(&self, st: &mut HubFabricState, now: u64) {
        for b in self.roster.keys() {
            let ep = endpoint(b);
            let homed: Vec<Participant> = Self::homed_on(st, b).cloned().collect();
            // copies
            let mut fresh: Vec<Message> = Vec::new();
            for p in &homed {
                let from = st.pushed.get(&p.address).copied().unwrap_or(0);
                if let Some(bx) = st.mail.boxes.get(&p.address) {
                    let new: Vec<Message> =
                        bx.msgs.iter().filter(|m| m.seq > from).cloned().collect();
                    if let Some(last) = new.last() {
                        st.pushed.insert(p.address.clone(), last.seq);
                    }
                    fresh.extend(new);
                }
            }
            for chunk in fresh.chunks(DELIVER_CHUNK) {
                let d = Deliver {
                    messages: chunk.to_vec(),
                };
                if enqueue(&mut st.core, &ep, K_DELIVER, &d).is_err() {
                    st.core
                        .note(now, "fabric.backlog", None, format!("box={b}"));
                }
            }
            // states and refusals
            let mut sf = StateFrame::default();
            let told = st.told.entry(b.clone()).or_default();
            for (id, s) in &st.mail.sent {
                if homed.iter().any(|p| p.address == s.msg.from)
                    && told.get(id).copied().unwrap_or(0) < s.version
                {
                    told.insert(id.clone(), s.version);
                    sf.states.push((id.clone(), s.recipients.clone()));
                }
            }
            sf.refused = st.refusals.remove(b).unwrap_or_default();
            if (!sf.states.is_empty() || !sf.refused.is_empty())
                && enqueue(&mut st.core, &ep, K_STATE, &sf).is_err()
            {
                st.core
                    .note(now, "fabric.backlog", None, format!("box={b}"));
            }
            // the directory: everyone any of the box's agents may see
            let mut seen: BTreeMap<Address, Participant> = BTreeMap::new();
            for p in &homed {
                let r = Reach::of(p);
                for q in st.mail.participants.values().filter(|q| r.sees(q)) {
                    seen.insert(q.address.clone(), q.clone());
                }
            }
            let dir = Directory {
                participants: seen.into_values().collect(),
            };
            let digest = digest_of(&dir);
            if st.dir_digest.get(b) != Some(&digest)
                && enqueue(&mut st.core, &ep, K_DIRECTORY, &dir).is_ok()
            {
                st.dir_digest.insert(b.clone(), digest);
            }
        }
    }

    fn send_walls(&self, st: &mut HubFabricState, b: &str, now: u64) {
        let Some(src) = &self.walls else { return };
        let mut scopes = BTreeSet::new();
        for p in Self::homed_on(st, b) {
            scopes.extend(Reach::of(p).walls());
        }
        let ep = endpoint(b);
        for scope in scopes {
            let mut wall = Wall {
                notes: src.approved(&scope, now),
                skills: if scope.starts_with("person:") {
                    Vec::new()
                } else {
                    src.skills(&scope)
                },
            }
            .bounded(&scope);
            // stay inside one body: the oldest notes go first
            while serde_json::to_vec(&wall).map_or(0, |v| v.len()) > PROFILE.max_body / 2
                && !wall.notes.is_empty()
            {
                wall.notes.pop();
            }
            let d = wall.digest();
            let digests = st.wall_digest.entry(b.to_string()).or_default();
            if digests.get(&scope) == Some(&d) {
                continue;
            }
            let frame = WallFrame {
                scope: scope.clone(),
                wall,
            };
            if enqueue(&mut st.core, &ep, K_WALLS, &frame).is_ok() {
                st.wall_digest
                    .entry(b.to_string())
                    .or_default()
                    .insert(scope, d);
            }
        }
    }

    fn local_reach(&self, st: &mut HubFabricState, by: &Reach) -> Result<(), FabricError> {
        // a person is a participant the moment they use the fabric
        if let Address::Person { id } = &by.me {
            if !st.mail.participants.contains_key(&by.me) {
                st.mail.register(Participant::person(id, &self.hub_box))?;
            }
        }
        Ok(())
    }
}

fn digest_of<T: Serialize>(v: &T) -> String {
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    crate::approval_subject::to_hex(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref())
}

impl FabricApi for HubFabric {
    fn register(&self, p: Participant, now: u64) -> Result<(), FabricError> {
        self.change(now, |me, st| {
            // the hub registers its own agents, people, groups and fleets; a worker's agents come over the channel
            if matches!(p.address, Address::Agent { .. }) && p.home != me.hub_box {
                return Err(FabricError::Refused(
                    "an agent is registered by the box it runs on".into(),
                ));
            }
            if st
                .mail
                .participants
                .get(&p.address)
                .is_some_and(|q| q.home != me.hub_box)
            {
                return Err(FabricError::Refused(
                    "that participant belongs to another box".into(),
                ));
            }
            st.mail.register(p)
        })
    }

    fn post(&self, by: &Reach, p: Post, now: u64) -> Result<PostReceipt, FabricError> {
        self.change(now, |me, st| {
            me.local_reach(st, by)?;
            let id = new_id();
            let r = st
                .mail
                .post(me.seams.screen.as_ref(), by, p, id.clone(), now)?;
            st.core.note(
                now,
                "fabric.post",
                Some(&id),
                format!("box={} recipients={}", me.hub_box, r.recipients.len()),
            );
            Ok(r)
        })
    }

    fn get(
        &self,
        by: &Reach,
        after: u64,
        limit: usize,
        wait_ms: u64,
        now: u64,
    ) -> Result<Batch, FabricError> {
        if wait_ms > 0 {
            drop(wait_for(&self.state, &self.cv, wait_ms, |st| {
                has_after(&st.mail, &by.me, after)
            })?);
        }
        self.change(now, |_, st| {
            st.mail.reach_of(by)?;
            Ok(st.mail.get(by, after, limit))
        })
    }

    fn thread(&self, by: &Reach, thread: &str, _now: u64) -> Result<Vec<Message>, FabricError> {
        let st = self.state.lock().map_err(|_| unavailable())?;
        st.mail.reach_of(by)?;
        Ok(st.mail.thread(by, thread))
    }

    fn ack(&self, by: &Reach, ids: &[String], now: u64) -> Result<usize, FabricError> {
        self.change(now, |_, st| {
            st.mail.reach_of(by)?;
            Ok(st.mail.ack(by, ids))
        })
    }

    fn participants(&self, by: &Reach, now: u64) -> Result<Vec<ParticipantView>, FabricError> {
        self.change(now, |me, st| {
            me.local_reach(st, by)?;
            let r = st.mail.reach_of(by)?;
            Ok(st.mail.participants(&r))
        })
    }

    fn sent(&self, by: &Reach, id: &str) -> Result<Vec<(Address, DeliveryState)>, FabricError> {
        let st = self.state.lock().map_err(|_| unavailable())?;
        st.mail.sent_states(by, id)
    }
}

// ---- a worker -----------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxFabricState {
    pub core: Core,
    /// The agents homed on this box.
    pub local: BTreeMap<Address, Participant>,
    /// The replica: this box's agents' mailboxes, what they sent, and the directory as participants.
    pub mail: Mailboxes,
    pub walls: Walls,
    /// Receipts not yet queued.
    #[serde(default)]
    pub receipts: Read,
}

impl HasCore for BoxFabricState {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}

/// A worker's end: a replica of its agents' mailboxes, and a queue to the hub.
pub struct BoxFabric {
    pub box_name: String,
    pub hub_box: String,
    pub seams: Seams,
    pub store: Option<Store<BoxFabricState>>,
    state: Mutex<BoxFabricState>,
    cv: Condvar,
}

impl BoxFabric {
    pub fn new(
        box_name: &str,
        my_fp: &str,
        hub_box: &str,
        hub_fp: &str,
        seams: Seams,
    ) -> BoxFabric {
        let mut core = Core::new(&endpoint(box_name), my_fp, my_fp, my_fp, EPOCH);
        core.pin(Link::new(&endpoint(hub_box), hub_fp, hub_fp, hub_fp, EPOCH));
        BoxFabric {
            box_name: box_name.into(),
            hub_box: hub_box.into(),
            seams,
            store: None,
            state: Mutex::new(BoxFabricState {
                core,
                local: BTreeMap::new(),
                mail: Mailboxes::default(),
                walls: Walls::default(),
                receipts: Read::default(),
            }),
            cv: Condvar::new(),
        }
    }

    pub fn with_store(mut self, store: Store<BoxFabricState>) -> Result<BoxFabric, FabricError> {
        if store.exists() {
            let st = store
                .read()
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
            self.state = Mutex::new(st);
        } else {
            let st = self.state.lock().map_err(|_| unavailable())?.clone();
            store
                .create(&st)
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
        }
        self.store = Some(store);
        Ok(self)
    }

    pub fn snapshot(&self) -> Option<BoxFabricState> {
        self.state.lock().ok().map(|s| s.clone())
    }

    fn hub_ep(&self) -> String {
        endpoint(&self.hub_box)
    }

    fn change<T>(
        &self,
        now: u64,
        f: impl FnOnce(&BoxFabric, &mut BoxFabricState) -> Result<T, FabricError>,
    ) -> Result<T, FabricError> {
        let mut st = self.state.lock().map_err(|_| unavailable())?;
        let out = f(self, &mut st);
        let rc = std::mem::take(&mut st.receipts);
        if !rc.delivered.is_empty() || !rc.read.is_empty() {
            let hub = self.hub_ep();
            if enqueue(&mut st.core, &hub, K_READ, &rc).is_err() {
                st.receipts = rc;
            }
        }
        if let Some(store) = &self.store {
            store
                .update(|disk| *disk = st.clone())
                .map_err(|e| FabricError::Unavailable(e.to_string()))?;
        }
        let hub = self.hub_ep();
        flush(&self.seams, &mut st.core, &hub, now);
        drain(&self.seams, &mut st.core);
        drop(st);
        self.cv.notify_all();
        out
    }

    /// One round with the hub.
    pub fn pump(&self, now: u64) -> Result<usize, FabricError> {
        self.change(now, |me, st| {
            let got = take(&me.seams, &mut st.core, &endpoint(&me.box_name), now);
            let n = got.len();
            let hub = me.hub_ep();
            for (from, kind, body) in got {
                if from != hub || TO_HUB.contains(&kind.as_str()) {
                    st.core
                        .note(now, "fabric.rejected", None, format!("kind={kind}"));
                    continue;
                }
                me.apply(st, &kind, &body);
            }
            st.mail.sweep(now);
            Ok(n)
        })
    }

    fn apply(&self, st: &mut BoxFabricState, kind: &str, body: &[u8]) {
        match kind {
            K_DELIVER => {
                let Some(d) = parse::<Deliver>(body) else {
                    return;
                };
                for m in d.messages {
                    if !st.local.contains_key(&m.recipient) {
                        continue;
                    }
                    let bx = st.mail.boxes.entry(m.recipient.clone()).or_default();
                    if bx.msgs.iter().any(|x| x.id == m.id) {
                        continue;
                    }
                    bx.last_seq = bx.last_seq.max(m.seq);
                    let at = bx.msgs.partition_point(|x| x.seq < m.seq);
                    bx.msgs.insert(at, m);
                }
            }
            K_STATE => {
                let Some(f) = parse::<StateFrame>(body) else {
                    return;
                };
                for (id, states) in f.states {
                    if let Some(s) = st.mail.sent.get_mut(&id) {
                        s.recipients = states;
                        s.version += 1;
                    }
                }
                for (id, why) in f.refused {
                    if let Some(s) = st.mail.sent.get_mut(&id) {
                        for v in s.recipients.values_mut() {
                            *v = DeliveryState::Refused;
                        }
                        s.refused = Some(why.chars().take(300).collect());
                        s.version += 1;
                    }
                }
            }
            K_DIRECTORY => {
                let Some(d) = parse::<Directory>(body) else {
                    return;
                };
                let mut all: BTreeMap<Address, Participant> = d
                    .participants
                    .into_iter()
                    .filter_map(|p| p.checked().ok())
                    .map(|p| (p.address.clone(), p))
                    .collect();
                for (a, p) in &st.local {
                    all.insert(a.clone(), p.clone());
                }
                st.mail.participants = all;
            }
            K_WALLS => {
                let Some(w) = parse::<WallFrame>(body) else {
                    return;
                };
                let wanted = st.local.values().any(|p| Reach::of(p).reads_wall(&w.scope));
                if wanted {
                    let wall = w.wall.bounded(&w.scope);
                    st.walls.walls.insert(w.scope, wall);
                }
            }
            _ => {}
        }
    }
}

impl FabricApi for BoxFabric {
    fn register(&self, p: Participant, now: u64) -> Result<(), FabricError> {
        self.change(now, |me, st| {
            let p = p.checked()?;
            if p.address.box_name() != Some(me.box_name.as_str()) {
                return Err(FabricError::Refused(
                    "a worker registers only the agents that run on it".into(),
                ));
            }
            st.local.insert(p.address.clone(), p.clone());
            st.mail.register(p.clone())?;
            let hub = me.hub_ep();
            enqueue(
                &mut st.core,
                &hub,
                K_REGISTER,
                &Register {
                    participants: vec![p],
                },
            )
        })
    }

    fn post(&self, by: &Reach, p: Post, now: u64) -> Result<PostReceipt, FabricError> {
        self.change(now, |me, st| {
            if !st.local.contains_key(&by.me) {
                return Err(FabricError::Refused(
                    "only an agent on this box posts from it".into(),
                ));
            }
            // checked here as on the hub (the hub checks again): the screen, the reach, the size and the rate
            let (_, text, recipients) = st.mail.check(me.seams.screen.as_ref(), by, &p, now)?;
            let id = new_id();
            let thread = p.thread.clone().unwrap_or_else(|| {
                p.reply_to
                    .as_deref()
                    .and_then(|r| st.mail.thread_of(&by.me, r))
                    .unwrap_or_else(|| id.clone())
            });
            let from = st.local.get(&by.me).map(super::model::Attribution::of);
            let msg = Message {
                id: id.clone(),
                thread,
                reply_to: p.reply_to.clone(),
                from: by.me.clone(),
                to: p.to.first().cloned().unwrap_or_else(|| by.me.clone()),
                recipient: by.me.clone(),
                text: text.clone(),
                sent_ms: now,
                seq: 0,
                attribution: from.ok_or_else(unavailable)?,
                state: DeliveryState::Queued,
            };
            let mut post = p;
            post.text = text;
            let hub = me.hub_ep();
            enqueue(
                &mut st.core,
                &hub,
                K_POST,
                &PostFrame {
                    id: id.clone(),
                    by: by.me.clone(),
                    post,
                },
            )?;
            let sent = Sent {
                msg,
                recipients: recipients
                    .into_iter()
                    .map(|a| (a, DeliveryState::Queued))
                    .collect(),
                refused: None,
                version: 1,
            };
            let r = receipt(&sent);
            st.mail.sent.insert(id, sent);
            Ok(r)
        })
    }

    fn get(
        &self,
        by: &Reach,
        after: u64,
        limit: usize,
        wait_ms: u64,
        now: u64,
    ) -> Result<Batch, FabricError> {
        if wait_ms > 0 {
            drop(wait_for(&self.state, &self.cv, wait_ms, |st| {
                has_after(&st.mail, &by.me, after)
            })?);
        }
        self.change(now, |_, st| {
            if !st.local.contains_key(&by.me) {
                return Err(FabricError::Refused(
                    "only an agent on this box reads from it".into(),
                ));
            }
            let b = st.mail.get(by, after, limit);
            for m in &b.messages {
                if m.state == DeliveryState::Delivered {
                    st.receipts.delivered.push((by.me.clone(), m.id.clone()));
                }
            }
            Ok(b)
        })
    }

    fn thread(&self, by: &Reach, thread: &str, _now: u64) -> Result<Vec<Message>, FabricError> {
        let st = self.state.lock().map_err(|_| unavailable())?;
        if !st.local.contains_key(&by.me) {
            return Err(FabricError::Refused(
                "only an agent on this box reads from it".into(),
            ));
        }
        Ok(st.mail.thread(by, thread))
    }

    fn ack(&self, by: &Reach, ids: &[String], now: u64) -> Result<usize, FabricError> {
        self.change(now, |_, st| {
            if !st.local.contains_key(&by.me) {
                return Err(FabricError::Refused(
                    "only an agent on this box reads from it".into(),
                ));
            }
            let before: BTreeSet<String> = st
                .mail
                .boxes
                .get(&by.me)
                .map(|b| {
                    b.msgs
                        .iter()
                        .filter(|m| m.state != DeliveryState::Read)
                        .map(|m| m.id.clone())
                        .collect()
                })
                .unwrap_or_default();
            let n = st.mail.ack(by, ids);
            for id in ids.iter().filter(|i| before.contains(*i)) {
                st.receipts.read.push((by.me.clone(), id.clone()));
            }
            Ok(n)
        })
    }

    fn participants(&self, by: &Reach, _now: u64) -> Result<Vec<ParticipantView>, FabricError> {
        let st = self.state.lock().map_err(|_| unavailable())?;
        let r = st.mail.reach_of(by)?;
        Ok(st.mail.participants(&r))
    }

    fn sent(&self, by: &Reach, id: &str) -> Result<Vec<(Address, DeliveryState)>, FabricError> {
        let st = self.state.lock().map_err(|_| unavailable())?;
        st.mail.sent_states(by, id)
    }

    fn walls(&self) -> Option<Walls> {
        self.state.lock().ok().map(|s| s.walls.clone())
    }

    fn propose(&self, by: &Reach, p: NewProposal, now: u64) -> Result<String, FabricError> {
        self.change(now, |me, st| {
            let reg = st.local.get(&by.me).ok_or_else(|| {
                FabricError::Refused("only an agent on this box proposes from it".into())
            })?;
            if !Reach::of(reg).reads_wall(&p.scope) {
                return Err(FabricError::Refused(format!(
                    "{} is not bound to this session",
                    p.scope
                )));
            }
            let text = format!("{}\n{}\n{}", p.title, p.body, p.tags.join(" "));
            if let Some(kind) = me.seams.screen.find(&text) {
                return Err(FabricError::Refused(format!(
                    "the note looks like it holds {kind}, so it was not proposed"
                )));
            }
            let id = new_id();
            let proposal = Proposal {
                id: id.clone(),
                by: by.me.clone(),
                person: reg.person.clone(),
                from_box: me.box_name.clone(),
                note: p,
            };
            let hub = me.hub_ep();
            enqueue(&mut st.core, &hub, K_PROPOSE, &ProposeFrame { proposal })?;
            Ok(id)
        })
    }
}
