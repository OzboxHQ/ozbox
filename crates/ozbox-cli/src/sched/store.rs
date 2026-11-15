//! The fleet store for schedules and triggers: one JSON document, changed only as one atomic read-modify-write.
//!
//! **The guarantee.** A (schedule, slot) pair fires at most once, however many dashboards run, on one computer or two,
//! however a failover goes, because three things happen inside one atomic read-modify-write of the document:
//!
//! 1. *The lease.* One holder at a time. Taking it, or retaking it after it lapsed, raises the `epoch`.
//! 2. *The fence.* A claim is accepted only if the claimer is the current holder, with the current epoch, and its own
//!    lease clock has not lapsed. A holder that was paused and woke up after another took over carries an old epoch and
//!    is refused.
//! 3. *The claim.* `<schedule>@<slot>` is written once; a second claim for it is refused whoever makes it.
//!
//! **Where the document lives.** Beside the configuration, under a lock file (two `ozbox serve` processes on one
//! computer), or, when a shared object is configured ([`super::shared`]), in that object, written with compare-and-swap:
//! a writer that lost a race reads again and redoes its change, so two computers share one lease the same way two
//! processes do. The closure given to [`Store::update`] may therefore run more than once; it must be a pure function of
//! the document it is given.
//!
//! **Time.** A holder renews with a `beat` counter. A would-be taker never compares the holder's clock with its own:
//! it writes down, in the document, *its own* clock reading the first time it saw each beat, and takes over only when
//! the beat has not moved for [`LEASE_MS`] by that same clock. Two computers whose clocks disagree by hours therefore
//! neither steal a live lease nor wait forever on a dead one.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::model::{Claim, Doc, Lease};
use super::shared::{Put, Shared};

/// How long a lease lasts without renewal. The holder renews about every five seconds.
pub const LEASE_MS: u64 = 30_000;
const LOCK_STALE: Duration = Duration::from_secs(10);
const LOCK_WAIT: Duration = Duration::from_secs(5);
/// A shared read is reused this long, so a page of requests does not make a page of network calls.
const CACHE_FOR: Duration = Duration::from_millis(1_500);
const CAS_TRIES: usize = 12;

#[derive(Debug, Clone)]
pub struct Store {
    path: PathBuf,
    shared: Option<Arc<dyn Shared>>,
    cache: Arc<Mutex<Option<(Instant, Doc)>>>,
}

/// Why a claim was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimError {
    /// Not the lease holder, a stale epoch, or the lease lapsed.
    Fenced,
    /// The slot was claimed already.
    Taken,
}

struct Guard(PathBuf);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Store {
            path: path.into(),
            shared: None,
            cache: Arc::default(),
        }
    }

    /// The same store, but kept in a shared object that other computers can write too. `path` stays as a local copy
    /// of the last document read, so the dashboard still starts with something when the object cannot be reached.
    pub fn with_shared(mut self, shared: Arc<dyn Shared>) -> Self {
        self.shared = Some(shared);
        self
    }

    #[cfg(test)]
    pub fn is_shared(&self) -> bool {
        self.shared.is_some()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".lock");
        PathBuf::from(p)
    }

    fn lock(&self) -> io::Result<Guard> {
        let lock = self.lock_path();
        if let Some(dir) = lock.parent() {
            fs::create_dir_all(dir)?;
        }
        let start = Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock)
            {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", std::process::id());
                    return Ok(Guard(lock));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&lock)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > LOCK_STALE);
                    if stale {
                        let _ = fs::remove_file(&lock);
                        continue;
                    }
                    if start.elapsed() > LOCK_WAIT {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "store is busy"));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn read_local(&self) -> Doc {
        fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// The document as last written (no lock: a local write is an atomic rename). Missing or unreadable is empty. With a
    /// shared object this is the object's current document (up to a second or two old), or the last copy if it is down.
    pub fn read(&self) -> Doc {
        let Some(sh) = &self.shared else {
            return self.read_local();
        };
        if let Ok(c) = self.cache.lock() {
            if let Some((at, d)) = c.as_ref() {
                if at.elapsed() < CACHE_FOR {
                    return d.clone();
                }
            }
        }
        match sh.get() {
            Ok(Some((bytes, _))) => {
                let d: Doc = serde_json::from_slice(&bytes).unwrap_or_default();
                self.remember(&d);
                d
            }
            Ok(None) => Doc::default(),
            Err(_) => self.read_local(),
        }
    }

    fn remember(&self, d: &Doc) {
        if let Ok(mut c) = self.cache.lock() {
            *c = Some((Instant::now(), d.clone()));
        }
        let _ = self.write_local(d);
    }

    fn write_local(&self, doc: &Doc) -> io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(doc).map_err(io::Error::other)?;
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &self.path)
    }

    /// Change the document as one atomic step. With a shared object, a write that another computer beat to the object is
    /// refused with `WouldBlock` (the caller reads again and decides); [`Store::update_retry`] redoes the change itself.
    pub fn update<R>(&self, f: impl FnOnce(&mut Doc) -> R) -> io::Result<R> {
        let mut f = Some(f);
        self.apply(1, &mut |d| f.take().map(|f| f(d)))?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "changed on another computer; try again",
                )
            })
    }

    /// Like [`Store::update`], but `f` may run again on a fresh document when another computer wrote first, so it must
    /// depend only on the document it is given. The lease, the claims and run bookkeeping use this.
    pub fn update_retry<R>(&self, mut f: impl FnMut(&mut Doc) -> R) -> io::Result<R> {
        self.apply(CAS_TRIES, &mut |d| Some(f(d)))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "store is busy"))
    }

    fn apply<R>(
        &self,
        tries: usize,
        f: &mut dyn FnMut(&mut Doc) -> Option<R>,
    ) -> io::Result<Option<R>> {
        let Some(sh) = &self.shared else {
            let _g = self.lock()?;
            let mut doc = self.read_local();
            let r = f(&mut doc);
            self.write_local(&doc)?;
            return Ok(r);
        };
        for attempt in 0..tries {
            let (mut doc, version) = match sh.get()? {
                Some((b, v)) => (serde_json::from_slice(&b).unwrap_or_default(), Some(v)),
                None => (Doc::default(), None),
            };
            let Some(r) = f(&mut doc) else {
                return Ok(None);
            };
            let bytes = serde_json::to_vec(&doc).map_err(io::Error::other)?;
            match sh.put_if(version.as_deref(), &bytes)? {
                Put::Done(_) => {
                    self.remember(&doc);
                    return Ok(Some(r));
                }
                Put::Conflict => {
                    // A short, different pause per try keeps two writers from colliding forever.
                    std::thread::sleep(Duration::from_millis(5 + (attempt as u64) * 7));
                }
            }
        }
        Ok(None)
    }

    /// Take or renew the lease for `me`. `Some(epoch)` when `me` holds it after the call.
    #[cfg(test)]
    pub fn acquire(&self, me: &str, now_ms: u64) -> io::Result<Option<u64>> {
        self.update_retry(|d| acquire(d, me, now_ms))
    }

    /// Fire a slot: `Ok(())` only for the current lease holder with the current epoch, and only the first time.
    #[cfg(test)]
    pub fn claim(
        &self,
        schedule_id: &str,
        slot_ms: u64,
        me: &str,
        epoch: u64,
        now_ms: u64,
    ) -> io::Result<Result<(), ClaimError>> {
        self.update_retry(|d| claim(d, schedule_id, slot_ms, me, epoch, now_ms))
    }
}

/// The lease rule, on a document already held atomically. `now_ms` is this computer's own clock and is compared only
/// with readings of this same computer's clock.
pub fn acquire(doc: &mut Doc, me: &str, now_ms: u64) -> Option<u64> {
    match &mut doc.lease {
        Some(l) if l.holder == me => {
            l.beat += 1;
            l.expires_ms = now_ms + LEASE_MS;
            l.watchers.clear();
            Some(l.epoch)
        }
        Some(l) if l.expires_ms != 0 => {
            // Someone else holds it. Write down when *I* first saw this beat; take over when it has not moved for a
            // full lease by my own clock.
            let seen = l.watchers.entry(me.to_string()).or_insert((l.beat, now_ms));
            if seen.0 != l.beat {
                *seen = (l.beat, now_ms);
            }
            if now_ms.saturating_sub(seen.1) < LEASE_MS {
                return None;
            }
            let epoch = l.epoch + 1;
            doc.lease = Some(Lease::new(me, epoch, now_ms));
            Some(epoch)
        }
        other => {
            // None, or released on purpose (`expires_ms == 0`): free to take at once.
            let epoch = other.as_ref().map_or(1, |l| l.epoch + 1);
            *other = Some(Lease::new(me, epoch, now_ms));
            Some(epoch)
        }
    }
}

/// Give the lease up, so another dashboard takes over at once instead of after the lease lapses.
pub fn release(doc: &mut Doc, me: &str) {
    if let Some(l) = doc.lease.as_mut().filter(|l| l.holder == me) {
        l.expires_ms = 0;
    }
}

pub fn claim(
    doc: &mut Doc,
    schedule_id: &str,
    slot_ms: u64,
    me: &str,
    epoch: u64,
    now_ms: u64,
) -> Result<(), ClaimError> {
    let held = doc
        .lease
        .as_ref()
        .is_some_and(|l| l.holder == me && l.epoch == epoch && l.expires_ms > now_ms);
    if !held {
        return Err(ClaimError::Fenced);
    }
    let key = format!("{schedule_id}@{slot_ms}");
    if doc.claims.contains_key(&key) {
        return Err(ClaimError::Taken);
    }
    doc.claims.insert(
        key,
        Claim {
            holder: me.to_string(),
            epoch,
            ts_ms: now_ms,
        },
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sched::shared::MemShared;
    use std::sync::{Arc, Barrier};

    fn store(dir: &Path) -> Store {
        Store::new(dir.join("fleet-schedules.json"))
    }

    /// Two computers, each with its own local copy, sharing one object.
    fn two(dir: &Path) -> (Arc<MemShared>, Store, Store) {
        let m = MemShared::new();
        let a = Store::new(dir.join("a.json")).with_shared(m.handle("a"));
        let b = Store::new(dir.join("b.json")).with_shared(m.handle("b"));
        (m, a, b)
    }

    #[test]
    fn one_holder_at_a_time_and_the_epoch_rises_on_every_handover() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        assert_eq!(s.acquire("a", 1_000).unwrap(), Some(1));
        assert_eq!(s.acquire("b", 2_000).unwrap(), None, "a still holds it");
        assert_eq!(
            s.acquire("a", 10_000).unwrap(),
            Some(1),
            "renewing keeps the epoch"
        );
        // b saw beat 1 for the first time here, then it never moves again; a lease later b takes over.
        assert_eq!(s.acquire("b", 11_000).unwrap(), None);
        assert_eq!(
            s.acquire("b", 11_000 + LEASE_MS - 1).unwrap(),
            None,
            "not yet a full lease"
        );
        assert_eq!(s.acquire("b", 11_000 + LEASE_MS).unwrap(), Some(2));
        assert_eq!(s.acquire("a", 11_000 + LEASE_MS + 1).unwrap(), None);
        // b releases: a takes it at once, with a higher epoch still.
        s.update(|doc| release(doc, "b")).unwrap();
        assert_eq!(s.acquire("a", 12_000 + LEASE_MS).unwrap(), Some(3));
    }

    #[test]
    fn a_stale_holder_is_fenced_and_a_slot_fires_once() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let e1 = s.acquire("a", 0).unwrap().unwrap();
        assert_eq!(s.claim("s1", 100, "a", e1, 10).unwrap(), Ok(()));
        assert_eq!(
            s.claim("s1", 100, "a", e1, 11).unwrap(),
            Err(ClaimError::Taken)
        );
        // a is paused (a laptop lid); b watches, then takes over.
        assert_eq!(s.acquire("b", 20).unwrap(), None);
        let e2 = s.acquire("b", 20 + LEASE_MS).unwrap().unwrap();
        assert!(e2 > e1);
        // a wakes up and tries to fire with its old epoch: fenced, even for a slot nobody has claimed.
        assert_eq!(
            s.claim("s1", 200, "a", e1, 21 + LEASE_MS).unwrap(),
            Err(ClaimError::Fenced)
        );
        assert_eq!(s.claim("s1", 200, "b", e2, 21 + LEASE_MS).unwrap(), Ok(()));
        // a holder whose own lease clock lapsed cannot fire either.
        assert_eq!(
            s.claim("s1", 300, "b", e2, 10 * LEASE_MS).unwrap(),
            Err(ClaimError::Fenced)
        );
    }

    #[test]
    fn two_contenders_never_fire_a_slot_twice() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("fleet-schedules.json");
        let barrier = Arc::new(Barrier::new(2));
        let mut hands = Vec::new();
        for who in ["dash-a", "dash-b"] {
            let (p, b) = (path.clone(), Arc::clone(&barrier));
            hands.push(std::thread::spawn(move || {
                let s = Store::new(p);
                b.wait();
                let mut won = Vec::new();
                for round in 0..60u64 {
                    let now = round * 1_000; // well inside one lease
                    let Some(epoch) = s.acquire(who, now).unwrap() else {
                        continue;
                    };
                    for slot in 0..5u64 {
                        if s.claim("sched", round * 10 + slot, who, epoch, now)
                            .unwrap()
                            .is_ok()
                        {
                            won.push(round * 10 + slot);
                        }
                    }
                }
                won
            }));
        }
        let results: Vec<Vec<u64>> = hands.into_iter().map(|h| h.join().unwrap()).collect();
        let mut all: Vec<u64> = results.concat();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "a slot was claimed twice");
        assert!(n > 0 && n <= 300);
    }

    // ----- two computers -----

    #[test]
    fn two_computers_share_one_lease_and_a_change_made_on_one_is_seen_on_the_other() {
        let d = tempfile::tempdir().unwrap();
        let (_m, a, b) = two(d.path());
        assert_eq!(a.acquire("a", 1_000).unwrap(), Some(1));
        assert_eq!(
            b.acquire("b", 1_000).unwrap(),
            None,
            "the other computer holds it"
        );
        a.update(|doc| {
            doc.claims.insert(
                "s@1".into(),
                Claim {
                    holder: "a".into(),
                    epoch: 1,
                    ts_ms: 1,
                },
            )
        })
        .unwrap();
        std::thread::sleep(CACHE_FOR + Duration::from_millis(50));
        assert!(b.read().claims.contains_key("s@1"));
        assert_eq!(
            b.claim("s", 1, "b", 1, 1_000).unwrap(),
            Err(ClaimError::Fenced)
        );
    }

    #[test]
    fn clock_skew_of_hours_neither_steals_a_live_lease_nor_waits_forever_on_a_dead_one() {
        let d = tempfile::tempdir().unwrap();
        let (_m, a, b) = two(d.path());
        for skew in [3 * 3_600_000i64, -(3 * 3_600_000i64)] {
            let t_a = 10_000_000u64;
            let t_b = (t_a as i64 + skew) as u64;
            let e = a.acquire("a", t_a).unwrap().unwrap();
            // a keeps renewing for a minute; b ticks every 5 s on its own, very wrong, clock.
            for i in 0..12u64 {
                a.acquire("a", t_a + i * 5_000).unwrap();
                assert_eq!(
                    b.acquire("b", t_b + i * 5_000 + 1).unwrap(),
                    None,
                    "skew {skew}: stole a live lease"
                );
            }
            // a stops. b keeps ticking and takes over one lease after it last saw a beat move, by b's clock.
            let stopped = t_b + 60_000;
            let mut took = None;
            for i in 0..40u64 {
                if let Some(epoch) = b.acquire("b", stopped + i * 5_000).unwrap() {
                    took = Some((i * 5_000, epoch));
                    break;
                }
            }
            let (after, epoch) = took.unwrap_or_else(|| panic!("skew {skew}: never took over"));
            assert!(after <= LEASE_MS + 5_000, "skew {skew}: took {after} ms");
            assert!(epoch > e);
            // put it back for the next skew: a retakes after b releases.
            b.update(|doc| release(doc, "b")).unwrap();
            a.acquire("a", t_a + 10_000_000).unwrap();
            b.update(|doc| release(doc, "a")).unwrap();
        }
    }

    #[test]
    fn a_partitioned_holder_cannot_fire_and_the_other_computer_takes_over_without_a_double_fire() {
        let d = tempfile::tempdir().unwrap();
        let (m, a, b) = two(d.path());
        let e1 = a.acquire("a", 0).unwrap().unwrap();
        assert_eq!(a.claim("nightly", 100, "a", e1, 1).unwrap(), Ok(()));
        // a's network goes down: it can neither renew nor claim.
        m.cut("a", true);
        assert!(a.acquire("a", 5_000).is_err());
        assert!(a.claim("nightly", 200, "a", e1, 5_000).is_err());
        // b sees a's beat stop moving and takes over after a lease.
        assert_eq!(b.acquire("b", 10_000).unwrap(), None);
        let e2 = b.acquire("b", 10_000 + LEASE_MS).unwrap().unwrap();
        assert!(e2 > e1);
        // the slot a already fired is not fired again; the next one is b's.
        assert_eq!(
            b.claim("nightly", 100, "b", e2, 10_000 + LEASE_MS).unwrap(),
            Err(ClaimError::Taken)
        );
        assert_eq!(
            b.claim("nightly", 200, "b", e2, 10_000 + LEASE_MS).unwrap(),
            Ok(())
        );
        // a comes back (its process never noticed it was cut off) and tries with its old epoch, and with a wall clock
        // that says its lease is still good: refused, because the document names b.
        m.cut("a", false);
        assert_eq!(
            a.claim("nightly", 300, "a", e1, 6_000).unwrap(),
            Err(ClaimError::Fenced)
        );
        assert_eq!(
            a.claim("nightly", 200, "a", e1, 6_000).unwrap(),
            Err(ClaimError::Fenced)
        );
        // and a rejoining as a contender does not win the lease back while b renews.
        assert_eq!(a.acquire("a", 20_000 + LEASE_MS).unwrap(), None);
        assert_eq!(b.acquire("b", 20_000 + LEASE_MS).unwrap(), Some(e2));
    }

    /// One tick of one computer at its own clock: take or renew the lease, then fire every slot that is due and not yet
    /// fired. Returns the slots this computer fired.
    fn tick(s: &Store, who: &str, clock_ms: u64, due_rounds: u64) -> Vec<u64> {
        // One atomic step, as the engine does it: renew or take the lease, then claim what is due.
        s.update_retry(|d| {
            let mut won = Vec::new();
            let Some(epoch) = acquire(d, who, clock_ms) else {
                return won;
            };
            for round in 0..due_rounds {
                for slot in 0..4u64 {
                    let id = round * 10 + slot;
                    if claim(d, "sched", id, who, epoch, clock_ms).is_ok() {
                        won.push(id);
                    }
                }
            }
            won
        })
        .unwrap()
    }

    #[test]
    fn two_computers_ticking_in_turn_fire_each_slot_exactly_once_and_the_live_holder_keeps_them_all(
    ) {
        // No threads and no wall clock: a fixed order, each computer on its own clock.
        let d = tempfile::tempdir().unwrap();
        let m = MemShared::new();
        let a = Store::new(d.path().join("a.json")).with_shared(m.handle("a"));
        let b = Store::new(d.path().join("b.json")).with_shared(m.handle("b"));
        let (mut won_a, mut won_b) = (Vec::new(), Vec::new());
        for round in 0..40u64 {
            // b's clock is hours off; it must not matter.
            won_a.extend(tick(&a, "a", round * 1_000, round + 1));
            won_b.extend(tick(&b, "b", 7 * 3_600_000 + round * 1_000, round + 1));
        }
        assert!(won_b.is_empty(), "b stole a live lease");
        let mut all = won_a.clone();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), won_a.len(), "a slot fired twice");
        assert_eq!(all.len(), 160, "every slot fired once, none lost");
    }

    #[test]
    fn a_seeded_interleaving_with_a_holder_that_dies_fires_every_slot_exactly_once() {
        for seed in 1..=12u64 {
            let d = tempfile::tempdir().unwrap();
            let m = MemShared::new();
            let a = Store::new(d.path().join("a.json")).with_shared(m.handle("a"));
            let b = Store::new(d.path().join("b.json")).with_shared(m.handle("b"));
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut next = move || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let dies_at = 10 + next() % 40;
            let (mut ca, mut cb) = (0u64, 5 * 3_600_000u64);
            let mut fired: Vec<u64> = Vec::new();
            // 300 steps; whoever goes next is random, each on its own clock that moves 1 s per own tick. The slots due
            // grow with the computer's own tick count, so a late computer catches up on everything before it.
            let mut ta = 0u64;
            for _ in 0..300 {
                if next() % 2 == 0 && ta < dies_at {
                    ta += 1;
                    ca += 1_000;
                    fired.extend(tick(&a, "a", ca, 40));
                } else {
                    cb += 1_000;
                    fired.extend(tick(&b, "b", cb, 40));
                }
            }
            // b ticked well over a lease alone after a stopped, far beyond one lease, so it holds and has caught up.
            let mut all = fired.clone();
            all.sort_unstable();
            all.dedup();
            assert_eq!(all.len(), fired.len(), "seed {seed}: a slot fired twice");
            assert_eq!(all.len(), 160, "seed {seed}: a slot was lost");
        }
    }

    #[test]
    fn a_computer_that_cannot_reach_the_object_still_reads_its_last_copy() {
        let d = tempfile::tempdir().unwrap();
        let (m, a, _b) = two(d.path());
        a.update(|doc| {
            doc.claims.insert(
                "x@1".into(),
                Claim {
                    holder: "a".into(),
                    epoch: 1,
                    ts_ms: 1,
                },
            )
        })
        .unwrap();
        m.cut("a", true);
        std::thread::sleep(CACHE_FOR + Duration::from_millis(50));
        assert!(
            a.read().claims.contains_key("x@1"),
            "the last copy, not an empty document"
        );
        assert!(a.update(|_| ()).is_err(), "but it cannot change anything");
    }
}
