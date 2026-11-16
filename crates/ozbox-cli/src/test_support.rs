//! Helpers the unit tests share.

use std::time::{Duration, Instant};

/// Runs `look` until it answers `Some`, for at most 10 s, and returns that answer. `None` after the deadline: the condition
/// never came true.
///
/// This is for ONE situation: a `flock`. A lock belongs to the open file, and the test binary is one process running many
/// tests on many threads, some of which start children (`git`, a command). A child holds a copy of every descriptor that was
/// open when it was forked until it has exec'd, so the instant after a test let go of its lock, a look from the same test can
/// still see it held. On a loaded machine that instant is long enough to see. Nothing is wrong with the lock: the question
/// "has the holder let go?" is answered by looking until it has, never by looking once.
///
/// It is bounded and it polls the condition itself, so it hides no failure: a lock that is really still held, or a test that
/// is really wrong, runs out the 10 s and fails. A test whose point IS that the lock is held does not use it (a held lock
/// needs no wait to be seen).
pub fn until<T>(mut look: impl FnMut() -> Option<T>) -> Option<T> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(v) = look() {
            return Some(v);
        }
        if Instant::now() >= end {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
