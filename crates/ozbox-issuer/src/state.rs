//! The issuer's own record: small JSON documents with a version, written only if the version is the one the writer read
//! (compare-and-set). A use cannot be spent twice and an approval cannot be taken twice, because the second write loses.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// A write whose expected version was not the current one.
#[derive(Debug, PartialEq, Eq)]
pub struct Conflict;

pub trait StateStore {
    /// The current version and text of a document.
    fn get(&self, key: &str) -> Option<(u64, String)>;
    /// Write `value` only if the document is at `expected` (`None`: only if it does not exist). Returns the new version.
    fn put_if(&self, key: &str, expected: Option<u64>, value: &str) -> Result<u64, Conflict>;
}

/// A table in memory, for tests and for the issuer's own simulation.
#[derive(Default)]
pub struct MemoryState(Mutex<BTreeMap<String, (u64, String)>>);

impl StateStore for MemoryState {
    fn get(&self, key: &str) -> Option<(u64, String)> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
    }

    fn put_if(&self, key: &str, expected: Option<u64>, value: &str) -> Result<u64, Conflict> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let current = m.get(key).map(|(v, _)| *v);
        if current != expected {
            return Err(Conflict);
        }
        let next = current.map_or(1, |v| v + 1);
        m.insert(key.to_string(), (next, value.to_string()));
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_wins_only_from_the_version_it_read() {
        let s = MemoryState::default();
        assert_eq!(s.put_if("a", None, "1"), Ok(1));
        assert_eq!(s.put_if("a", None, "x"), Err(Conflict), "created twice");
        assert_eq!(s.put_if("a", Some(1), "2"), Ok(2));
        assert_eq!(
            s.put_if("a", Some(1), "stale"),
            Err(Conflict),
            "a stale write"
        );
        assert_eq!(s.get("a"), Some((2, "2".into())));
        assert!(s.get("b").is_none());
    }
}
