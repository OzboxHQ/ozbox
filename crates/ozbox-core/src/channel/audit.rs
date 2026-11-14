//! Taking an end's audit events into the audit log, once and complete.
//!
//! Events are written into the state in the same write as the change they describe, each with a source number under the end's
//! `store_id`. They are handed to the log **under the store's lock**, and dropped from the state only by number: the log's last
//! source number says what it already holds, never a count taken from an earlier snapshot. Two processes draining at once
//! therefore cannot lose an event, and a retry after a crash cannot repeat one.
//!
//! A state restored from a backup starts a new `store_id` (see [`super::session::Core::restored`]). If instead the log is **ahead**
//! of the state for the *same* `store_id` (a rollback nobody acknowledged), [`guard`] refuses to go on, with a plain message,
//! because every new event would otherwise be skipped as "already logged".

use std::io;

use serde::de::DeserializeOwned;
use serde::Serialize;

use super::session::Core;
use super::store::{Store, StoreError};
use crate::audit::NewEvent;

/// Where audit events go. The audit trail holds kinds, ids and codes, never message text.
pub trait AuditSink: Send + Sync {
    /// Add events in order, as one write. Events whose source number the log already holds are skipped.
    fn record_many(&self, events: Vec<NewEvent>) -> io::Result<()>;
    /// The last source record in the log: the end's store id and number.
    fn last_src(&self) -> io::Result<Option<(String, u64)>>;
}

impl AuditSink for crate::audit::AuditLog {
    fn record_many(&self, events: Vec<NewEvent>) -> io::Result<()> {
        self.append_many(events).map(|_| ())
    }

    fn last_src(&self) -> io::Result<Option<(String, u64)>> {
        crate::audit::AuditLog::last_src(self)
    }
}

/// A state that holds a channel [`Core`].
pub trait HasCore {
    fn core(&self) -> &Core;
    fn core_mut(&mut self) -> &mut Core;
}

#[derive(Debug)]
pub struct JournalError(pub String);

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<StoreError> for JournalError {
    fn from(e: StoreError) -> Self {
        JournalError(e.to_string())
    }
}

/// Refuse to work when the audit log holds a newer record of this state than the state does: the state was rolled back.
pub fn guard(core: &Core, sink: &dyn AuditSink) -> Result<(), JournalError> {
    let last = sink
        .last_src()
        .map_err(|e| JournalError(format!("the audit log could not be read: {}", e.kind())))?;
    match last {
        Some((ep, n)) if ep == core.store_id && n > core.audit_n => Err(JournalError(
            "the audit log is ahead of this store, so the store looks restored from a backup; acknowledge the restore before going on"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Change the state under the store's lock, **once**: first drop the events the log already holds, then apply `f`, then write.
/// The events `f` adds stay pending in the state until [`drain`] takes them.
pub fn change<S, T>(
    store: &Store<S>,
    sink: &dyn AuditSink,
    f: impl FnOnce(&mut S) -> T,
) -> Result<T, JournalError>
where
    S: HasCore + Serialize + DeserializeOwned,
{
    // read before the lock: the log's last number only ever rises for one store id, so an early read is a safe lower bound
    let last = sink
        .last_src()
        .map_err(|e| JournalError(format!("the audit log could not be read: {}", e.kind())))?;
    Ok(store.update(|s| {
        s.core_mut().trim_logged(last.as_ref());
        f(s)
    })?)
}

/// Hand every pending event the log does not hold to the log, under the store's lock so no writer interleaves. Writes no state.
pub fn drain<S>(store: &Store<S>, sink: &dyn AuditSink) -> Result<(), JournalError>
where
    S: HasCore + Serialize + DeserializeOwned,
{
    let outcome = store.with_lock(|s| -> io::Result<()> {
        let core = s.core();
        if core.audit.is_empty() {
            return Ok(());
        }
        let last = sink.last_src()?;
        let pending: Vec<NewEvent> = core
            .audit
            .iter()
            .filter(|e| match (&e.src, &last) {
                (Some((ep, n)), Some((lep, ln))) => !(ep == lep && n <= ln),
                _ => true,
            })
            .cloned()
            .collect();
        sink.record_many(pending)
    })?;
    outcome.map_err(|e| JournalError(format!("the audit log could not be written: {}", e.kind())))
}
