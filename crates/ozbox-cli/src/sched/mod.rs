//! Schedules and triggers: cron-style scheduled runs and signed inbound webhooks, both handed to one run system.
//!
//! The store, the lease and the guarantee are in [`store`]; the decisions in [`engine`]; the time words in [`cron`] and
//! [`plain`]; webhooks in [`hooks`] and [`receive`]. A run is started only through [`runner::RunStarter`].

pub mod core_runs;
pub mod cron;
pub mod engine;
pub mod hooks;
pub mod input;
pub mod model;
pub mod plain;
pub mod receive;
pub mod runner;
pub mod shared;
pub mod store;
pub mod view;

#[cfg(test)]
mod tests;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
