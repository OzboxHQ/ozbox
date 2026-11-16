#![cfg_attr(test, allow(clippy::unwrap_used))]
//! `ozboxd`, the Oz Box box daemon. Everything is a library module so it can be unit-tested; Linux-only
//! behaviour is behind `cfg(target_os = "linux")` and sits behind traits with fakes for tests.

pub mod agent_authority;
pub mod agent_events;
#[cfg(unix)]
pub mod agent_sessions;
pub mod api;
pub mod backup;
pub mod backup_root;
pub mod backup_service;
#[cfg(unix)]
pub mod backup_state;
pub mod checkpoint;
pub mod config;
pub mod files;
pub mod growfs;
pub mod health;
#[cfg(unix)]
pub mod hook_cli;
pub mod host;
pub mod http;
pub mod idle;
pub mod interruption;
pub mod local_ai;
pub mod metrics;
#[cfg(unix)]
pub mod pressure;
pub mod procs;
pub mod quiesce;
#[cfg(unix)]
pub mod run_backend;
#[cfg(unix)]
pub mod run_shim;
#[cfg(unix)]
pub mod run_units;
pub mod runs;
pub mod secrets_link;
pub mod selftest;
#[cfg(unix)]
pub mod session_resume;
pub mod skills;
pub mod store;
#[cfg(unix)]
pub mod terminal;
pub mod timeutil;
pub mod tools;
