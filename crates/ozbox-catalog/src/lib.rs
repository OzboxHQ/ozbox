#![cfg_attr(test, allow(clippy::unwrap_used))]
//! The Oz Box tool catalog.
//!
//! A box ships small. Everything else a person might want (editors, AI agents, languages, cloud CLIs) is a *tool* in
//! this catalog: data, not code. Each tool says where it comes from, how that source is verified, how it is removed
//! and how it keeps itself up to date. A tool whose source could not be verified from its vendor's own documentation
//! is marked `verified = false` with the reason, and no plan will include it.
//!
//! This crate is pure: it parses and validates the catalog, and turns a request ("install these, remove those") into a
//! [`plan::Plan`], a list of concrete steps with argv arrays. It runs nothing. The box daemon executes plans.

pub mod model;
pub mod plan;
pub mod verify;

pub use model::{
    Arch, Bundle, Catalog, Group, Step, StepDef, Tool, UpdateHow, Updates, Verification,
    CATALOG_SCHEMA,
};
pub use plan::{
    Action, Op, Plan, PlanError, PlanRequest, PlanStep, PlanTool, Privilege, HOME_TOKEN,
};

/// The catalog compiled into this binary.
pub fn embedded() -> Result<Catalog, String> {
    Catalog::parse(include_str!("../../../catalog/catalog.toml"))
}
