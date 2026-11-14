//! Core types shared by every Oz Box component.
//!
//! The central idea is **plan, then apply**: every mutating operation is first turned into a [`Plan`] — a
//! list of concrete [`Change`]s — that is shown to the person before anything happens. Applying a plan that
//! is already satisfied is a no-op, so every command is idempotent and safe to retry.
//!
//! Providers (a cloud, a VPS host, or the in-memory fake used by tests) implement [`Provider`]. Nothing above
//! that trait knows which provider it is talking to.

pub mod adopt;
pub mod agent_engine;
pub mod agent_line;
pub mod approval;
pub mod approval_subject;
pub mod approval_verify;
pub mod approvals;
pub mod audit;
pub mod audit_remote;
pub mod backup_scope;
pub mod channel;
pub mod claude_code;
pub mod daemon_scope;
pub mod engine;
pub mod error;
pub mod exec;
pub mod filelock;
pub mod hub;
pub mod infra;
pub mod memory_plan;
pub mod metrics;
pub mod model_usage;
pub mod name;
pub mod orch;
pub mod orch_merge;
pub mod orch_rules;
pub mod permissions;
pub mod plan;
pub mod procs;
pub mod provider;
pub mod release;
pub mod roles;
pub mod run;
pub mod size;
pub mod spec;
pub mod supervisor;
pub mod tofu;
pub mod tool_gate;
pub mod upgrade_kind;

pub use engine::{
    Backend, CapacityRequest, Engine, MachineChoice, APPROVER_LABEL, FIRST_BOOT_LABEL,
    INGRESS_LABEL, RESUME_AFTER_LABEL, UPGRADE_TO_LABEL,
};
pub use error::{Error, Result};
pub use exec::{CommandRunner, CommandSpec, Output, RecordingRunner, SystemRunner};
pub use metrics::{GpuSample, MetricsSample, RunUsage};
pub use model_usage::ModelUsage;
pub use name::BoxName;
pub use plan::{Change, Operation, Plan, Risk};
pub use provider::{
    resolve_image, Capabilities, ImageInfo, OldWorkDisk, Provider, ResizeMethod, SnapshotInfo,
    SnapshotKind,
};
pub use release::{ReleaseKind, ReleaseVerifier, Verdict, DEFAULT_RELEASE_REPO};
pub use size::{GpuKind, Size, SizeSpec};
pub use spec::{BoxRecord, BoxSpec, BoxState, DiskGb};
pub use tofu::{
    check_applicable, check_replace_plan, ModuleOutputs, ModuleVars, ReplacePlan, TofuModule,
};
pub use upgrade_kind::{decide as decide_upgrade_kind, UpgradeKind, UpgradeRecord};
