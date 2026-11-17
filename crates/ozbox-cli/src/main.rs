//! `ozbox`: the command line for Oz Box.

mod agent_mcp;
mod agent_mcp_cli;
mod approval_key;
mod approval_key_cli;
mod approval_keystore;
mod approval_laptop;
mod approval_requests;
mod approval_wait;
mod attestation;
mod audit_service;
mod auth_cli;
mod aws_native;
mod awscli;
mod backup_ops;
mod backups;
mod bill;
mod box_config;
mod box_egress;
mod box_secrets;
mod broker;
mod broker_cloud;
mod broker_paths;
mod browse_cli;
mod browser_launch;
mod browser_tools;
mod capped;
mod channels;
mod chat;
mod cli;
mod code;
mod code_cli;
mod config;
mod cost_cli;
mod cost_demo;
mod dashboard_cli;
mod dashboard_keep;
mod egress;
mod egress_guard;
mod guard;
mod guard_cli;
mod guard_diff;
mod guard_hold;
mod guard_scan;
mod helper_refresh;
mod host_guard_cli;
mod host_tools;
mod import_report;
mod infra_cli;
mod ingress_cli;
mod ingress_client;
mod ingress_guard;
mod init;
mod init_cli;
mod local_ai;
mod mcp;
mod memory_cli;
mod memory_guard;
mod memory_tools;
mod mesh;
mod mesh_cli;
mod messages;
mod messages_adopt_key;
mod messages_agent;
mod messages_alerts;
mod messages_backup;
mod messages_chat;
mod messages_code;
mod messages_cost;
mod messages_hardening;
mod messages_infra;
mod messages_models;
mod messages_notice;
mod messages_old_disk;
mod messages_orch;
mod messages_perm;
mod messages_quiesce;
mod messages_runs;
mod messages_sched;
mod messages_secrets;
mod messages_tunnel;
mod messages_v1;
mod metadata_guard;
mod model_engines;
mod model_prices;
mod model_providers;
mod model_usage;
mod models;
mod models_cli;
mod netguard;
mod notice;
mod notify;
mod notify_config;
mod orch_cli;
mod orch_tools;
mod orphans;
mod patch_guard;
mod peer_uid;
mod perm_cli;
#[cfg(unix)]
mod pin_fetch;
mod plugin_cli;
mod pricing;
mod profiles;
mod quiesce;
mod request_file;
mod restore_new;
mod run;
mod runner;
#[cfg(test)]
mod runner_acceptance;
mod runner_egress;
mod runner_imports;
mod runner_pins;
mod runner_setup;
mod runs_cli;
mod sched;
mod sched_cli;
mod secrets;
mod secrets_adopt;
mod secrets_adopt_facts;
mod secrets_approval;
#[cfg(test)]
mod secrets_audit_tests;
mod secrets_cli;
mod secrets_enc;
mod secrets_escrow;
mod secrets_file;
mod secrets_ingress;
mod secrets_persist;
mod secrets_recover;
mod secrets_restic;
#[cfg(unix)]
mod secrets_service;
mod secrets_state;
mod serve;
mod settings;
mod ssh_limits;
mod sshconfig;
mod state;
#[cfg(test)]
mod systemd_props_guard;
mod telegram;
mod telegram_store;
mod telegram_transcript;
mod telemetry;
mod telemetry_cli;
#[cfg(test)]
mod test_support;
mod this_box;
mod timezone;
mod tokenmac;
mod tools_cli;
mod tunnel;
mod tunnel_cli;
mod workload;
mod workload_cli;
mod workload_policy;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // clap prints usage errors and exits with 2 (and `--help` / `--version` with 0).
    let args = cli::Cli::parse();
    let is_telemetry = matches!(
        args.command,
        cli::Command::Telemetry { .. } | cli::Command::BuildInfo
    );
    match run::run(args) {
        Ok(()) => {
            telemetry_cli::after_command(is_telemetry);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
