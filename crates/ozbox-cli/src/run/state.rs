//! `ozbox state`: where each box's OpenTofu state lives (ADR 0033), and the safe move from this computer into the
//! encrypted bucket `ozbox init` made.
//!
//! `status` only reads. `migrate` is plan, print, confirm, apply like every change: per box it copies the local state into
//! the bucket, reads it back and compares it, and plans against the bucket, which must show no change
//! ([`ozbox_core::TofuModule::migrate_local_to_s3`]). The local files stay. Only with `--switch`, and only when no box is
//! left with state on this computer alone, does it set `state_backend = "s3"` in the configuration.

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;

use ozbox_core::tofu::{MigrateReport, S3State};
use ozbox_core::{BoxName, ModuleVars, TofuModule};
use ozbox_provider_aws::AwsBackend;
use ozbox_provider_hcloud::HcloudBackend;
use serde::Serialize;

use super::{print_json, CliError, Flags, Result};
use crate::cli::{ProviderKind, StateCommand};
use crate::config::Config;
use crate::messages::t;

/// How to describe a live box to the module.
type VarsFn = Box<dyn Fn(&BoxName) -> ozbox_core::Result<ModuleVars>>;

/// The module's runner (bucket-backed) and how to describe a live box to it, for one provider.
struct Target {
    section: &'static str,
    /// Runs OpenTofu against the bucket whatever the configuration currently says.
    tofu: TofuModule,
    vars: VarsFn,
    s3: S3State,
    /// Whether the configuration already keeps state in the bucket.
    switched: bool,
}

fn target(kind: ProviderKind, config: &Config) -> Result<Target> {
    let s3 = config
        .s3_state(kind, true)?
        .ok_or_else(|| CliError::Msg(t("state.err_real_only", &[])))?;
    let switched = config.s3_state(kind, false)?.is_some();
    Ok(match kind {
        ProviderKind::Aws => {
            let b = Arc::new(AwsBackend::new(
                Arc::new(ozbox_core::SystemRunner),
                super::aws_config(config, true)?,
            ));
            Target {
                section: "aws",
                tofu: b.tofu_module(),
                vars: Box::new(move |n| b.state_vars(n)),
                s3,
                switched,
            }
        }
        ProviderKind::Hcloud => {
            let b = Arc::new(HcloudBackend::new(
                Arc::new(ozbox_provider_hcloud::api::UreqApi::from_env()),
                Arc::new(ozbox_core::SystemRunner),
                super::hcloud_config(config, true)?,
            ));
            Target {
                section: "hcloud",
                tofu: b.tofu_module(),
                vars: Box::new(move |n| b.state_vars(n)),
                s3,
                switched,
            }
        }
        ProviderKind::Fake | ProviderKind::Plugin => {
            return Err(CliError::Msg(t("state.err_real_only", &[])))
        }
    })
}

fn join(v: &[String]) -> String {
    if v.is_empty() {
        t("state.none", &[])
    } else {
        v.join(", ")
    }
}

#[derive(Serialize)]
struct Status {
    backend: &'static str,
    bucket: String,
    region: String,
    local: Vec<String>,
    bucket_boxes: Vec<String>,
    not_copied: Vec<String>,
}

pub fn command(kind: ProviderKind, config: &Config, cmd: &StateCommand, f: &Flags) -> Result<()> {
    let tg = target(kind, config)?;
    match cmd {
        StateCommand::Status => status(&tg, f),
        StateCommand::Migrate { name, all, switch } => {
            migrate(kind, config, &tg, name, *all, *switch, f)
        }
    }
}

fn status(tg: &Target, f: &Flags) -> Result<()> {
    let local = tg.tofu.local_boxes();
    let (bucket_boxes, why) = match tg.tofu.workspaces() {
        Ok(v) => (v, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    let not_copied: Vec<String> = local
        .iter()
        .filter(|b| !bucket_boxes.contains(b))
        .cloned()
        .collect();
    if f.json {
        return print_json(&Status {
            backend: if tg.switched { "s3" } else { "local" },
            bucket: tg.s3.bucket.clone(),
            region: tg.s3.region.clone(),
            local,
            bucket_boxes,
            not_copied,
        });
    }
    if tg.switched {
        println!(
            "{}",
            t(
                "state.where_s3",
                &[("bucket", &tg.s3.bucket), ("region", &tg.s3.region)]
            )
        );
    } else {
        println!(
            "{}",
            t("state.where_local", &[("dir", "the ozbox state directory")])
        );
    }
    println!("{}", t("state.local_boxes", &[("boxes", &join(&local))]));
    match why {
        None => println!(
            "{}",
            t("state.bucket_boxes", &[("boxes", &join(&bucket_boxes))])
        ),
        Some(w) => println!("{}", t("state.bucket_unreadable", &[("why", &w)])),
    }
    if !not_copied.is_empty() {
        println!("{}", t("state.not_yet", &[("boxes", &join(&not_copied))]));
    }
    Ok(())
}

#[derive(Serialize)]
struct Outcome {
    migrated: Vec<MigrateReport>,
    switched: bool,
}

/// The boxes whose bucket copy must not become the live state yet, each with why, in words. Read-only.
fn switch_blockers(tofu: &TofuModule) -> Vec<String> {
    use ozbox_core::tofu::{bucket_copy_problem, SwitchProblem};
    let mut out = Vec::new();
    for b in tofu.local_boxes() {
        let Ok(name) = BoxName::new(&b) else {
            continue;
        };
        let why = match (
            tofu.local_state_summary(&name),
            tofu.bucket_state_summary(&name),
        ) {
            (Ok(None), _) => None,
            (Ok(Some(local)), Ok(bucket)) => {
                bucket_copy_problem(&local, bucket.as_ref()).map(|p| match p {
                    SwitchProblem::Missing => "state.why_missing",
                    SwitchProblem::Different => "state.why_different",
                    SwitchProblem::Stale => "state.why_stale",
                })
            }
            _ => Some("state.why_unreadable"),
        };
        if let Some(k) = why {
            out.push(format!("{b} ({})", t(k, &[])));
        }
    }
    out
}

fn migrate(
    kind: ProviderKind,
    config: &Config,
    tg: &Target,
    name: &Option<BoxName>,
    all: bool,
    switch: bool,
    f: &Flags,
) -> Result<()> {
    let boxes: Vec<BoxName> = match (name, all) {
        (Some(n), _) => vec![n.clone()],
        (None, true) => tg
            .tofu
            .local_boxes()
            .iter()
            .filter_map(|n| BoxName::new(n).ok())
            .collect(),
        (None, false) => return Err(CliError::Msg(t("state.need_target", &[]))),
    };
    if boxes.is_empty() {
        println!("{}", t("state.nothing", &[]));
        return Ok(());
    }
    let mut planned = Vec::new();
    for b in &boxes {
        match tg.tofu.local_state_summary(b)? {
            Some(s) => planned.push((b.clone(), s)),
            None => return Err(CliError::Msg(t("state.no_local", &[("box", b.as_str())]))),
        }
    }
    if !f.json {
        println!("{}", t("state.intro", &[]));
        for (b, s) in &planned {
            println!(
                "{}",
                t(
                    "state.line",
                    &[
                        ("box", b.as_str()),
                        ("resources", &s.resources.to_string()),
                        ("serial", &s.serial.to_string()),
                        ("bucket", &tg.s3.bucket),
                        ("key", &tg.tofu.remote_key(b).unwrap_or_default()),
                    ]
                )
            );
        }
        println!("{}", t("state.promise", &[]));
        println!(
            "{}",
            t(
                if switch {
                    "state.switch_note"
                } else {
                    "state.no_switch_note"
                },
                &[]
            )
        );
    }
    if f.dry_run {
        if !f.json {
            println!("{}", t("state.dry_run", &[]));
        }
        return Ok(());
    }
    if !f.yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Msg(t("state.err_confirm", &[])));
        }
        let mut err = std::io::stderr();
        let _ = write!(
            err,
            "{}",
            t("state.prompt", &[("n", &boxes.len().to_string())])
        );
        let _ = err.flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::Core(e.into()))?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::Msg(t("state.aborted", &[])));
        }
    }
    let mut done: Vec<MigrateReport> = Vec::new();
    for (b, _) in &planned {
        let step = (tg.vars)(b).and_then(|v| tg.tofu.migrate_local_to_s3(&v));
        match step {
            Ok(r) => {
                if !f.json {
                    println!(
                        "{}",
                        t(
                            "state.done_line",
                            &[
                                ("box", b.as_str()),
                                ("resources", &r.resources.to_string()),
                                (
                                    "already",
                                    &if r.already_there {
                                        t("state.already", &[])
                                    } else {
                                        String::new()
                                    }
                                ),
                            ]
                        )
                    );
                    if let Some(p) = &r.backup {
                        println!("{}", t("state.backup_line", &[("path", p)]));
                    }
                }
                done.push(r);
            }
            Err(e) => {
                return Err(CliError::Msg(t(
                    "state.failed_after",
                    &[
                        ("box", b.as_str()),
                        ("why", &e.to_string()),
                        ("done", &done.len().to_string()),
                    ],
                )))
            }
        }
    }
    let mut switched = false;
    if switch && !tg.switched {
        // Only when every box with state on this computer has a copy in the bucket that may be the live one: the same
        // state, or the same one written further on. A box with none would read "no state" afterwards; one whose copy
        // is older (changed here since it was copied) or another state would plan from the wrong resources.
        let left = switch_blockers(&tg.tofu);
        if left.is_empty() {
            let path = Config::path()
                .ok_or_else(|| CliError::Msg("cannot find the configuration file".into()))?;
            crate::config::set_provider_key(&path, tg.section, "state_backend", "s3")?;
            switched = true;
            if !f.json {
                println!("{}", t("state.switched", &[]));
            }
        } else if !f.json {
            println!(
                "{}",
                t("state.switch_refused", &[("boxes", &left.join(", "))])
            );
        }
    }
    let _ = (kind, config);
    if f.json {
        return print_json(&Outcome {
            migrated: done,
            switched,
        });
    }
    Ok(())
}
