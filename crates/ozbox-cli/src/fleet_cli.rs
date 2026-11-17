//! `ozbox fleet`: the owner's side of managing the fleet from a box's dashboard (ADR 0040, Amendment 2).
//!
//! - `fleet enable` makes the two fleet roles once (an administrator's sign-in, plan then apply) and records, on this computer,
//!   what the later commands pin: the box, its store, the credential holder's public key.
//! - `fleet window` opens a time-boxed change window for ONE plan: it shows what the session may do, asks, assumes
//!   `obx-fleet-change` with the plan-scoped session policy (only this computer's own sign-in is in that role's trust), signs the
//!   window with this computer's approval key and seals it to the holder. Nothing is sent without being shown.
//! - `fleet approvers sign` signs the list of passkeys that may confirm a fleet change; the holder trusts only this list.
//!
//! No credential is printed, put in an argument or written to disk here: the session lives in memory until it is sealed.

// Reached from the `fleet` command in `run`.
use std::io::Write;
use std::path::{Path, PathBuf};

use ozbox_core::fleet_approvers::{signed_bytes, Approver, ApproverSet, SignedApproverSet};
use ozbox_core::{CommandRunner, CommandSpec, Plan};
use ozbox_provider_aws::fleet_session::{self, WindowRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::fleet_gate::{operation_refusal, plan_hash};
use crate::fleet_holder::{seal_window, window_message, SessionCreds, WindowPayload};
use crate::init_cli::Ask;
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;

/// What this computer pins about one fleet manager. Public values only (no key, no credential).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetPins {
    pub box_id: String,
    pub store_id: String,
    /// The box the dashboard runs on: never changed from its own dashboard.
    pub fleet_box: String,
    /// The credential holder's public key (hex), pinned like the secrets service's key.
    pub holder_public: String,
    pub account_id: String,
    /// `SourceIdentity` is `ozbox-<person>`.
    pub person: String,
    /// The approval key in this computer's keychain that signs windows and approver lists.
    pub key_id: String,
}

pub fn pins_path() -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("fleet.json"))
}

pub fn load_pins(path: &Path) -> Result<FleetPins, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| CliError::Msg(t("fleet.cli_not_enabled", &[])))?;
    serde_json::from_str(&text).map_err(|_| CliError::Msg(t("fleet.cli_pins_damaged", &[])))
}

pub fn save_pins(path: &Path, p: &FleetPins) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(p).map_err(|e| CliError::Msg(e.to_string()))?;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| CliError::Msg(e.to_string()))?;
    }
    std::fs::write(path, text).map_err(|e| CliError::Msg(e.to_string()))
}

pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

fn say(f: &Flags, out: &mut dyn Write, text: String) {
    if !f.json {
        let _ = writeln!(out, "{text}");
    }
}

/// `30m`, `90s`, `1h`, or bare seconds.
pub fn parse_duration(s: &str) -> Option<u32> {
    let s = s.trim();
    let (n, mult) = match s.chars().last()? {
        'h' => (&s[..s.len() - 1], 3600),
        'm' => (&s[..s.len() - 1], 60),
        's' => (&s[..s.len() - 1], 1),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    n.parse::<u32>().ok()?.checked_mul(mult)
}

pub struct WindowArgs {
    pub plan_id: String,
    pub plan_file: PathBuf,
    pub window_secs: u32,
    pub profile: Option<String>,
    pub region: Option<String>,
    /// A clone launches its source's machine type, which the plan does not carry.
    pub machine_type: Option<String>,
    pub out: PathBuf,
}

/// Open a change window for one plan and write the sealed message for the credential holder.
#[allow(clippy::too_many_arguments)]
pub fn window(
    a: &WindowArgs,
    pins: &FleetPins,
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    ask: &mut dyn Ask,
    f: &Flags,
    now_secs: u64,
    out: &mut dyn Write,
) -> Result<Value, CliError> {
    let text = std::fs::read_to_string(&a.plan_file)
        .map_err(|_| CliError::Msg(t("fleet.cli_plan_unreadable", &[])))?;
    if text.len() > 1 << 20 {
        return Err(CliError::Msg(t("fleet.cli_plan_unreadable", &[])));
    }
    let plan: Plan = serde_json::from_str(&text)
        .map_err(|_| CliError::Msg(t("fleet.cli_plan_unreadable", &[])))?;
    operation_refusal(&plan.operation, &pins.fleet_box).map_err(|r| CliError::Msg(r.message))?;
    if plan.is_noop() {
        return Err(CliError::Msg(t("fleet.cli_plan_noop", &[])));
    }
    let grant = fleet_session::grant(&WindowRequest {
        operation: &plan.operation,
        account_id: &pins.account_id,
        plan_id: &a.plan_id,
        person: &pins.person,
        now_secs,
        window_secs: a.window_secs,
        machine_type: a.machine_type.as_deref(),
    })
    .map_err(CliError::Msg)?;
    let hash_hex = ozbox_core::audit::hex(&plan_hash(&plan));
    let box_name = plan.operation.box_name().to_string();
    say(
        f,
        out,
        t(
            "fleet.cli_window_shown",
            &[
                ("verb", plan.operation.verb()),
                ("box", &box_name),
                ("mins", &(a.window_secs.div_ceil(60)).to_string()),
                ("hash", &hash_hex[..12]),
            ],
        ),
    );
    for c in &plan.changes {
        say(f, out, format!("  {} {}", c.kind, c.description));
    }
    let summary = json!({
        "plan_id": a.plan_id,
        "plan_hash": hash_hex,
        "box": box_name,
        "verb": plan.operation.verb(),
        "window_seconds": a.window_secs,
        "expires_at": fleet_session::rfc3339(grant.expires_at_secs),
        "role": grant.role_arn,
        "session_name": grant.role_session_name,
        "session_policy_chars": grant.session_policy.len(),
    });
    if f.dry_run {
        say(f, out, t("fleet.cli_window_dry", &[]));
        return Ok(json!({ "window": summary, "opened": false }));
    }
    if !f.yes {
        if !ask.interactive() {
            return Err(CliError::Msg(t("fleet.cli_window_need_yes", &[])));
        }
        let ans = ask.line(&t("fleet.cli_window_ask", &[]));
        if ans.as_deref().map(str::to_ascii_lowercase).as_deref() != Some("yes") {
            return Err(CliError::Msg(t("fleet.cli_window_declined", &[])));
        }
    }
    // the owner's approval key signs what the holder will read
    let seed = keys
        .get(&format!(
            "{}{}",
            crate::approval_key::KEYCHAIN_PREFIX,
            pins.key_id
        ))
        .map_err(|e| CliError::Msg(e.0))?
        .map(Zeroizing::new)
        .ok_or_else(|| CliError::Msg(t("fleet.cli_no_key", &[])))?;
    let expires_ms = grant.expires_at_secs * 1000;
    let signature = crate::approval_key::sign(
        &seed,
        &window_message(
            &pins.box_id,
            &pins.store_id,
            &a.plan_id,
            &hash_hex,
            &box_name,
            expires_ms,
        ),
    )
    .map_err(CliError::Msg)?;
    let holder = ozbox_seal::public_from_hex(&pins.holder_public)
        .map_err(|_| CliError::Msg(t("fleet.cli_pins_damaged", &[])))?;

    // the session, from this computer's own sign-in; the policy is not secret, the session is
    let mut args: Vec<String> = vec![
        "sts".into(),
        "assume-role".into(),
        "--role-arn".into(),
        grant.role_arn.clone(),
        "--role-session-name".into(),
        grant.role_session_name.clone(),
        "--source-identity".into(),
        grant.source_identity.clone(),
        "--policy".into(),
        grant.session_policy.clone(),
        "--duration-seconds".into(),
        grant.duration_secs.to_string(),
        "--output".into(),
        "json".into(),
    ];
    for (k, v) in &grant.tags {
        args.push("--tags".into());
        args.push(format!("Key={k},Value={v}"));
    }
    if let Some(p) = &a.profile {
        args.push("--profile".into());
        args.push(p.clone());
    }
    if let Some(r) = &a.region {
        args.push("--region".into());
        args.push(r.clone());
    }
    let reply = runner
        .run(&CommandSpec::new("aws").args(args))
        .map_err(|_| CliError::Msg(t("fleet.cli_assume_failed", &[])))?;
    if reply.status != Some(0) {
        return Err(CliError::Msg(t("fleet.cli_assume_failed", &[])));
    }
    let session = SessionCreds::from_sts_json(&reply.stdout).map_err(CliError::Msg)?;
    let payload = WindowPayload {
        plan_id: a.plan_id.clone(),
        plan_hash: hash_hex.clone(),
        window_box: box_name.clone(),
        expires_at_ms: expires_ms,
        signature,
        session,
    };
    let (enc, ct) =
        seal_window(&holder, &pins.box_id, &pins.store_id, &payload).map_err(CliError::Msg)?;
    drop(payload);
    let msg = json!({
        "op": "window",
        "plan_id": a.plan_id,
        "plan_hash": hash_hex,
        "enc": ozbox_core::approval_subject::to_hex(&enc),
        "ct": ozbox_core::approval_subject::to_hex(&ct),
    });
    std::fs::write(
        &a.out,
        serde_json::to_vec(&msg).map_err(|e| CliError::Msg(e.to_string()))?,
    )
    .map_err(|e| CliError::Msg(e.to_string()))?;
    say(
        f,
        out,
        t(
            "fleet.cli_window_opened",
            &[
                ("until", &fleet_session::rfc3339(grant.expires_at_secs)),
                ("file", &a.out.display().to_string()),
            ],
        ),
    );
    Ok(json!({ "window": summary, "opened": true, "sealed_message": a.out }))
}

/// The credentials file `fleet approvers sign` reads: the passkeys the dashboard lists, which the owner is vouching for.
#[derive(Debug, Deserialize)]
pub struct CredentialsFile {
    pub approvers: Vec<Approver>,
}

/// Sign the list of passkeys that may confirm a fleet change.
pub fn approvers_sign(
    pins: &FleetPins,
    keys: &dyn SecretStore,
    credentials: &Path,
    version: u64,
    out_file: &Path,
    now_ms: u64,
) -> Result<Value, CliError> {
    let text = std::fs::read_to_string(credentials)
        .map_err(|_| CliError::Msg(t("fleet.cli_creds_unreadable", &[])))?;
    let file: CredentialsFile = serde_json::from_str(&text)
        .map_err(|_| CliError::Msg(t("fleet.cli_creds_unreadable", &[])))?;
    if file.approvers.is_empty() {
        return Err(CliError::Msg(t("fleet.cli_creds_unreadable", &[])));
    }
    let set = ApproverSet {
        version,
        box_id: pins.box_id.clone(),
        store_id: pins.store_id.clone(),
        issued_at_ms: now_ms,
        approvers: file.approvers,
    };
    let set_text = set.to_text().map_err(CliError::Msg)?;
    let seed = keys
        .get(&format!(
            "{}{}",
            crate::approval_key::KEYCHAIN_PREFIX,
            pins.key_id
        ))
        .map_err(|e| CliError::Msg(e.0))?
        .map(Zeroizing::new)
        .ok_or_else(|| CliError::Msg(t("fleet.cli_no_key", &[])))?;
    let signature =
        crate::approval_key::sign(&seed, &String::from_utf8_lossy(&signed_bytes(&set_text)))
            .map_err(CliError::Msg)?;
    let signed = SignedApproverSet {
        set: set_text,
        signature,
    };
    let msg = json!({ "op": "approvers", "signed": signed });
    std::fs::write(
        out_file,
        serde_json::to_vec(&msg).map_err(|e| CliError::Msg(e.to_string()))?,
    )
    .map_err(|e| CliError::Msg(e.to_string()))?;
    Ok(json!({ "version": version, "people": set.approvers.len(), "file": out_file }))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The command line. `enable` and `window` run here, on the owner's computer; `apply-unit` and `holder-serve` are the box's.
pub fn run(
    command: &crate::cli::FleetCommand,
    yes: bool,
    dry_run: bool,
    json: bool,
) -> Result<(), CliError> {
    use crate::cli::{FleetApproversCommand as A, FleetCommand as C};
    let f = Flags { yes, dry_run, json };
    let print = |v: &Value| {
        if json {
            println!("{v}");
        }
    };
    match command {
        C::Enable {
            profile,
            region,
            window_permission_set,
            machine_types,
            image_ids,
            subnet_ids,
            fleet_box,
            max_volume_gb,
            max_iops,
            max_throughput,
            read_costs,
            box_id,
            store_id,
            holder_key,
            person,
            key,
        } => {
            // what is pinned is checked before anything is asked of the cloud
            if holder_key.is_some() != (box_id.is_some() && store_id.is_some()) {
                return Err(CliError::Msg(t("fleet.cli_pin_all_three", &[])));
            }
            if let Some(h) = holder_key {
                ozbox_seal::public_from_hex(h)
                    .map_err(|_| CliError::Msg(t("fleet.cli_pins_damaged", &[])))?;
            }
            let (v, account) =
                crate::init_cli::run_fleet_enable_real(&crate::init_cli::FleetEnableArgs {
                    profile: profile.clone(),
                    region: region.clone(),
                    opts: crate::init::FleetOpts {
                        regions: region.iter().cloned().collect(),
                        machine_types: machine_types.clone(),
                        image_ids: image_ids.clone(),
                        subnet_ids: subnet_ids.clone(),
                        window_permission_set: window_permission_set.clone(),
                        fleet_manager_box: fleet_box.to_string(),
                        max_volume_gb: *max_volume_gb,
                        max_iops: *max_iops,
                        max_throughput: *max_throughput,
                        read_costs: *read_costs,
                    },
                    yes,
                    dry_run,
                    json,
                })
                .map_err(CliError::Msg)?;
            if !dry_run {
                if let (Some(b), Some(s), Some(h), Some(path)) =
                    (box_id, store_id, holder_key, pins_path())
                {
                    save_pins(
                        &path,
                        &FleetPins {
                            box_id: b.clone(),
                            store_id: s.clone(),
                            fleet_box: fleet_box.to_string(),
                            holder_public: h.clone(),
                            account_id: account,
                            person: person.clone(),
                            key_id: key.clone(),
                        },
                    )?;
                }
            }
            print(&v);
            Ok(())
        }
        C::Window {
            plan_id,
            plan_file,
            duration,
            profile,
            region,
            machine_type,
            out,
        } => {
            let pins = load_pins(
                &pins_path().ok_or_else(|| CliError::Msg(t("fleet.cli_not_enabled", &[])))?,
            )?;
            let window_secs = parse_duration(duration)
                .ok_or_else(|| CliError::Msg(t("fleet.cli_bad_duration", &[])))?;
            let keys = crate::approval_key_cli::keychain();
            let v = window(
                &WindowArgs {
                    plan_id: plan_id.clone(),
                    plan_file: plan_file.clone(),
                    window_secs,
                    profile: profile.clone(),
                    region: region.clone(),
                    machine_type: machine_type.clone(),
                    out: out.clone(),
                },
                &pins,
                &ozbox_core::SystemRunner,
                keys.as_ref(),
                &mut crate::init_cli::Terminal,
                &f,
                now_secs(),
                &mut std::io::stdout(),
            )?;
            print(&v);
            Ok(())
        }
        C::Approvers {
            command:
                A::Sign {
                    credentials,
                    version,
                    out,
                },
        } => {
            let pins = load_pins(
                &pins_path().ok_or_else(|| CliError::Msg(t("fleet.cli_not_enabled", &[])))?,
            )?;
            let keys = crate::approval_key_cli::keychain();
            let v = approvers_sign(
                &pins,
                keys.as_ref(),
                credentials,
                *version,
                out,
                now_secs() * 1000,
            )?;
            if json {
                print(&v);
            } else {
                println!(
                    "{}",
                    t(
                        "fleet.cli_approvers_signed",
                        &[("file", &out.display().to_string())]
                    )
                );
            }
            Ok(())
        }
        C::ApplyUnit => crate::fleet_serve::apply_unit_main().map_err(CliError::Msg),
        C::HolderServe {
            socket,
            dir,
            box_id,
            store_id,
            this_box,
            laptop_key,
            dashboard_uid,
            ingress_uid,
            role_arn,
            apply_uid,
        } => crate::fleet_serve::holder_main(&crate::fleet_serve::HolderArgs {
            socket: socket.clone(),
            dir: dir.clone(),
            box_id: box_id.clone(),
            store_id: store_id.clone(),
            this_box: this_box.clone(),
            laptop_key: laptop_key.clone(),
            dashboard_uid: *dashboard_uid,
            ingress_uid: *ingress_uid,
            role_arn: role_arn.clone(),
            apply_uid: apply_uid.clone(),
        })
        .map_err(CliError::Msg),
    }
}

#[cfg(test)]
mod tests;
