//! `ozbox permissions ...` and `ozbox audit ...`: the command line for the permission engine and the audit chain. It reads
//! and changes the same task store the dashboard server uses (`ozbox_core::run`), so what one shows the other shows.
//!
//! A grant made here has no second factor to ask for (the sign-in layer belongs to the dashboard), so it needs the name of
//! what it covers typed back with `--confirm` and is recorded as a typed confirmation, never as a second factor.

use ozbox_core::permissions::{
    self, Action, ActorKind, Ctx, Environment, Mode, NewGrant, Scope, SecondFactor,
};
use ozbox_core::run::TaskStore;
use ozbox_core::{Error, Result};
use serde_json::{json, Value};

use crate::cli::{AuditCommand, PermissionsCommand};
use crate::messages::t;
use crate::runs_cli::{store_path, Flags};

fn store() -> Result<TaskStore> {
    store_path()
        .map(TaskStore::new)
        .ok_or_else(|| Error::Config(t("runs.no_store", &[])))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn who() -> String {
    "owner".to_string()
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, v: &str) -> Result<T> {
    serde_json::from_value(json!(v))
        .map_err(|_| Error::Config(t("perm.bad_value", &[("what", what), ("value", v)])))
}

pub fn permissions(cmd: &PermissionsCommand, f: &Flags) -> Result<()> {
    let store = store()?;
    let now = now_ms();
    match cmd {
        PermissionsCommand::Show => {
            let book = store.load()?;
            if f.json {
                let grants: Vec<Value> = book
                    .perms
                    .grants
                    .iter()
                    .map(|g| {
                        let mut v = serde_json::to_value(g).unwrap_or(Value::Null);
                        v["state"] = json!(g.state(now));
                        v
                    })
                    .collect();
                return print_json(&json!({ "settings": book.perms.settings(), "grants": grants }));
            }
            let p = &book.perms;
            println!(
                "{}",
                t("perm.mode", &[("mode", &format!("{:?}", p.default_mode))])
            );
            for r in &p.rules {
                println!(
                    "{}",
                    t(
                        "perm.rule",
                        &[
                            ("id", &r.id),
                            ("effect", &format!("{:?}", r.effect)),
                            ("action", &r.action),
                            (
                                "scope",
                                &format!("{:?}:{}", r.scope, r.scope_id.as_deref().unwrap_or("*"))
                            )
                        ]
                    )
                );
            }
            let active: Vec<_> = p.active_grants(now).collect();
            if active.is_empty() {
                println!("{}", t("perm.no_grants", &[]));
            }
            for g in active {
                println!(
                    "{}",
                    t(
                        "perm.grant",
                        &[
                            ("id", &g.id),
                            ("scope", &format!("{:?}:{}", g.scope, g.scope_id)),
                            ("minutes", &((g.expires_ms - now) / 60_000).to_string()),
                            ("by", &g.granted_by),
                            (
                                "factor",
                                if g.factor.is_real() {
                                    "second factor"
                                } else {
                                    "typed confirmation, not 2FA"
                                }
                            )
                        ]
                    )
                );
            }
            Ok(())
        }
        PermissionsCommand::Mode { mode } => {
            let mode: Mode = parse("mode", mode)?;
            if f.dry_run {
                println!("{}", t("perm.dry_run", &[("what", "set the default mode")]));
                return Ok(());
            }
            store.update(|b| {
                b.perms.default_mode = mode;
                b.record(
                    now,
                    &who(),
                    "permission.settings_changed",
                    None,
                    "default mode",
                );
            })?;
            println!("{}", t("perm.mode_set", &[("mode", &format!("{mode:?}"))]));
            Ok(())
        }
        PermissionsCommand::Grant {
            scope,
            id,
            reason,
            minutes,
            actions,
            confirm,
            unattended,
            uses,
        } => {
            let scope: Scope = parse("scope", scope)?;
            if confirm.as_deref() != Some(id.as_str()) {
                return Err(Error::Config(t("perm.confirm", &[("id", id)])));
            }
            if f.dry_run {
                println!("{}", t("perm.dry_run", &[("what", "make a grant")]));
                return Ok(());
            }
            let new = NewGrant {
                granted_by: who(),
                scope,
                scope_id: id.clone(),
                actions: if actions.is_empty() {
                    vec!["*".into()]
                } else {
                    actions.clone()
                },
                reason: reason.clone(),
                minutes: *minutes,
                factor: SecondFactor::TypedConfirmation,
                allow_unattended: *unattended,
                max_uses: *uses,
            };
            let g = store
                .update(|b| {
                    let r = b.perms.create_grant(new, now);
                    if let Ok(g) = &r {
                        b.record(
                            now,
                            &who(),
                            "grant.created",
                            None,
                            &format!(
                                "{} {:?}:{} {} min via typed_confirmation",
                                g.id, g.scope, g.scope_id, minutes
                            )
                            .to_lowercase(),
                        );
                    }
                    r
                })?
                .map_err(|e| Error::Config(e.to_string()))?;
            if f.json {
                return print_json(&serde_json::to_value(&g)?);
            }
            println!(
                "{}",
                t(
                    "perm.granted",
                    &[("id", &g.id), ("minutes", &minutes.to_string())]
                )
            );
            Ok(())
        }
        PermissionsCommand::Revoke { id } => {
            if f.dry_run {
                println!("{}", t("perm.dry_run", &[("what", "revoke a grant")]));
                return Ok(());
            }
            store
                .update(|b| {
                    let r = b.perms.revoke_grant(id, &who(), now);
                    if r.is_ok() {
                        b.record(now, &who(), "grant.revoked", None, id);
                    }
                    r
                })?
                .map_err(|e| Error::Config(e.to_string()))?;
            println!("{}", t("perm.revoked", &[("id", id)]));
            Ok(())
        }
        PermissionsCommand::Check {
            action,
            r#box,
            env,
            command,
            tool,
            writes,
        } => {
            let action: Action = parse("action", action)?;
            let env: Environment = match env {
                Some(e) => parse("env", e)?,
                None => Environment::Sandbox,
            };
            let book = store.load()?;
            let ctx = Ctx {
                person: who(),
                actor: ActorKind::Agent,
                box_name: r#box.clone(),
                env,
                command: command
                    .as_ref()
                    .map(|c| c.split_whitespace().map(str::to_string).collect()),
                tool: tool.clone(),
                writes: *writes,
                ..Ctx::default()
            };
            let d = permissions::decide(&book.perms, &ctx, action, now);
            if f.json {
                return print_json(
                    &json!({ "effect": d.effect, "reason": d.reason.code(), "rule": d.rule, "grant": d.grant }),
                );
            }
            println!(
                "{}",
                t(
                    "perm.decision",
                    &[
                        ("effect", &format!("{:?}", d.effect)),
                        ("why", d.reason.sentence())
                    ]
                )
            );
            Ok(())
        }
    }
}

pub fn audit(cmd: &AuditCommand, f: &Flags) -> Result<()> {
    let log = store()?.audit_log();
    match cmd {
        AuditCommand::List { limit, action } => {
            let mut v = log.entries()?;
            v.reverse();
            let rows: Vec<_> = v
                .into_iter()
                .filter(|e| action.as_deref().is_none_or(|p| e.action.starts_with(p)))
                .take(*limit)
                .collect();
            if f.json {
                return print_json(&serde_json::to_value(&rows)?);
            }
            if rows.is_empty() {
                println!("{}", t("audit.none", &[]));
            }
            for e in rows {
                println!(
                    "{}",
                    t(
                        "audit.row",
                        &[
                            ("seq", &e.seq.to_string()),
                            ("actor", &e.actor),
                            ("action", &e.action),
                            ("subject", e.subject.as_deref().unwrap_or("-")),
                            ("detail", &e.detail)
                        ]
                    )
                );
            }
            Ok(())
        }
        AuditCommand::Seal => {
            let c = log.seal_now(now_ms())?;
            println!(
                "{}",
                t(
                    if c.is_some() {
                        "audit.sealed"
                    } else {
                        "audit.nothing_to_seal"
                    },
                    &[]
                )
            );
            Ok(())
        }
        AuditCommand::Verify => {
            let r = log.verify()?;
            if f.json {
                print_json(&serde_json::to_value(&r)?)?;
            } else if r.ok {
                println!(
                    "{}",
                    t(
                        "audit.ok",
                        &[
                            ("entries", &r.entries.to_string()),
                            ("head", &r.head_hash.chars().take(12).collect::<String>()),
                            ("unsealed", &r.unsealed_tail.to_string())
                        ]
                    )
                );
            } else {
                println!("{}", t("audit.broken", &[]));
                if !r.altered.is_empty() {
                    println!(
                        "{}",
                        t("audit.altered", &[("seqs", &format!("{:?}", r.altered))])
                    );
                }
                for g in &r.deleted {
                    println!(
                        "{}",
                        t(
                            "audit.deleted",
                            &[
                                ("after", &g.after_seq.to_string()),
                                ("before", &g.before_seq.to_string())
                            ]
                        )
                    );
                }
                if !r.out_of_order.is_empty() {
                    println!(
                        "{}",
                        t("audit.order", &[("seqs", &format!("{:?}", r.out_of_order))])
                    );
                }
                if !r.bad_seals.is_empty() {
                    println!(
                        "{}",
                        t("audit.seals", &[("seqs", &format!("{:?}", r.bad_seals))])
                    );
                }
                if let Some(x) = r.truncated {
                    println!(
                        "{}",
                        t(
                            "audit.truncated",
                            &[
                                ("sealed", &x.sealed_seq.to_string()),
                                ("last", &x.last_seq.to_string())
                            ]
                        )
                    );
                }
                if !r.unreadable_lines.is_empty() {
                    println!(
                        "{}",
                        t(
                            "audit.unreadable",
                            &[("lines", &format!("{:?}", r.unreadable_lines))]
                        )
                    );
                }
            }
            if r.ok {
                Ok(())
            } else {
                Err(Error::Config(t("audit.failed", &[])))
            }
        }
    }
}
