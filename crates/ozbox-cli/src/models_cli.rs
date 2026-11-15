//! `ozbox models list|add|test|remove|default|usage`: the same settings and secret store as Settings -> Models.
//!
//! A key is read from standard input (`--key-stdin`), never from a command line, and is never printed. Every change
//! validates the whole settings file before saving; `--dry-run` stops before saving.

use std::io::{IsTerminal, Read};

use serde_json::json;

use crate::cli::{ModelsCommand, PriceCommand};
use crate::messages::t;
use crate::model_engines;
use crate::model_providers as mp;
use crate::model_usage;
use crate::models;
use crate::netguard::UreqClient;
use crate::run::CliError;
use crate::secrets::SecretStore;
use crate::settings::{EngineModel, ModelChoice, ModelProvider, Settings};

type Result<T> = std::result::Result<T, CliError>;

fn msg<T>(m: String) -> Result<T> {
    Err(CliError::Msg(m))
}

fn print_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    Ok(())
}

fn settings_path() -> Result<std::path::PathBuf> {
    Settings::path().ok_or_else(|| CliError::Msg(t("models.cli.no_settings", &[])))
}

fn save(settings: &Settings, dry_run: bool) -> Result<()> {
    settings.validate()?;
    if !dry_run {
        settings.save_to(&settings_path()?)?;
    }
    Ok(())
}

fn read_key() -> Result<String> {
    if std::io::stdin().is_terminal() {
        return msg(t("models.cli.key_tty", &[]));
    }
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|_| CliError::Msg(t("models.cli.key_read", &[])))?;
    Ok(s.trim().to_string())
}

fn parse_choice(s: &str) -> Result<ModelChoice> {
    match s.split_once(':') {
        Some((p, m)) if !p.is_empty() && !m.is_empty() => Ok(ModelChoice {
            provider_id: p.to_string(),
            model: m.to_string(),
        }),
        _ => msg(t("models.cli.bad_choice", &[("value", s)])),
    }
}

pub fn run(cmd: &ModelsCommand, yes: bool, dry_run: bool, json: bool) -> Result<()> {
    let path = settings_path()?;
    let mut settings = Settings::load_from(&path)?;
    let secrets = crate::secrets_file::select();
    match cmd {
        ModelsCommand::List => list(&settings, secrets.as_ref(), json),
        ModelsCommand::Add {
            id,
            kind,
            label,
            base_url,
            local,
            region,
            resource,
            hosted_on,
            cap,
            key_stdin,
        } => {
            let kind = mp::parse_kind(kind).ok_or_else(|| {
                CliError::Msg(t(
                    "models.cli.bad_kind",
                    &[("kinds", &mp::ALL.map(mp::kind_id).join(", "))],
                ))
            })?;
            if settings.models.providers.iter().any(|p| &p.id == id) {
                return msg(t("models.cli.exists", &[("id", id)]));
            }
            settings.models.providers.push(ModelProvider {
                id: id.clone(),
                kind,
                label: label.clone().unwrap_or_else(|| id.clone()),
                base_url: base_url.clone(),
                local_endpoint: *local,
                monthly_cap_usd: *cap,
                region: region.clone(),
                resource: resource.clone(),
                hosted_on: hosted_on.clone(),
            });
            save(&settings, dry_run)?;
            let key = if *key_stdin { Some(read_key()?) } else { None };
            if let (Some(k), false) = (&key, dry_run) {
                secrets
                    .set(&models::key_name(id), k)
                    .map_err(|e| CliError::Msg(e.to_string()))?;
            }
            if json {
                return print_json(
                    &json!({ "added": id, "key_saved": key.is_some() && !dry_run, "dry_run": dry_run }),
                );
            }
            println!(
                "{}",
                t(
                    if dry_run {
                        "models.cli.add_dry"
                    } else {
                        "models.cli.added"
                    },
                    &[("id", id)]
                )
            );
            Ok(())
        }
        ModelsCommand::Test { id, ping, model } => {
            let p = settings
                .models
                .providers
                .iter()
                .find(|p| &p.id == id)
                .ok_or_else(|| CliError::Msg(t("models.cli.unknown", &[("id", id)])))?;
            if p.hosted_on.is_some() {
                return msg(t(
                    "models.cli.hosted",
                    &[("box", p.hosted_on.as_deref().unwrap_or_default())],
                ));
            }
            if *ping {
                let m = model
                    .clone()
                    .or_else(|| models::default_model_for(&settings.models, id).map(str::to_string))
                    .ok_or_else(|| CliError::Msg(t("models.cli.need_model", &[])))?;
                if !yes {
                    return msg(t("models.cli.ping_needs_yes", &[]));
                }
                if dry_run {
                    return print_dry(json, id);
                }
                let r = models::test_connection(&UreqClient, secrets.as_ref(), p, &m)
                    .map_err(CliError::Msg)?;
                return finish(json, r.ok, &r.detail, json!({ "result": r }));
            }
            if dry_run {
                return print_dry(json, id);
            }
            let r = models::list_models(&UreqClient, secrets.as_ref(), p).map_err(CliError::Msg)?;
            if !json && r.ok {
                for m in &r.models {
                    println!("  {m}");
                }
            }
            finish(json, r.ok, &r.detail, json!({ "result": r }))
        }
        ModelsCommand::Remove { id } => {
            if !settings.models.providers.iter().any(|p| &p.id == id) {
                return msg(t("models.cli.unknown", &[("id", id)]));
            }
            let m = &mut settings.models;
            m.providers.retain(|p| &p.id != id);
            for slot in [
                &mut m.defaults.coding,
                &mut m.defaults.chat,
                &mut m.defaults.review,
            ] {
                if slot.as_ref().is_some_and(|c| &c.provider_id == id) {
                    *slot = None;
                }
            }
            let uses = |e: &EngineModel| {
                &e.provider_id == id || e.fallback.as_ref().is_some_and(|f| &f.provider_id == id)
            };
            m.engines.retain(|_, e| !uses(e));
            for per_box in m.box_overrides.values_mut() {
                per_box.retain(|_, e| !uses(e));
            }
            m.prices.retain(|k, _| !k.starts_with(&format!("{id}/")));
            save(&settings, dry_run)?;
            if !dry_run {
                let _ = secrets.delete(&models::key_name(id));
            }
            if json {
                return print_json(&json!({ "removed": id, "dry_run": dry_run }));
            }
            println!(
                "{}",
                t(
                    if dry_run {
                        "models.cli.remove_dry"
                    } else {
                        "models.cli.removed"
                    },
                    &[("id", id)]
                )
            );
            Ok(())
        }
        ModelsCommand::Price { command } => {
            let (provider, model, set) = match command {
                PriceCommand::Set {
                    provider_id: provider,
                    model,
                    input,
                    output,
                } => (provider, model, Some((*input, *output))),
                PriceCommand::Clear {
                    provider_id: provider,
                    model,
                } => (provider, model, None),
            };
            if !settings.models.providers.iter().any(|p| &p.id == provider) {
                return msg(t("models.cli.unknown", &[("id", provider)]));
            }
            let key = format!("{provider}/{model}");
            match set {
                Some((input_per_mtok_usd, output_per_mtok_usd)) => {
                    settings.models.prices.insert(
                        key.clone(),
                        crate::settings::ModelPriceOverride {
                            input_per_mtok_usd,
                            output_per_mtok_usd,
                        },
                    );
                }
                None => {
                    settings.models.prices.remove(&key);
                }
            }
            save(&settings, dry_run)?;
            if json {
                return print_json(
                    &json!({ "provider": provider, "model": model, "price_set": set.is_some(), "dry_run": dry_run }),
                );
            }
            println!(
                "{}",
                t(
                    match (set.is_some(), dry_run) {
                        (true, false) => "models.cli.price_set",
                        (true, true) => "models.cli.price_set_dry",
                        (false, false) => "models.cli.price_cleared",
                        (false, true) => "models.cli.price_cleared_dry",
                    },
                    &[("key", &key)]
                )
            );
            Ok(())
        }
        ModelsCommand::Default {
            target,
            provider,
            model,
            fallback,
            on_box,
            clear,
        } => {
            let engine = model_engines::known(target);
            if !engine && !["coding", "chat", "review"].contains(&target.as_str()) {
                return msg(t("models.cli.bad_target", &[("target", target)]));
            }
            if on_box.is_some() && !engine {
                return msg(t("models.cli.box_needs_engine", &[]));
            }
            let choice = if *clear {
                None
            } else {
                match (provider, model) {
                    (Some(p), Some(m)) => Some(ModelChoice {
                        provider_id: p.clone(),
                        model: m.clone(),
                    }),
                    _ => return msg(t("models.cli.need_provider_model", &[])),
                }
            };
            let m = &mut settings.models;
            if engine {
                let fb = fallback.as_deref().map(parse_choice).transpose()?;
                let entry = choice.map(|c| EngineModel {
                    provider_id: c.provider_id,
                    model: c.model,
                    fallback: fb,
                });
                let map = match on_box {
                    Some(b) => m.box_overrides.entry(b.clone()).or_default(),
                    None => &mut m.engines,
                };
                match entry {
                    Some(e) => {
                        map.insert(target.clone(), e);
                    }
                    None => {
                        map.remove(target);
                    }
                }
                m.box_overrides.retain(|_, v| !v.is_empty());
            } else {
                match target.as_str() {
                    "coding" => m.defaults.coding = choice,
                    "chat" => m.defaults.chat = choice,
                    _ => m.defaults.review = choice,
                }
            }
            save(&settings, dry_run)?;
            if json {
                return print_json(
                    &json!({ "target": target, "models": settings.models, "dry_run": dry_run }),
                );
            }
            println!(
                "{}",
                t(
                    if dry_run {
                        "models.cli.default_dry"
                    } else {
                        "models.cli.default_set"
                    },
                    &[("target", target)]
                )
            );
            Ok(())
        }
        ModelsCommand::Resolve { engine, on_box } => {
            let r = model_engines::resolve(
                &settings.models,
                secrets.as_ref(),
                on_box.as_deref(),
                engine,
            )
            .map_err(CliError::Msg)?;
            let names: Vec<String> = r.env_names().iter().map(|n| (*n).to_string()).collect();
            let fallback = r
                .fallback
                .as_ref()
                .map(|f| format!("{} / {}", f.provider_id, f.model));
            if json {
                return print_json(&json!({
                    "engine": r.engine, "provider_id": r.provider_id, "model": r.model,
                    "fallback": fallback, "env_names": names,
                }));
            }
            println!(
                "{}",
                t(
                    "models.cli.resolved",
                    &[
                        ("engine", &r.engine),
                        ("provider", &r.provider_id),
                        ("model", &r.model),
                        ("names", &names.join(", ")),
                    ]
                )
            );
            Ok(())
        }
        ModelsCommand::Record {
            provider,
            model,
            input_tokens,
            output_tokens,
            cached_input_tokens,
            on_box,
            engine,
        } => {
            if !settings.models.providers.iter().any(|p| &p.id == provider) {
                return msg(t("models.cli.unknown", &[("id", provider)]));
            }
            let u = ozbox_core::ModelUsage {
                ts_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                box_name: on_box.clone(),
                engine: engine.clone(),
                provider_id: provider.clone(),
                model: model.clone(),
                input_tokens: *input_tokens,
                output_tokens: *output_tokens,
                cached_input_tokens: *cached_input_tokens,
            };
            if !dry_run {
                model_usage::record(&model_usage::path_for(&path), &u).map_err(CliError::Msg)?;
            }
            if json {
                return print_json(&json!({ "recorded": !dry_run, "dry_run": dry_run }));
            }
            println!(
                "{}",
                t(
                    if dry_run {
                        "models.cli.record_dry"
                    } else {
                        "models.cli.recorded"
                    },
                    &[]
                )
            );
            Ok(())
        }
        ModelsCommand::Usage { days } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let s = model_usage::summary_for(&settings, Some(&path), now, *days);
            if json {
                return print_json(&json!({ "usage": s, "estimate": true }));
            }
            println!(
                "{}",
                t(
                    "models.cli.usage_total",
                    &[
                        ("days", &days.to_string()),
                        ("calls", &s.total.calls.to_string()),
                        ("input", &s.total.input_tokens.to_string()),
                        ("output", &s.total.output_tokens.to_string()),
                        ("cost", &format!("{:.2}", s.total.est_cost_usd)),
                    ]
                )
            );
            for r in &s.by_model {
                println!(
                    "{}",
                    t(
                        "models.cli.usage_row",
                        &[
                            ("key", &r.key),
                            ("calls", &r.totals.calls.to_string()),
                            ("cost", &format!("{:.2}", r.totals.est_cost_usd)),
                        ]
                    )
                );
            }
            Ok(())
        }
    }
}

fn print_dry(json: bool, id: &str) -> Result<()> {
    if json {
        return print_json(&json!({ "tested": id, "dry_run": true }));
    }
    println!("{}", t("models.cli.test_dry", &[("id", id)]));
    Ok(())
}

fn finish(json: bool, ok: bool, detail: &str, v: serde_json::Value) -> Result<()> {
    if json {
        print_json(&v)?;
    } else {
        println!("{detail}");
    }
    if ok {
        Ok(())
    } else {
        Err(CliError::Msg(t("models.cli.failed", &[])))
    }
}

fn list(settings: &Settings, secrets: &dyn SecretStore, json: bool) -> Result<()> {
    let m = &settings.models;
    let rows: Vec<serde_json::Value> = m
        .providers
        .iter()
        .map(|p| {
            json!({
                "id": p.id, "kind": mp::kind_id(p.kind), "label": p.label, "local_endpoint": p.local_endpoint,
                "hosted_on": p.hosted_on, "monthly_cap_usd": p.monthly_cap_usd,
                "key_saved": secrets.exists(&models::key_name(&p.id)).unwrap_or(false),
            })
        })
        .collect();
    if json {
        return print_json(&json!({
            "providers": rows, "defaults": m.defaults, "engines": m.engines, "box_overrides": m.box_overrides,
        }));
    }
    if rows.is_empty() {
        println!("{}", t("models.cli.none", &[]));
    }
    for r in &rows {
        println!(
            "{}",
            t(
                "models.cli.row",
                &[
                    ("id", r["id"].as_str().unwrap_or_default()),
                    ("kind", r["kind"].as_str().unwrap_or_default()),
                    (
                        "key",
                        if r["key_saved"] == true {
                            "key saved"
                        } else {
                            "no key"
                        }
                    ),
                ]
            )
        );
    }
    for (e, c) in &m.engines {
        println!(
            "{}",
            t(
                "models.cli.engine_row",
                &[
                    ("engine", e),
                    ("provider", &c.provider_id),
                    ("model", &c.model)
                ]
            )
        );
    }
    Ok(())
}
