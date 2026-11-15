//! `ozbox adopt <box>`: see `ozbox_provider_aws::adopt`. Plan, print, confirm, apply, like every change; the only thing it
//! writes is the box's OpenTofu state (backed up before and after), never a cloud resource.

use std::io::{BufRead, IsTerminal, Write};

use ozbox_core::adopt::{AdoptPlan, AdoptReport};
use ozbox_core::BoxName;
use ozbox_provider_aws::AwsBackend;
use ozbox_provider_hcloud::HcloudBackend;

use super::{CliError, Flags, Result};
use crate::cli::ProviderKind;
use crate::config::Config;
use crate::messages::t;

pub fn command(kind: ProviderKind, config: &Config, name: &BoxName, f: &Flags) -> Result<()> {
    // Each provider finds its own resources and corrects its own import artefacts; the rest is shared.
    type Apply = Box<dyn Fn(&AdoptPlan) -> ozbox_core::Result<AdoptReport>>;
    let (plan, apply): (AdoptPlan, Apply) = match kind {
        ProviderKind::Aws => {
            let backend = std::sync::Arc::new(AwsBackend::new(
                std::sync::Arc::new(ozbox_core::SystemRunner),
                super::aws_config(config, false)?,
            ));
            let plan = backend.adopt_plan(name)?;
            (plan, Box::new(move |p| backend.adopt_apply(p)))
        }
        ProviderKind::Hcloud => {
            let backend = std::sync::Arc::new(HcloudBackend::new(
                std::sync::Arc::new(ozbox_provider_hcloud::api::UreqApi::from_env()),
                std::sync::Arc::new(ozbox_core::SystemRunner),
                super::hcloud_config(config, false)?,
            ));
            let plan = backend.adopt_plan(name)?;
            (plan, Box::new(move |p| backend.adopt_apply(p)))
        }
        ProviderKind::Fake | ProviderKind::Plugin => {
            return Err(CliError::Msg(t("adopt.err_real_only", &[])))
        }
    };
    if f.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).unwrap_or_default()
        );
    } else {
        println!("{}", t("adopt.intro", &[("box", name.as_str())]));
        for i in &plan.items {
            println!("  {:<42} {}  ({})", i.address, i.id, i.what);
        }
        println!("{}", t("adopt.promise", &[]));
    }
    if f.dry_run {
        if !f.json {
            println!("{}", t("adopt.dry_run", &[]));
        }
        return Ok(());
    }
    if !f.yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Msg(t(
                "adopt.err_confirm",
                &[("box", name.as_str())],
            )));
        }
        let mut err = std::io::stderr();
        let _ = write!(err, "Adopt {name}? [y/N] ");
        let _ = err.flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::Core(e.into()))?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::Msg("aborted; nothing was changed".into()));
        }
    }
    let r = apply(&plan)?;
    if f.json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    } else {
        println!(
            "{}",
            t(
                "adopt.done",
                &[("box", name.as_str()), ("n", &r.imported.len().to_string())]
            )
        );
        for c in &r.corrected {
            println!("  corrected: {c}");
        }
        for c in &r.tag_only {
            println!("  next apply will change tags only: {c}");
        }
        if let Some(b) = &r.backup_before {
            println!("  state backed up before: {b}");
        }
        if let Some(b) = &r.backup_after {
            println!("  state backed up after: {b}");
        }
    }
    Ok(())
}
