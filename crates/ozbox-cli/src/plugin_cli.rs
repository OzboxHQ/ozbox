//! `ozbox plugin list | add | approve | revoke | remove` (ADR 0031), and opening an approved provider plugin.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use ozbox_core::{Engine, Provider};
use ozbox_plugin::host::{Approvals, Plugin, PluginBackend};

use crate::cli::PluginCommand;
use crate::messages::t;
use crate::run::CliError;

fn msg(key: &str) -> CliError {
    CliError::Msg(t(key, &[]))
}

/// `~/.config/ozbox/plugins/`, beside the main configuration.
pub fn plugins_dir() -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("plugins"))
}

fn approvals_path() -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("plugins.toml"))
}

/// The provider plugin named in the configuration, as a provider the engine can drive. Refuses a plugin that is not
/// added, not a provider, or whose program is not the approved one.
pub fn open_provider(name: Option<&str>) -> Result<Box<dyn Provider>, CliError> {
    let name = name.ok_or_else(|| msg("plugin.config_needs_name"))?;
    let dir = plugins_dir()
        .ok_or_else(|| msg("init.cli_no_home"))?
        .join(name);
    let probe = ozbox_plugin::Manifest {
        name: name.to_string(),
        kind: ozbox_plugin::Kind::Provider,
        api_version: ozbox_plugin::API_VERSION,
        program: "x".into(),
        license: "Apache-2.0".into(),
        description: String::new(),
    };
    if probe.check().is_err() {
        return Err(msg("plugin.bad_name"));
    }
    let plugin = Plugin::load(&dir).map_err(|e| CliError::Msg(e.to_string()))?;
    let approvals = Approvals::load(&approvals_path().ok_or_else(|| msg("init.cli_no_home"))?);
    let backend =
        PluginBackend::open(plugin, approvals).map_err(|e| CliError::Msg(e.to_string()))?;
    Ok(Box::new(Engine::new(backend)))
}

pub struct Ctx<'a> {
    pub dir: PathBuf,
    pub approvals: PathBuf,
    pub yes: bool,
    pub dry_run: bool,
    pub interactive: bool,
    pub input: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
}

pub fn run(cmd: &PluginCommand, yes: bool, dry_run: bool, _json: bool) -> Result<(), CliError> {
    let dir = plugins_dir().ok_or_else(|| msg("init.cli_no_home"))?;
    let approvals = approvals_path().ok_or_else(|| msg("init.cli_no_home"))?;
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = std::io::stdout();
    let mut c = Ctx {
        dir,
        approvals,
        yes,
        dry_run,
        interactive: std::io::stdin().is_terminal(),
        input: &mut lock,
        out: &mut out,
    };
    run_with(cmd, &mut c)
}

fn confirm(c: &mut Ctx, lines: &[String]) -> Result<bool, CliError> {
    let _ = writeln!(c.out, "{}", t("mesh.plan_head", &[]));
    for l in lines {
        let _ = writeln!(c.out, "  - {l}");
    }
    if c.dry_run {
        let _ = writeln!(c.out, "{}", t("mesh.dry_run", &[]));
        return Ok(false);
    }
    if c.yes {
        return Ok(true);
    }
    if !c.interactive {
        return Err(msg("mesh.refuse_no_tty"));
    }
    let _ = write!(c.out, "{} [y/N] ", t("mesh.proceed", &[]));
    let _ = c.out.flush();
    let mut line = String::new();
    let _ = c.input.read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(true)
    } else {
        Err(msg("mesh.aborted"))
    }
}

fn copy_folder(from: &Path, to: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(to).map_err(|_| msg("plugin.copy_failed"))?;
    // only plain files at the top level: a plugin is a manifest and a program, not a tree
    for entry in std::fs::read_dir(from).map_err(|_| msg("plugin.copy_failed"))? {
        let entry = entry.map_err(|_| msg("plugin.copy_failed"))?;
        let ty = entry.file_type().map_err(|_| msg("plugin.copy_failed"))?;
        if ty.is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name()))
                .map_err(|_| msg("plugin.copy_failed"))?;
        }
    }
    Ok(())
}

pub fn run_with(cmd: &PluginCommand, c: &mut Ctx) -> Result<(), CliError> {
    let mut approvals = Approvals::load(&c.approvals);
    match cmd {
        PluginCommand::List => {
            let mut any = false;
            if let Ok(rd) = std::fs::read_dir(&c.dir) {
                let mut dirs: Vec<_> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect();
                dirs.sort();
                for d in dirs {
                    if let Ok(p) = Plugin::load(&d) {
                        any = true;
                        let state = match p.program_hash() {
                            Ok(h) if approvals.get(&p.manifest.name) == Some(h.as_str()) => {
                                "approved"
                            }
                            Ok(_) if approvals.get(&p.manifest.name).is_some() => {
                                "changed since approved"
                            }
                            _ => "not approved",
                        };
                        let kind = format!("{:?}", p.manifest.kind).to_lowercase();
                        let _ = writeln!(
                            c.out,
                            "{:<24} {:<9} {:<16} {state}",
                            p.manifest.name, kind, p.manifest.license
                        );
                    }
                }
            }
            if !any {
                let _ = writeln!(c.out, "{}", t("plugin.none", &[]));
            }
            Ok(())
        }
        PluginCommand::Add { path } => {
            let p = Plugin::load(path).map_err(|e| CliError::Msg(e.to_string()))?;
            let hash = p.program_hash().map_err(|e| CliError::Msg(e.to_string()))?;
            let to = c.dir.join(&p.manifest.name);
            let kind = format!("{:?}", p.manifest.kind).to_lowercase();
            let lines = vec![
                t(
                    "plugin.plan_add",
                    &[("name", &p.manifest.name), ("kind", &kind)],
                ),
                t("plugin.plan_license", &[("license", &p.manifest.license)]),
                t("plugin.plan_hash", &[("hash", &hash)]),
                t("plugin.plan_not_run", &[]),
            ];
            if !confirm(c, &lines)? {
                return Ok(());
            }
            copy_folder(path, &to)?;
            let _ = writeln!(
                c.out,
                "{}",
                t("plugin.added", &[("name", &p.manifest.name)])
            );
            Ok(())
        }
        PluginCommand::Approve { name } => {
            let p = Plugin::load(&c.dir.join(name)).map_err(|e| CliError::Msg(e.to_string()))?;
            let hash = p.program_hash().map_err(|e| CliError::Msg(e.to_string()))?;
            let lines = vec![
                t("plugin.plan_license", &[("license", &p.manifest.license)]),
                t("plugin.plan_approve", &[("name", name), ("hash", &hash)]),
            ];
            if !confirm(c, &lines)? {
                return Ok(());
            }
            approvals.approve(name, &hash);
            approvals.save(&c.approvals).map_err(CliError::Msg)?;
            let _ = writeln!(c.out, "{}", t("plugin.approved", &[("name", name)]));
            Ok(())
        }
        PluginCommand::Revoke { name } => {
            if !approvals.revoke(name) {
                return Err(msg("plugin.not_approved_yet"));
            }
            approvals.save(&c.approvals).map_err(CliError::Msg)?;
            let _ = writeln!(c.out, "{}", t("plugin.revoked", &[("name", name)]));
            Ok(())
        }
        PluginCommand::Remove { name } => {
            // a name is checked as a plain word before it becomes part of a path
            Plugin::load(&c.dir.join(name)).map_err(|e| CliError::Msg(e.to_string()))?;
            let lines = vec![t("plugin.plan_remove", &[("name", name)])];
            if !confirm(c, &lines)? {
                return Ok(());
            }
            let _ = std::fs::remove_dir_all(c.dir.join(name));
            approvals.revoke(name);
            approvals.save(&c.approvals).map_err(CliError::Msg)?;
            let _ = writeln!(c.out, "{}", t("plugin.removed", &[("name", name)]));
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make(dir: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("plugin.toml"),
            format!("name = \"{name}\"\nkind = \"tunnel\"\napi_version = 1\nlicense = \"Apache-2.0\"\nprogram = \"prog\"\n"),
        )
        .unwrap();
        std::fs::write(dir.join("prog"), body).unwrap();
    }

    fn go(root: &Path, cmd: &PluginCommand, yes: bool) -> (Result<(), CliError>, String) {
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(Vec::new());
        let mut c = Ctx {
            dir: root.join("plugins"),
            approvals: root.join("plugins.toml"),
            yes,
            dry_run: false,
            interactive: false,
            input: &mut input,
            out: &mut out,
        };
        let r = run_with(cmd, &mut c);
        (r, String::from_utf8(out).unwrap())
    }

    #[test]
    fn add_shows_the_hash_and_approving_is_a_separate_step() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        make(&src, "demo", "#!/bin/sh\n");
        let add = PluginCommand::Add { path: src.clone() };
        assert!(
            go(root.path(), &add, false).0.is_err(),
            "needs --yes without a terminal"
        );
        let (r, out) = go(root.path(), &add, true);
        r.unwrap();
        assert!(out.contains("SHA-256") || out.contains("sha256") || out.contains("hash"));
        let (_, listed) = go(root.path(), &PluginCommand::List, true);
        assert!(listed.contains("not approved"));
        go(
            root.path(),
            &PluginCommand::Approve {
                name: "demo".into(),
            },
            true,
        )
        .0
        .unwrap();
        assert!(go(root.path(), &PluginCommand::List, true)
            .1
            .contains("approved"));
        // the program changes: it is no longer the approved one
        std::fs::write(
            root.path().join("plugins/demo/prog"),
            "#!/bin/sh\necho changed\n",
        )
        .unwrap();
        assert!(go(root.path(), &PluginCommand::List, true)
            .1
            .contains("changed since approved"));
    }

    #[test]
    fn revoke_and_remove_and_odd_names() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("src");
        make(&src, "demo", "x");
        go(root.path(), &PluginCommand::Add { path: src }, true)
            .0
            .unwrap();
        go(
            root.path(),
            &PluginCommand::Approve {
                name: "demo".into(),
            },
            true,
        )
        .0
        .unwrap();
        go(
            root.path(),
            &PluginCommand::Revoke {
                name: "demo".into(),
            },
            true,
        )
        .0
        .unwrap();
        assert!(go(
            root.path(),
            &PluginCommand::Revoke {
                name: "demo".into()
            },
            true
        )
        .0
        .is_err());
        assert!(go(
            root.path(),
            &PluginCommand::Remove {
                name: "../x".into()
            },
            true
        )
        .0
        .is_err());
        go(
            root.path(),
            &PluginCommand::Remove {
                name: "demo".into(),
            },
            true,
        )
        .0
        .unwrap();
        assert!(!root.path().join("plugins/demo").exists());
    }
}
