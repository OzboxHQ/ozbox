//! `ozbox hub …`: the registrars that vouch for a worker's box identity (ADR 0042). Every change is shown first, then confirmed
//! (ADR 0002).
//!
//! * `ozbox hub repin`: on `main`, as root, pin or rotate the registrars the hub trusts.
//! * `ozbox hub registrar-key` and `ozbox hub attest`: on **your own computer**, the laptop registrar for Hetzner and for
//!   machines you own. Refused on a box.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use ozbox_hubd::enrol::Provider;
use ozbox_hubd::registrar::{self, laptop, pins, AttestSigner, SeedSigner};
use zeroize::Zeroizing;

use crate::cli::HubCommand;
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;

/// The laptop's registrar key, in its secret store. Never on a box.
pub const REGISTRAR_KEY: &str = "hub-registrar-key";
/// The prefix of a Hetzner worker's one-time creation secret, kept on the laptop beside the box's id.
pub const CREATION_PREFIX: &str = "hub-creation-";
/// The default registrars file on `main`.
pub const DEFAULT_REGISTRARS: &str = "/etc/ozbox/hub-registrars.json";

/// Names only a laptop holds: a box's secret socket refuses to write, list or read them.
pub fn is_laptop_only(name: &str) -> bool {
    name == REGISTRAR_KEY || name.starts_with(CREATION_PREFIX)
}

#[derive(Clone, Copy)]
pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

pub struct Deps<'a> {
    pub secrets: &'a dyn SecretStore,
    pub stdin: &'a mut dyn BufRead,
    pub interactive: bool,
    pub out: &'a mut dyn Write,
    pub as_root: bool,
    pub site: laptop::Site,
    pub now: u64,
}

fn msg(key: &str) -> CliError {
    CliError::Msg(t(key, &[]))
}

fn refused(e: &ozbox_hubd::enrol::Refusal) -> CliError {
    CliError::Msg(t(
        "hubreg.refused",
        &[("code", e.code), ("why", &e.message)],
    ))
}

fn say(d: &mut Deps, line: &str) {
    let _ = writeln!(d.out, "{line}");
}

/// Show the plan; stop on `--dry-run`; otherwise confirm. `Ok(false)` means nothing is to be done.
fn plan_then_confirm(d: &mut Deps, f: Flags, lines: &[String]) -> Result<bool, CliError> {
    if !f.json {
        say(d, &t("hubreg.plan_head", &[]));
        for l in lines {
            say(d, &format!("  - {l}"));
        }
    }
    if f.dry_run {
        if !f.json {
            say(d, &t("hubreg.dry_run", &[]));
        }
        return Ok(false);
    }
    if f.yes {
        return Ok(true);
    }
    if !d.interactive {
        return Err(msg("hubreg.refuse_no_tty"));
    }
    let _ = write!(d.out, "{} [y/N] ", t("hubreg.proceed", &[]));
    let _ = d.out.flush();
    let mut line = String::new();
    let _ = d.stdin.read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(true)
    } else {
        Err(msg("hubreg.aborted"))
    }
}

fn provider(word: &str) -> Result<Provider, CliError> {
    match word {
        "aws" => Ok(Provider::Aws),
        "hetzner" => Ok(Provider::Hetzner),
        "own" => Ok(Provider::Own),
        _ => Err(msg("hubreg.bad_provider")),
    }
}

fn signer(d: &Deps) -> Result<SeedSigner, CliError> {
    let seed = d
        .secrets
        .get(REGISTRAR_KEY)
        .map_err(|_| msg("hubreg.store_failed"))?
        .ok_or_else(|| msg("hubreg.no_key"))?;
    SeedSigner::from_seed_hex(&Zeroizing::new(seed)).map_err(|_| msg("hubreg.store_failed"))
}

pub fn run_with(
    cmd: &HubCommand,
    registrars: &Path,
    d: &mut Deps,
    f: Flags,
) -> Result<(), CliError> {
    match cmd {
        HubCommand::Repin {
            add,
            provider: prov,
            remove,
            ..
        } => {
            let change = match (add, remove) {
                (None, None) => {
                    let regs =
                        ozbox_hubd::daemon::read_registrars(registrars).map_err(CliError::Msg)?;
                    if f.json {
                        let rows: Vec<_> = regs
                            .registrars
                            .iter()
                            .map(|r| serde_json::json!({"provider": r.provider.word(), "fingerprint": r.fingerprint()}))
                            .collect();
                        say(d, &serde_json::json!({"registrars": rows}).to_string());
                    } else if regs.registrars.is_empty() {
                        say(d, &t("hubreg.pins_none", &[]));
                    } else {
                        say(
                            d,
                            &t(
                                "hubreg.pins_head",
                                &[("count", &regs.registrars.len().to_string())],
                            ),
                        );
                        for r in &regs.registrars {
                            say(
                                d,
                                &t(
                                    "hubreg.pin_row",
                                    &[
                                        ("provider", r.provider.word()),
                                        ("fingerprint", &r.fingerprint()),
                                    ],
                                ),
                            );
                        }
                    }
                    return Ok(());
                }
                (Some(public), None) => pins::Change::Add {
                    provider: provider(
                        prov.as_deref().ok_or_else(|| msg("hubreg.need_provider"))?,
                    )?,
                    public: public.clone(),
                },
                (None, Some(fp)) => pins::Change::Remove {
                    fingerprint: fp.clone(),
                },
                (Some(public), Some(fp)) => pins::Change::Replace {
                    fingerprint: fp.clone(),
                    provider: provider(
                        prov.as_deref().ok_or_else(|| msg("hubreg.need_provider"))?,
                    )?,
                    public: public.clone(),
                },
            };
            let plan = pins::plan(registrars, &change).map_err(|e| refused(&e))?;
            if f.json {
                say(d, &serde_json::json!({"plan": plan}).to_string());
            }
            if !plan_then_confirm(d, f, &plan.steps)? {
                return Ok(());
            }
            pins::apply(registrars, &plan, d.as_root).map_err(|e| refused(&e))?;
            say(
                d,
                &t(
                    "hubreg.repinned",
                    &[("count", &plan.after.len().to_string())],
                ),
            );
            Ok(())
        }
        HubCommand::RegistrarKey => {
            if d.site.box_markers.iter().any(|p| p.exists()) {
                return Err(msg("hubreg.on_a_box"));
            }
            let exists = d
                .secrets
                .exists(REGISTRAR_KEY)
                .map_err(|_| msg("hubreg.store_failed"))?;
            if !exists {
                if !plan_then_confirm(d, f, &[t("hubreg.key_plan", &[])])? {
                    return Ok(());
                }
                let (seed, _) = SeedSigner::generate().map_err(|_| msg("hubreg.store_failed"))?;
                d.secrets
                    .set(REGISTRAR_KEY, &seed)
                    .map_err(|_| msg("hubreg.store_failed"))?;
                say(d, &t("hubreg.key_made", &[]));
            } else {
                say(d, &t("hubreg.key_exists", &[]));
            }
            let s = signer(d)?;
            let public = s.public_hex();
            let fp = registrar::registrar_fingerprint(&s);
            if f.json {
                say(
                    d,
                    &serde_json::json!({"public": public, "fingerprint": fp}).to_string(),
                );
            } else {
                say(
                    d,
                    &t(
                        "hubreg.key_public",
                        &[("public", &public), ("fingerprint", &fp)],
                    ),
                );
            }
            Ok(())
        }
        HubCommand::Attest { request, out } => {
            if d.site.box_markers.iter().any(|p| p.exists()) {
                return Err(msg("hubreg.on_a_box"));
            }
            let text = std::fs::read(request)
                .ok()
                .filter(|b| b.len() <= 64 * 1024)
                .ok_or_else(|| msg("hubreg.request_unreadable"))?;
            let req: laptop::LaptopRequest =
                serde_json::from_slice(&text).map_err(|_| msg("hubreg.request_bad"))?;
            let plan = laptop::plan(&req).map_err(|e| refused(&e))?;
            if f.json {
                say(d, &serde_json::json!({"plan": plan}).to_string());
            }
            if !plan_then_confirm(d, f, &plan.steps)? {
                return Ok(());
            }
            let s = signer(d)?;
            let secret: Option<Zeroizing<String>> = if req.provider == Provider::Hetzner {
                d.secrets
                    .get(&format!("{CREATION_PREFIX}{}", req.box_id))
                    .map_err(|_| msg("hubreg.store_failed"))?
                    .map(Zeroizing::new)
            } else {
                None
            };
            let a = laptop::apply(
                &plan,
                &req,
                &s,
                secret.as_ref().map(|z| z.as_bytes()),
                &d.site,
                d.now,
            )
            .map_err(|e| refused(&e))?;
            let body = serde_json::to_string_pretty(&a).map_err(|_| msg("hubreg.out_failed"))?;
            match out {
                Some(p) => {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(p)
                        .map_err(|_| {
                            CliError::Msg(t(
                                "hubreg.out_exists",
                                &[("path", &p.display().to_string())],
                            ))
                        })?;
                    file.write_all(body.as_bytes())
                        .map_err(|_| msg("hubreg.out_failed"))?;
                    say(d, &t("hubreg.attested", &[]));
                }
                None => say(d, &body),
            }
            Ok(())
        }
    }
}

pub fn run(cmd: &HubCommand, f: Flags) -> Result<(), CliError> {
    use std::io::IsTerminal;
    let registrars: PathBuf = match cmd {
        HubCommand::Repin { registrars, .. } => registrars
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_REGISTRARS)),
        _ => PathBuf::from(DEFAULT_REGISTRARS),
    };
    let secrets = crate::secrets_file::select();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = std::io::stdout();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0);
    let mut d = Deps {
        secrets: secrets.as_ref(),
        stdin: &mut lock,
        interactive: std::io::stdin().is_terminal(),
        out: &mut out,
        as_root: pins::running_as_root(),
        site: laptop::Site::default(),
        now,
    };
    run_with(cmd, &registrars, &mut d, f)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    const FLAGS: Flags = Flags {
        yes: true,
        dry_run: false,
        json: false,
    };

    fn go(
        cmd: &HubCommand,
        path: &Path,
        secrets: &MemorySecrets,
        f: Flags,
        as_root: bool,
        site: laptop::Site,
        input: &str,
    ) -> (Result<(), CliError>, String) {
        let mut stdin = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        let r = {
            let mut d = Deps {
                secrets,
                stdin: &mut stdin,
                interactive: !input.is_empty(),
                out: &mut out,
                as_root,
                site,
                now: 1_800_000_000_000,
            };
            run_with(cmd, path, &mut d, f)
        };
        (r, String::from_utf8(out).unwrap())
    }

    fn no_box() -> laptop::Site {
        laptop::Site {
            box_markers: vec![],
        }
    }

    fn repin(add: Option<&str>, remove: Option<&str>) -> HubCommand {
        HubCommand::Repin {
            add: add.map(str::to_string),
            provider: Some("aws".into()),
            remove: remove.map(str::to_string),
            registrars: None,
        }
    }

    fn key() -> String {
        SeedSigner::generate().unwrap().1.public_hex()
    }

    #[test]
    fn repin_is_planned_confirmed_root_only_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.json");
        std::fs::write(&path, br#"{"registrars":[]}"#).unwrap();
        let s = MemorySecrets::default();
        let k = key();
        let add = repin(Some(&k), None);
        // a dry run shows the plan and writes nothing
        let (r, out) = go(
            &add,
            &path,
            &s,
            Flags {
                dry_run: true,
                ..FLAGS
            },
            true,
            no_box(),
            "",
        );
        r.unwrap();
        assert!(out.contains("pin aws registrar") && out.contains("Dry run"));
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"registrars":[]}"#);
        // not root: refused, nothing written
        let (r, _) = go(&add, &path, &s, FLAGS, false, no_box(), "");
        assert!(r.unwrap_err().to_string().contains("not-root"));
        // no terminal and no --yes: refused
        let (r, _) = go(
            &add,
            &path,
            &s,
            Flags {
                yes: false,
                ..FLAGS
            },
            true,
            no_box(),
            "",
        );
        assert!(r.is_err());
        // declined at the prompt
        let (r, _) = go(
            &add,
            &path,
            &s,
            Flags {
                yes: false,
                ..FLAGS
            },
            true,
            no_box(),
            "n\n",
        );
        assert!(r.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"registrars":[]}"#);
        // confirmed
        let (r, out) = go(
            &add,
            &path,
            &s,
            Flags {
                yes: false,
                ..FLAGS
            },
            true,
            no_box(),
            "y\n",
        );
        r.unwrap();
        assert!(out.contains("1 registrar(s)"));
        let (_, listed) = go(&repin(None, None), &path, &s, FLAGS, false, no_box(), "");
        assert!(listed.contains("aws"));
        // a bad key and a missing provider are refused with a reason
        let (r, _) = go(
            &repin(Some("zz"), None),
            &path,
            &s,
            FLAGS,
            true,
            no_box(),
            "",
        );
        assert!(r.unwrap_err().to_string().contains("bad-pin"));
        let no_provider = HubCommand::Repin {
            add: Some(key()),
            provider: None,
            remove: None,
            registrars: None,
        };
        assert!(go(&no_provider, &path, &s, FLAGS, true, no_box(), "")
            .0
            .is_err());
    }

    #[test]
    fn the_laptop_key_is_made_once_attests_after_a_confirmed_plan_and_never_on_a_box() {
        use ozbox_hubd::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let s = MemorySecrets::default();
        let nothing = dir.path().join("none.json");
        // no key yet: attesting says so
        let id: Identity = {
            let x = |_: u8| {
                ozbox_seal::public_to_hex(&ozbox_seal::ServiceKey::generate().unwrap().public())
            };
            let (_, a) = SeedSigner::generate().unwrap();
            let (_, b) = SeedSigner::generate().unwrap();
            Identity {
                sign_public: a.public_hex(),
                seal_public: x(0),
                delivery_public: x(1),
                handshake_public: b.public_hex(),
            }
        };
        let req = laptop::LaptopRequest {
            provider: Provider::Own,
            machine: "machine-7".into(),
            box_id: "box-w1".into(),
            orchestration: "orch-1".into(),
            hub_identity_fp: "ab".repeat(16),
            private_address: String::new(),
            class: "worker".into(),
            environment: "staging".into(),
            identity: id,
            creation_proof: String::new(),
        };
        let rf = dir.path().join("req.json");
        std::fs::write(&rf, serde_json::to_vec(&req).unwrap()).unwrap();
        let out_file = dir.path().join("att.json");
        let attest = HubCommand::Attest {
            request: rf.clone(),
            out: Some(out_file.clone()),
        };
        let (r, _) = go(&attest, &nothing, &s, FLAGS, false, no_box(), "");
        assert!(r.unwrap_err().to_string().contains("no registrar key"));
        // make the key (once)
        let (r, out) = go(
            &HubCommand::RegistrarKey,
            &nothing,
            &s,
            FLAGS,
            false,
            no_box(),
            "",
        );
        r.unwrap();
        assert!(out.contains("Public key:"));
        let seed = s.get(REGISTRAR_KEY).unwrap().unwrap();
        let (_, again) = go(
            &HubCommand::RegistrarKey,
            &nothing,
            &s,
            FLAGS,
            false,
            no_box(),
            "",
        );
        assert!(again.contains("already have") && !again.contains(&seed));
        assert!(!out.contains(&seed));
        // on a box: refused, with the key or without
        let marker = dir.path().join("etc-ozbox");
        std::fs::create_dir(&marker).unwrap();
        let on_box = laptop::Site {
            box_markers: vec![marker],
        };
        let (r, _) = go(&attest, &nothing, &s, FLAGS, false, on_box, "");
        assert!(r.unwrap_err().to_string().contains("never on a box"));
        assert!(!out_file.exists());
        // a dry run signs nothing
        let (r, _) = go(
            &attest,
            &nothing,
            &s,
            Flags {
                dry_run: true,
                ..FLAGS
            },
            false,
            no_box(),
            "",
        );
        r.unwrap();
        assert!(!out_file.exists());
        // confirmed: signed, and the file holds the public attestation only
        let (r, out) = go(&attest, &nothing, &s, FLAGS, false, no_box(), "");
        r.unwrap();
        assert!(out_file.exists() && out.contains("Signed"));
        let body = std::fs::read_to_string(&out_file).unwrap();
        assert!(body.contains("\"signature\"") && !body.contains(&seed));
        // never overwrites
        assert!(go(&attest, &nothing, &s, FLAGS, false, no_box(), "")
            .0
            .is_err());
    }

    #[test]
    fn the_laptops_key_names_are_not_a_boxs_to_write_list_or_read() {
        assert!(is_laptop_only(REGISTRAR_KEY) && is_laptop_only("hub-creation-box-w1"));
        assert!(!is_laptop_only("approval-key-laptop"));
        assert!(
            crate::secrets::valid_name(REGISTRAR_KEY)
                && crate::secrets::valid_name("hub-creation-box-w1")
        );
        assert!(!crate::secrets_service::box_may_write(REGISTRAR_KEY));
        assert!(!crate::secrets_service::box_may_write(
            "hub-creation-box-w1"
        ));
        assert!(crate::secrets_service::is_system_name(REGISTRAR_KEY));
    }
}
