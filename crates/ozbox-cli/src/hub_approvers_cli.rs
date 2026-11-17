//! `ozbox hub approvers …`: who may approve on a worker, carried from your own computer to each worker by way of `main` (ADR 0042).
//!
//! * `targets` (on `main`): the workers an approver list can be made for, with the ids their approval services pinned.
//! * `sign` (on **your own computer**, never a box): the passkeys your dashboard lists, signed with your computer's approval key as a
//!   set for each worker. The private half never leaves the keychain.
//! * `sync` (on `main`): shows the plan, then hands the signed bundle to the hub. **`main` signs nothing and decides nothing:** each
//!   worker's own approval service checks your signature against a key the box already trusts, and refuses an unsigned, forged,
//!   older, expired or other-box list. A bundle `main` made up changes nobody's approvals.
//! * `status` (on `main`): the version each worker was sent and says it holds, and any refusal it gave.
//!
//! The bundle is handed to the server through a file in the hub's state directory (the way the task store is shared): the server
//! sends it on its next round. Nothing in that file is a secret (public keys, names and a signature).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use ozbox_core::approval_subject::Ids;
use ozbox_core::hub::approver_sync::{
    build_set, precheck, signed_bytes, Bundle, BundleEntry, CredentialRecord, SignedApprovers,
    MAX_VALID_MS,
};
use ozbox_core::hub::engine::HubState;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli::HubApproversCommand;
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;

/// The file the server watches for a bundle to send.
pub const OUTBOX_FILE: &str = "approvers-outbox.json";
const MAX_FILE: u64 = 256 * 1024;
const DAY_MS: u64 = 86_400_000;

#[derive(Clone, Copy)]
pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

pub struct Ctx<'a> {
    /// The computer's approval keychain (`approval-key-<id>` holds a seed). Used by `sign` only.
    pub keys: &'a dyn SecretStore,
    pub state_dir: Option<PathBuf>,
    pub box_markers: Vec<PathBuf>,
    pub stdin: &'a mut dyn BufRead,
    pub interactive: bool,
    pub out: &'a mut dyn Write,
    pub now: u64,
}

/// What `targets` writes and `sign` reads.
#[derive(Debug, Serialize, Deserialize)]
pub struct Targets {
    pub workers: Vec<Target>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Target {
    pub worker: String,
    pub box_id: String,
    pub store_id: String,
    #[serde(default)]
    pub held: u64,
    #[serde(default)]
    pub sent: u64,
}

/// The credentials file: the same record `ozbox fleet approvers sign` reads.
#[derive(Debug, Deserialize)]
struct CredentialsFile {
    approvers: Vec<CredentialRecord>,
}

fn msg(key: &str) -> CliError {
    CliError::Msg(t(key, &[]))
}

fn say(c: &mut Ctx, line: &str) {
    let _ = writeln!(c.out, "{line}");
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what_key: &str) -> Result<T, CliError> {
    let what = t(what_key, &[]);
    let f = std::fs::File::open(path)
        .map_err(|_| CliError::Msg(t("hubappr.file_unreadable", &[("what", &what)])))?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(f, MAX_FILE + 1), &mut buf)
        .map_err(|_| CliError::Msg(t("hubappr.file_unreadable", &[("what", &what)])))?;
    if buf.len() as u64 > MAX_FILE {
        return Err(CliError::Msg(t("hubappr.file_bad", &[("what", &what)])));
    }
    serde_json::from_slice(&buf)
        .map_err(|_| CliError::Msg(t("hubappr.file_bad", &[("what", &what)])))
}

fn hub_state(c: &Ctx) -> Result<HubState, CliError> {
    let dir = c
        .state_dir
        .as_ref()
        .ok_or_else(|| msg("hubappr.no_state"))?;
    let store = ozbox_core::channel::store::Store::<HubState>::new(dir.join("hub"));
    if !store.exists() {
        return Err(msg("hubappr.no_state"));
    }
    store.read().map_err(|_| msg("hubappr.no_state"))
}

/// Show the plan; stop on `--dry-run`; otherwise confirm. `Ok(false)` means nothing is to be done.
fn plan_then_confirm(c: &mut Ctx, f: Flags, lines: &[String]) -> Result<bool, CliError> {
    if !f.json {
        say(c, &t("hubreg.plan_head", &[]));
        for l in lines {
            say(c, &format!("  - {l}"));
        }
    }
    if f.dry_run {
        if !f.json {
            say(c, &t("hubreg.dry_run", &[]));
        }
        return Ok(false);
    }
    if f.yes {
        return Ok(true);
    }
    if !c.interactive {
        return Err(msg("hubreg.refuse_no_tty"));
    }
    let _ = write!(c.out, "{} [y/N] ", t("hubreg.proceed", &[]));
    let _ = c.out.flush();
    let mut line = String::new();
    let _ = c.stdin.read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(true)
    } else {
        Err(msg("hubreg.aborted"))
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            CliError::Msg(t(
                "hubappr.out_exists",
                &[("path", &path.display().to_string())],
            ))
        })?;
    file.write_all(bytes).map_err(|_| msg("hubappr.out_failed"))
}

fn until(ms: u64) -> String {
    // whole days from the epoch's start are enough for a plan line; the exact instant is in the signed body
    let days = ms / DAY_MS;
    let (y, m, d) = civil(days as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 as a calendar date (Howard Hinnant's algorithm).
fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn run_with(cmd: &HubApproversCommand, c: &mut Ctx, f: Flags) -> Result<(), CliError> {
    match cmd {
        HubApproversCommand::Targets { out } => {
            let st = hub_state(c)?;
            let workers: Vec<Target> = st
                .service_pins
                .iter()
                .map(|(w, p)| {
                    let t = st
                        .peers
                        .get(w)
                        .map(|p| p.approvers.clone())
                        .unwrap_or_default();
                    Target {
                        worker: w.clone(),
                        box_id: p.ids.box_id.clone(),
                        store_id: p.ids.store_id.clone(),
                        held: t.held_seq,
                        sent: t.sent_seq,
                    }
                })
                .collect();
            if workers.is_empty() {
                return Err(msg("hubappr.no_workers"));
            }
            let json = serde_json::to_string_pretty(&Targets { workers })
                .map_err(|_| msg("hubappr.out_failed"))?;
            let list: Targets =
                serde_json::from_str(&json).map_err(|_| msg("hubappr.out_failed"))?;
            match out {
                Some(p) => {
                    write_new(p, json.as_bytes())?;
                    say(
                        c,
                        &t(
                            "hubappr.targets_written",
                            &[
                                ("count", &list.workers.len().to_string()),
                                ("path", &p.display().to_string()),
                            ],
                        ),
                    );
                }
                None if f.json => say(c, &json),
                None => {
                    say(
                        c,
                        &t(
                            "hubappr.targets_head",
                            &[("count", &list.workers.len().to_string())],
                        ),
                    );
                    for w in &list.workers {
                        say(
                            c,
                            &t(
                                "hubappr.target_row",
                                &[
                                    ("worker", &w.worker),
                                    ("held", &w.held.to_string()),
                                    ("sent", &w.sent.to_string()),
                                ],
                            ),
                        );
                    }
                }
            }
            Ok(())
        }
        HubApproversCommand::Sign {
            targets,
            credentials,
            version,
            valid_days,
            key_id,
            out,
        } => {
            if c.box_markers.iter().any(|p| p.exists()) {
                return Err(msg("hubappr.on_a_box"));
            }
            let targets: Targets = read_json(targets, "hubappr.what_targets")?;
            let creds: CredentialsFile = read_json(credentials, "hubappr.what_credentials")?;
            if !crate::approval_key::id_ok(key_id) {
                return Err(CliError::Msg(t("hubappr.no_key", &[("key_id", key_id)])));
            }
            let valid_ms = valid_days.saturating_mul(DAY_MS);
            if valid_ms == 0 || valid_ms > MAX_VALID_MS {
                return Err(msg("hubappr.bad_days"));
            }
            let mut bodies = Vec::new();
            for tg in &targets.workers {
                let ids = Ids {
                    box_id: tg.box_id.clone(),
                    store_id: tg.store_id.clone(),
                };
                if tg.held >= *version {
                    return Err(CliError::Msg(format!(
                        "{}: version {} is not higher than the one it holds ({})",
                        tg.worker, version, tg.held
                    )));
                }
                let b = build_set(&ids, &creds.approvers, *version, valid_ms, c.now)
                    .map_err(CliError::Msg)?;
                bodies.push((tg.worker.clone(), b));
            }
            if bodies.is_empty() {
                return Err(msg("hubappr.sync_nothing"));
            }
            let people: Vec<String> = creds
                .approvers
                .iter()
                .map(|a| {
                    format!(
                        "{} ({})",
                        a.person,
                        a.credential_id.chars().take(8).collect::<String>()
                    )
                })
                .collect();
            let mut lines = Vec::new();
            for (w, b) in &bodies {
                lines.push(t(
                    "hubappr.sign_plan",
                    &[
                        ("version", &version.to_string()),
                        ("worker", w),
                        ("count", &b.set.approvers.len().to_string()),
                        ("until", &until(b.set.expires_ms)),
                    ],
                ));
            }
            lines.push(t("hubappr.sign_people", &[("people", &people.join(", "))]));
            lines.push(t("hubappr.sign_key", &[("key_id", key_id)]));
            if !plan_then_confirm(c, f, &lines)? {
                return Ok(());
            }
            let seed = c
                .keys
                .get(&format!("{}{key_id}", crate::approval_key::KEYCHAIN_PREFIX))
                .map_err(|_| msg("hubappr.out_failed"))?
                .map(Zeroizing::new)
                .ok_or_else(|| CliError::Msg(t("hubappr.no_key", &[("key_id", key_id)])))?;
            let mut sets = Vec::new();
            for (worker, b) in &bodies {
                let text = b.to_text().map_err(CliError::Msg)?;
                let signature = crate::approval_key::sign(
                    &seed,
                    &String::from_utf8_lossy(&signed_bytes(&text)),
                )
                .map_err(CliError::Msg)?;
                sets.push(BundleEntry {
                    worker: worker.clone(),
                    signed: SignedApprovers {
                        body: text,
                        signature,
                    },
                });
            }
            let n = sets.len();
            let json = serde_json::to_vec_pretty(&Bundle { sets })
                .map_err(|_| msg("hubappr.out_failed"))?;
            write_new(out, &json)?;
            say(
                c,
                &t(
                    "hubappr.signed",
                    &[
                        ("count", &n.to_string()),
                        ("path", &out.display().to_string()),
                    ],
                ),
            );
            Ok(())
        }
        HubApproversCommand::Sync { bundle } => {
            let b: Bundle = read_json(bundle, "hubappr.what_bundle")?;
            if b.sets.is_empty() {
                return Err(msg("hubappr.sync_nothing"));
            }
            let st = hub_state(c)?;
            let dir = c.state_dir.clone().ok_or_else(|| msg("hubappr.no_state"))?;
            let outbox = dir.join(OUTBOX_FILE);
            if outbox.exists() {
                return Err(msg("hubappr.sync_waiting"));
            }
            let mut lines = Vec::new();
            for e in &b.sets {
                let seq = precheck(&st, &e.worker, &e.signed).map_err(|why| {
                    CliError::Msg(t(
                        "hubappr.sync_refused",
                        &[("worker", &e.worker), ("why", &why)],
                    ))
                })?;
                let count =
                    serde_json::from_str::<ozbox_core::hub::approver_sync::SetBody>(&e.signed.body)
                        .map(|s| s.set.approvers.len())
                        .unwrap_or(0);
                lines.push(t(
                    "hubappr.sync_plan",
                    &[
                        ("version", &seq.to_string()),
                        ("worker", &e.worker),
                        ("count", &count.to_string()),
                    ],
                ));
            }
            if !plan_then_confirm(c, f, &lines)? {
                return Ok(());
            }
            let json = serde_json::to_vec(&b).map_err(|_| msg("hubappr.out_failed"))?;
            let tmp = dir.join(format!("{OUTBOX_FILE}.tmp"));
            std::fs::write(&tmp, &json).map_err(|_| msg("hubappr.out_failed"))?;
            std::fs::rename(&tmp, &outbox).map_err(|_| msg("hubappr.out_failed"))?;
            say(
                c,
                &t(
                    "hubappr.sync_queued",
                    &[("count", &b.sets.len().to_string())],
                ),
            );
            Ok(())
        }
        HubApproversCommand::Status => {
            let st = hub_state(c)?;
            let waiting = c
                .state_dir
                .as_ref()
                .is_some_and(|d| d.join(OUTBOX_FILE).exists());
            if f.json {
                let rows: Vec<_> = st
                    .service_pins
                    .keys()
                    .map(|w| {
                        let t = st
                            .peers
                            .get(w)
                            .map(|p| p.approvers.clone())
                            .unwrap_or_default();
                        serde_json::json!({
                            "worker": w, "sent": t.sent_seq, "held": t.held_seq,
                            "refused": t.refused, "waiting": waiting,
                        })
                    })
                    .collect();
                say(
                    c,
                    &serde_json::json!({"workers": rows, "waiting": waiting}).to_string(),
                );
                return Ok(());
            }
            say(
                c,
                &t(
                    "hubappr.status_head",
                    &[("count", &st.service_pins.len().to_string())],
                ),
            );
            for w in st.service_pins.keys() {
                let tr = st
                    .peers
                    .get(w)
                    .map(|p| p.approvers.clone())
                    .unwrap_or_default();
                say(
                    c,
                    &t(
                        "hubappr.status_row",
                        &[
                            ("worker", w),
                            ("sent", &tr.sent_seq.to_string()),
                            ("held", &tr.held_seq.to_string()),
                        ],
                    ),
                );
                if let Some(why) = &tr.refused {
                    say(c, &t("hubappr.status_refused", &[("why", why)]));
                }
            }
            if waiting {
                say(c, &t("hubappr.status_waiting", &[]));
            }
            say(c, &t("hubappr.status_note", &[]));
            Ok(())
        }
    }
}

pub fn run(cmd: &HubApproversCommand, f: Flags) -> Result<(), CliError> {
    use std::io::IsTerminal;
    let keys = crate::approval_key_cli::keychain();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = std::io::stdout();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0);
    let mut c = Ctx {
        keys: keys.as_ref(),
        state_dir: std::env::var_os("OZBOX_HUB_STATE_DIR").map(PathBuf::from),
        box_markers: ozbox_hubd::registrar::laptop::Site::default().box_markers,
        stdin: &mut lock,
        interactive: std::io::stdin().is_terminal(),
        out: &mut out,
        now,
    };
    run_with(cmd, &mut c, f)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use ozbox_core::hub::approvals::ServicePin;
    use ozbox_core::hub::engine::HubState;
    use ozbox_core::hub::testkit::{test_rp, Passkey};

    const NOW: u64 = 1_800_000_000_000;
    const YES: Flags = Flags {
        yes: true,
        dry_run: false,
        json: false,
    };

    struct Rig {
        dir: tempfile::TempDir,
        keys: MemorySecrets,
        seed: String,
    }

    fn pin(box_id: &str) -> ServicePin {
        ServicePin {
            ids: Ids {
                box_id: box_id.into(),
                store_id: format!("store-{box_id}"),
            },
            envelope_key_hex: "ab".repeat(32),
        }
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let store = ozbox_core::channel::store::Store::<HubState>::new(dir.path().join("hub"));
        let mut st = HubState::new("main", "fp-main", 1);
        st.pin_service("box-a", pin("box-a"));
        st.pin_service("box-b", pin("box-b"));
        store.create(&st).unwrap();
        let (seed, _) = crate::approval_key::generate().unwrap();
        let keys = MemorySecrets::default();
        keys.set(
            &format!("{}laptop", crate::approval_key::KEYCHAIN_PREFIX),
            &seed,
        )
        .unwrap();
        Rig {
            dir,
            keys,
            seed: seed.to_string(),
        }
    }

    fn go(
        r: &Rig,
        cmd: &HubApproversCommand,
        f: Flags,
        on_box: bool,
        input: &str,
    ) -> (Result<(), CliError>, String) {
        let mut stdin = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        let res = {
            let mut c = Ctx {
                keys: &r.keys,
                state_dir: Some(r.dir.path().to_path_buf()),
                box_markers: if on_box {
                    vec![r.dir.path().to_path_buf()]
                } else {
                    vec![]
                },
                stdin: &mut stdin,
                interactive: !input.is_empty(),
                out: &mut out,
                now: NOW,
            };
            run_with(cmd, &mut c, f)
        };
        (res, String::from_utf8(out).unwrap())
    }

    fn creds(r: &Rig, p: &Passkey) -> PathBuf {
        let path = r.dir.path().join("creds.json");
        let rec = CredentialRecord {
            credential_id: p.id.clone(),
            person: "owner".into(),
            role: ozbox_core::approval::Role::Owner,
            public_key: p.public_hex(),
            rp: test_rp(),
        };
        std::fs::write(&path, serde_json::json!({"approvers": [rec]}).to_string()).unwrap();
        path
    }

    fn targets(r: &Rig) -> PathBuf {
        let path = r.dir.path().join("targets.json");
        let (res, _) = go(
            r,
            &HubApproversCommand::Targets {
                out: Some(path.clone()),
            },
            YES,
            false,
            "",
        );
        res.unwrap();
        path
    }

    fn sign_cmd(r: &Rig, p: &Passkey, version: u64, out: &str) -> HubApproversCommand {
        HubApproversCommand::Sign {
            targets: targets_path(r),
            credentials: creds(r, p),
            version,
            valid_days: 30,
            key_id: "laptop".into(),
            out: r.dir.path().join(out),
        }
    }

    fn targets_path(r: &Rig) -> PathBuf {
        let p = r.dir.path().join("targets.json");
        if !p.exists() {
            targets(r);
        }
        p
    }

    #[test]
    fn targets_name_the_workers_with_their_ids_and_a_hub_with_no_state_says_so() {
        let r = rig();
        let p = targets(&r);
        let t: Targets = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(t.workers.len(), 2);
        assert_eq!(t.workers[0].box_id, "box-a");
        // listing prints them too
        let (res, out) = go(
            &r,
            &HubApproversCommand::Targets { out: None },
            YES,
            false,
            "",
        );
        res.unwrap();
        assert!(out.contains("box-a") && out.contains("box-b"), "{out}");
        // a computer with no hub state is told so
        let empty = tempfile::tempdir().unwrap();
        let mut stdin = std::io::Cursor::new(Vec::new());
        let mut out = Vec::new();
        let mut c = Ctx {
            keys: &r.keys,
            state_dir: Some(empty.path().to_path_buf()),
            box_markers: vec![],
            stdin: &mut stdin,
            interactive: false,
            out: &mut out,
            now: NOW,
        };
        let e = run_with(&HubApproversCommand::Targets { out: None }, &mut c, YES).unwrap_err();
        assert!(e.to_string().contains("no hub state"), "{e}");
    }

    #[test]
    fn signing_is_on_your_own_computer_planned_confirmed_and_never_prints_a_key() {
        let r = rig();
        let owner = Passkey::new("cred-owner").unwrap();
        // refused on a box
        let (res, _) = go(&r, &sign_cmd(&r, &owner, 1, "b.json"), YES, true, "");
        assert!(res.unwrap_err().to_string().contains("never on a box"));
        // dry run: the plan, nothing written
        let dry = Flags {
            yes: false,
            dry_run: true,
            json: false,
        };
        let (res, out) = go(&r, &sign_cmd(&r, &owner, 1, "b.json"), dry, false, "");
        res.unwrap();
        assert!(
            out.contains("box-a") && out.contains("version 1") && out.contains("Dry run"),
            "{out}"
        );
        assert!(!r.dir.path().join("b.json").exists());
        // not confirmed in a non-terminal: refused
        let no = Flags {
            yes: false,
            dry_run: false,
            json: false,
        };
        assert!(go(&r, &sign_cmd(&r, &owner, 1, "b.json"), no, false, "")
            .0
            .is_err());
        // confirmed: the bundle holds one signed set per worker, each verifying with the laptop's key and no other
        let (res, out) = go(&r, &sign_cmd(&r, &owner, 1, "b.json"), no, false, "y\n");
        res.unwrap();
        let b: Bundle =
            serde_json::from_slice(&std::fs::read(r.dir.path().join("b.json")).unwrap()).unwrap();
        assert_eq!(b.sets.len(), 2);
        let pk = crate::approval_key::public_of(&r.seed).unwrap();
        let ids = Ids {
            box_id: "box-a".into(),
            store_id: "store-box-a".into(),
        };
        let set = b.sets[0]
            .signed
            .verify(std::slice::from_ref(&pk), &ids, NOW + 1)
            .unwrap();
        assert_eq!(set.seq, 1);
        let (other_seed, _) = crate::approval_key::generate().unwrap();
        let other_pk = crate::approval_key::public_of(&other_seed).unwrap();
        assert!(b.sets[0].signed.verify(&[other_pk], &ids, NOW + 1).is_err());
        // a bundle is not overwritten, and no key value is in anything printed or written
        assert!(go(&r, &sign_cmd(&r, &owner, 1, "b.json"), YES, false, "")
            .0
            .is_err());
        let written = std::fs::read_to_string(r.dir.path().join("b.json")).unwrap();
        assert!(!out.contains(&r.seed) && !written.contains(&r.seed));
        // no key on this computer
        let nokey = Rig {
            dir: tempfile::tempdir().unwrap(),
            keys: MemorySecrets::default(),
            seed: String::new(),
        };
        std::fs::write(
            nokey.dir.path().join("targets.json"),
            std::fs::read(targets_path(&r)).unwrap(),
        )
        .unwrap();
        let cmd = HubApproversCommand::Sign {
            targets: nokey.dir.path().join("targets.json"),
            credentials: creds(&nokey, &owner),
            version: 1,
            valid_days: 30,
            key_id: "laptop".into(),
            out: nokey.dir.path().join("x.json"),
        };
        assert!(go(&nokey, &cmd, YES, false, "")
            .0
            .unwrap_err()
            .to_string()
            .contains("no approval key"));
        // a version no higher than the one a worker holds, and a life over 90 days, are refused
        let mut st = ozbox_core::channel::store::Store::<HubState>::new(r.dir.path().join("hub"))
            .read()
            .unwrap();
        st.peers
            .entry("box-a".into())
            .or_default()
            .approvers
            .held_seq = 3;
        ozbox_core::channel::store::Store::<HubState>::new(r.dir.path().join("hub"))
            .update(|d| *d = st)
            .unwrap();
        std::fs::remove_file(r.dir.path().join("targets.json")).unwrap();
        let (res, _) = go(&r, &sign_cmd(&r, &owner, 3, "c.json"), YES, false, "");
        assert!(res.unwrap_err().to_string().contains("not higher"));
        let long = HubApproversCommand::Sign {
            targets: targets_path(&r),
            credentials: creds(&r, &owner),
            version: 9,
            valid_days: 91,
            key_id: "laptop".into(),
            out: r.dir.path().join("d.json"),
        };
        assert!(go(&r, &long, YES, false, "").0.is_err());
    }

    #[test]
    fn sync_shows_the_plan_needs_a_confirmation_leaves_one_bundle_for_the_server_and_status_says_what_the_worker_holds(
    ) {
        let r = rig();
        let owner = Passkey::new("cred-owner").unwrap();
        go(&r, &sign_cmd(&r, &owner, 1, "b.json"), YES, false, "")
            .0
            .unwrap();
        let sync = HubApproversCommand::Sync {
            bundle: r.dir.path().join("b.json"),
        };
        let no = Flags {
            yes: false,
            dry_run: false,
            json: false,
        };
        let dry = Flags {
            yes: false,
            dry_run: true,
            json: false,
        };
        let (res, out) = go(&r, &sync, dry, false, "");
        res.unwrap();
        assert!(
            out.contains("send version 1 to box-a") && out.contains("checks your signature itself"),
            "{out}"
        );
        assert!(!r.dir.path().join(OUTBOX_FILE).exists());
        assert!(go(&r, &sync, no, false, "").0.is_err());
        go(&r, &sync, no, false, "yes\n").0.unwrap();
        assert!(r.dir.path().join(OUTBOX_FILE).exists());
        // one at a time: the server has not taken it yet
        assert!(go(&r, &sync, YES, false, "")
            .0
            .unwrap_err()
            .to_string()
            .contains("already waiting"));
        let (res, out) = go(&r, &HubApproversCommand::Status, YES, false, "");
        res.unwrap();
        assert!(
            out.contains("box-a")
                && out.contains("is waiting for the server")
                && out.contains("own account"),
            "{out}"
        );
        // a bundle for a worker the hub has not pinned, or for other ids, is refused before anything is queued
        std::fs::remove_file(r.dir.path().join(OUTBOX_FILE)).unwrap();
        let mut b: Bundle =
            serde_json::from_slice(&std::fs::read(r.dir.path().join("b.json")).unwrap()).unwrap();
        b.sets[0].worker = "box-z".into();
        std::fs::write(r.dir.path().join("z.json"), serde_json::to_vec(&b).unwrap()).unwrap();
        let bad = HubApproversCommand::Sync {
            bundle: r.dir.path().join("z.json"),
        };
        assert!(go(&r, &bad, YES, false, "")
            .0
            .unwrap_err()
            .to_string()
            .contains("box-z"));
        assert!(!r.dir.path().join(OUTBOX_FILE).exists());
        // a file that is not a bundle is refused unread
        std::fs::write(r.dir.path().join("junk.json"), b"{\"sets\":[],\"x\":1}").unwrap();
        let junk = HubApproversCommand::Sync {
            bundle: r.dir.path().join("junk.json"),
        };
        assert!(go(&r, &junk, YES, false, "").0.is_err());
    }
}
