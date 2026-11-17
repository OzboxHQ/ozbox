//! `ozbox secrets approval-key enroll | revoke | list` and `ozbox secrets approve`: the laptop side of the laptop-key
//! approval (see `approval_key`). The Ed25519 seed lives in this computer's keychain under `approval-key-<id>` and is never
//! printed, sent or put in an argument; only the public key and signatures cross to the box, over its SSH route.

use ozbox_core::{BoxName, CommandRunner};
use serde_json::{json, Value};

use crate::approval_key as ak;
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::{KeychainSecrets, SecretStore};
use crate::workload_cli::ssh_receive;

fn keychain_name(id: &str) -> String {
    format!("{}{id}", ak::KEYCHAIN_PREFIX)
}

fn id_of(id: &str) -> Result<&str, CliError> {
    if ak::id_ok(id) {
        Ok(id)
    } else {
        Err(CliError::Msg(t("approval_key.bad_id", &[])))
    }
}

fn say(json: bool, v: &Value, text: String) {
    if json {
        println!("{v}");
    } else {
        println!("{text}");
    }
}

/// Make a key on this computer and enrol its public half on the box.
pub fn enroll(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    box_name: &BoxName,
    id: &str,
    approval: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let id = id_of(id)?;
    let name = keychain_name(id);
    // One key may approve on many boxes (`ozbox create` pins the `laptop` key on each): a key already in this computer's
    // keychain is enrolled as it is, and only a key made here is removed if the box does not take it.
    let existing = keys.get(&name).map_err(|e| CliError::Msg(e.0))?;
    let made = existing.is_none();
    let public = match existing {
        Some(seed) => {
            let seed = zeroize::Zeroizing::new(seed);
            ak::public_of(&seed).map_err(CliError::Msg)?
        }
        None => {
            let (seed, public) = ak::generate().map_err(CliError::Msg)?;
            keys.set(&name, &seed).map_err(|e| CliError::Msg(e.0))?;
            public
        }
    };
    let req = json!({"op": "approval_key_enroll", "key_id": id, "public_key": public,
        "approval": approval.unwrap_or("")});
    match ssh_receive(runner, box_name.as_str(), &req) {
        Ok(v) => {
            let via = v["result"]["via"].as_str().unwrap_or("").to_string();
            say(
                json,
                &json!({"key": id, "enrolled": true, "via": via}),
                t(
                    "approval_key.enrolled",
                    &[("id", id), ("box", box_name.as_str()), ("via", &via)],
                ),
            );
            Ok(())
        }
        Err(e) => {
            // a key made for this enrolment and not taken is not kept; a key that was already here stays
            if made {
                let _ = keys.delete(&name);
            }
            Err(e)
        }
    }
}

pub fn revoke(
    runner: &dyn CommandRunner,
    box_name: &BoxName,
    id: &str,
    approval: Option<&str>,
    json: bool,
) -> Result<(), CliError> {
    let id = id_of(id)?;
    let req =
        json!({"op": "approval_key_revoke", "key_id": id, "approval": approval.unwrap_or("")});
    ssh_receive(runner, box_name.as_str(), &req)?;
    // the private half stays in this computer's keychain: the same key may still approve on other boxes
    say(
        json,
        &json!({"key": id, "revoked": true}),
        t(
            "approval_key.revoked",
            &[("id", id), ("box", box_name.as_str())],
        ),
    );
    Ok(())
}

pub fn list(runner: &dyn CommandRunner, box_name: &BoxName, json: bool) -> Result<(), CliError> {
    let v = ssh_receive(runner, box_name.as_str(), &json!({"op": "approval_keys"}))?;
    let ids: Vec<String> = v["result"]["keys"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if json {
        println!("{}", json!({"keys": ids}));
    } else if ids.is_empty() {
        println!("{}", t("approval_key.none", &[("box", box_name.as_str())]));
    } else {
        for i in ids {
            println!("{i}");
        }
    }
    Ok(())
}

/// Ask the box for a challenge, sign it with this computer's key, and return the approval code the box made (and how long it
/// lasts, in seconds). Nothing is printed.
pub fn obtain(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    box_name: &BoxName,
    id: &str,
    scope: &str,
    project: &str,
    env: &str,
) -> Result<(String, Value), CliError> {
    let id = id_of(id)?;
    let seed = keys
        .get(&keychain_name(id))
        .map_err(|e| CliError::Msg(e.0))?
        .ok_or_else(|| CliError::Msg(t("approval_key.no_local", &[("id", id)])))?;
    let seed = zeroize::Zeroizing::new(seed);
    let ch = ssh_receive(
        runner,
        box_name.as_str(),
        &json!({"op": "approval_challenge", "key_id": id, "scope": scope, "project": project, "env": env}),
    )?;
    let nonce = ch["result"]["nonce"].as_str().unwrap_or("").to_string();
    let expires = ch["result"]["expires_ms"].as_u64().unwrap_or(0);
    if nonce.is_empty() || expires == 0 {
        return Err(CliError::Msg(t("approval_key.bad_answer", &[])));
    }
    let signature = ak::sign(
        &seed,
        &ak::message(scope, project, env, id, &nonce, expires),
    )
    .map_err(CliError::Msg)?;
    let done = ssh_receive(
        runner,
        box_name.as_str(),
        &json!({"op": "approval_redeem", "key_id": id, "nonce": nonce, "signature": signature}),
    )?;
    let code = done["result"]["code"].as_str().unwrap_or("");
    if code.is_empty() {
        return Err(CliError::Msg(t("approval_key.bad_answer", &[])));
    }
    Ok((
        code.to_string(),
        done["result"]["expires_in_seconds"].clone(),
    ))
}

/// [`obtain`] with this computer's pinned `laptop` key, for a command that needs an approval and has no person to ask: `None`
/// when this computer holds no such key (a box with no second factor needs none) or the box would not give one; the request
/// is then sent without, and the box says why if it needed one.
pub fn obtain_for(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    box_name: &BoxName,
    scope: &str,
) -> Option<String> {
    obtain(runner, keys, box_name, ak::PIN_ID, scope, "", "")
        .ok()
        .map(|(c, _)| c)
}

/// Ask the box for a challenge, sign it with this computer's key, and print the approval code the box made.
#[allow(clippy::too_many_arguments)]
pub fn approve(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    box_name: &BoxName,
    id: &str,
    scope: &str,
    project: &str,
    env: &str,
    json: bool,
    dry_run: bool,
) -> Result<(), CliError> {
    // A key kept on a computer never decides Production (ADR 0041 section 3): say so now, before a code is made that the box would
    // refuse as "not valid". A dry run says it too, since it tells what a real run would do.
    if crate::secrets_approval::laptop_key_never_covers(scope, env) {
        return Err(CliError::Msg(t(
            "approval_key.production_needs_dashboard",
            &[("box", box_name.as_str()), ("env", env)],
        )));
    }
    if dry_run {
        let id = id_of(id)?;
        // a dry run reads no key (only whether it exists: the private half may prompt for the keychain), asks the box
        // nothing and mints nothing: it says what a real run would do
        if !keys
            .exists(&keychain_name(id))
            .map_err(|e| CliError::Msg(e.0))?
        {
            return Err(CliError::Msg(t("approval_key.no_local", &[("id", id)])));
        }
        say(
            json,
            &json!({"dry_run": true, "would_approve": scope, "project": project, "env": env,
                "box": box_name.as_str(), "key": id}),
            t(
                "approval_key.dry_run",
                &[("scope", scope), ("box", box_name.as_str()), ("key", id)],
            ),
        );
        return Ok(());
    }
    let (code, expires_in) = obtain(runner, keys, box_name, id, scope, project, env)?;
    // the code is the one thing this prints: it is single-use, scoped and expires in minutes
    say(
        json,
        &json!({"code": code, "scope": scope, "project": project, "env": env,
            "expires_in_seconds": expires_in}),
        t("approval_key.code", &[("code", &code), ("scope", scope)]),
    );
    Ok(())
}

pub fn keychain() -> Box<dyn SecretStore> {
    KeychainSecrets::detect()
}

/// The key a new box is given as its first approver: this computer's `laptop` key, made in the keychain when there is
/// none. Returns the label value that pins it (the public half in base32). The private half never leaves the keychain.
/// `OZBOX_APPROVAL_PIN=off` makes a box with no pin.
pub fn pin_for_create(keys: &dyn SecretStore) -> Result<Option<String>, String> {
    if std::env::var("OZBOX_APPROVAL_PIN").as_deref() == Ok("off") {
        return Ok(None);
    }
    let name = keychain_name(ak::PIN_ID);
    let public = match keys.get(&name).map_err(|e| e.0)? {
        Some(seed) => {
            let seed = zeroize::Zeroizing::new(seed);
            ak::public_of(&seed)?
        }
        None => {
            let (seed, public) = ak::generate()?;
            keys.set(&name, &seed).map_err(|e| e.0)?;
            public
        }
    };
    ak::pin_label(&public)
        .map(Some)
        .ok_or_else(|| "the key could not be made".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use ozbox_core::{Output, RecordingRunner};

    #[test]
    fn a_dry_run_mints_nothing_asks_the_box_nothing_and_says_what_it_would_do() {
        let keys = MemorySecrets::default();
        keys.set(&keychain_name("laptop"), "x").unwrap();
        let r = RecordingRunner::new();
        let b = BoxName::new("dev").unwrap();
        // the runner has no reply queued: any call to the box would be noticed
        approve(
            &r, &keys, &b, "laptop", "import", "app", "staging", true, true,
        )
        .unwrap();
        assert!(r.calls().is_empty(), "a dry run must not contact the box");
        // and a dry run without the key is still refused, so it tells the truth about what a real run would do
        let none = MemorySecrets::default();
        assert!(approve(&r, &none, &b, "laptop", "import", "", "", true, true).is_err());
    }

    /// `secrets approve` for a Production import is refused up front with the rule, even as a dry run, and asks the box nothing.
    /// Every other environment, and every other scope, goes on as before.
    #[test]
    fn approving_a_production_import_with_this_computers_key_is_refused_before_anything_is_asked() {
        let keys = MemorySecrets::default();
        keys.set(&keychain_name("laptop"), "x").unwrap();
        let r = RecordingRunner::new();
        let b = BoxName::new("dev").unwrap();
        for env in ["production", "prod", "live", "qa"] {
            for dry in [true, false] {
                let e = approve(&r, &keys, &b, "laptop", "import", "app", env, true, dry)
                    .unwrap_err()
                    .to_string();
                assert!(
                    e.contains(crate::secrets_approval::PRODUCTION_IMPORT_RULE) && e.contains(env),
                    "{env} dry={dry}: {e}"
                );
            }
        }
        assert!(r.calls().is_empty(), "nothing was asked of the box");
        // staging still works (dry run: it reads no key and asks nothing), and so does a Production-named policy scope
        approve(
            &r, &keys, &b, "laptop", "import", "app", "staging", true, true,
        )
        .unwrap();
        approve(
            &r,
            &keys,
            &b,
            "laptop",
            "policy",
            "app",
            "production",
            true,
            true,
        )
        .unwrap();
        // the catalogue sentence and the service's sentence are the same words
        let said = crate::messages::t(
            "approval_key.production_needs_dashboard",
            &[("box", "dev"), ("env", "production")],
        );
        assert!(
            said.starts_with(crate::secrets_approval::PRODUCTION_IMPORT_RULE),
            "{said}"
        );
    }

    fn answer(r: &RecordingRunner, v: Value) {
        r.reply(Output {
            status: Some(0),
            stdout: v.to_string(),
            stderr: String::new(),
        });
    }

    /// The `laptop` key `ozbox create` pins is one key for every box: enrolling it on another box sends the same public
    /// half, and revoking it on one box leaves it for the others.
    #[test]
    fn a_key_already_on_this_computer_is_enrolled_as_it_is_and_a_revoke_keeps_it() {
        let keys = MemorySecrets::default();
        let label = pin_for_create(&keys).unwrap().unwrap();
        let seed = keys.get("approval-key-laptop").unwrap().unwrap();
        let public = ak::public_of(&seed).unwrap();
        assert_eq!(ak::pin_label(&public).unwrap(), label);
        let b = BoxName::new("dev").unwrap();
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        answer(
            &r,
            json!({"ok": true, "result": {"via": "dashboard-stepup"}}),
        );
        enroll(&r, &keys, &b, "laptop", Some("code"), true).unwrap();
        // the request is sealed: neither the public key nor the approval code is in what travels
        let outer = String::from_utf8(r.calls()[0].stdin.clone().unwrap()).unwrap();
        assert!(!outer.contains(&public) && !outer.contains("\"code\""));
        let sent =
            crate::ingress_client::testing::open_sent("dev", r.calls()[0].stdin.as_ref().unwrap())
                .to_string();
        assert!(sent.contains(&public) && !sent.contains(&seed));
        assert_eq!(keys.get("approval-key-laptop").unwrap().unwrap(), seed);
        // a box that refuses does not cost this computer its key
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "no approver yet".into(),
        });
        assert!(enroll(&r, &keys, &b, "laptop", None, true).is_err());
        assert_eq!(keys.get("approval-key-laptop").unwrap().unwrap(), seed);
        let r = RecordingRunner::new();
        answer(&r, json!({"ok": true, "result": {"via": "root"}}));
        revoke(&r, &b, "laptop", None, true).unwrap();
        assert_eq!(keys.get("approval-key-laptop").unwrap().unwrap(), seed);
        // a key made for an enrolment the box refused is not kept
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "refused".into(),
        });
        assert!(enroll(&r, &keys, &b, "spare", None, true).is_err());
        assert!(keys.get("approval-key-spare").unwrap().is_none());
    }
}
