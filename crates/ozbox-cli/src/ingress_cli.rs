//! `ozbox secrets ingress pin | escrow | setup-code`: the commands of the sealed route to a box's secrets service (see
//! `ingress_client`). None of them prints a key; the setup code is printed because it is what the person asked for, and it is
//! single-use and expires in minutes.

use std::io::{BufRead, IsTerminal};

use ozbox_core::{BoxName, CommandRunner, SystemRunner};
use serde_json::json;

use crate::cli::IngressCommand;
use crate::ingress_client::{call, pin_command, FilePins};
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;

/// The keychain entry that holds a copy of a box's file-kept store key.
pub fn escrow_name(box_name: &str) -> String {
    format!("kek-escrow-{box_name}")
}

pub fn run(command: &IngressCommand, json: bool) -> Result<(), CliError> {
    let runner = SystemRunner;
    match command {
        IngressCommand::Pin { on_box, replace } => {
            let pins = FilePins(FilePins::default_path());
            pin_command(
                &runner,
                &pins,
                on_box.as_str(),
                *replace,
                &mut |prompt| {
                    if !std::io::stdin().is_terminal() {
                        return false;
                    }
                    eprint!("{prompt}");
                    let mut line = String::new();
                    let _ = std::io::stdin().lock().read_line(&mut line);
                    line.trim() == on_box.as_str()
                },
                json,
            )
        }
        IngressCommand::Escrow { on_box } => escrow(
            &runner,
            crate::approval_key_cli::keychain().as_ref(),
            on_box,
            json,
        ),
        IngressCommand::SetupCode { on_box } => setup_code(
            &runner,
            crate::approval_key_cli::keychain().as_ref(),
            on_box,
            json,
        ),
        IngressCommand::Requests { on_box, action } => {
            crate::approval_laptop::run(on_box, action, json)
        }
    }
}

/// Fetch the file-kept store key through the ingress route and keep it in this computer's keychain, so `ozbox upgrade` can
/// put it back after the system disk is replaced. The key is never printed.
pub fn escrow(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    on_box: &BoxName,
    json: bool,
) -> Result<(), CliError> {
    // Not by the SSH key alone: once the box has a second factor, the store key leaves it only with an approval from the
    // computer's approval key (ADR 0029, Amendment 9).
    let approval = crate::approval_key_cli::obtain_for(runner, keys, on_box, "kek-export");
    let v = call(
        runner,
        on_box.as_str(),
        &json!({"op": "kek_export", "approval": approval.unwrap_or_default()}),
    )?;
    let kek = zeroize::Zeroizing::new(v["value"].as_str().unwrap_or("").to_string());
    if kek.is_empty() {
        return Err(CliError::Msg(t("ingress.bad_answer", &[])));
    }
    keys.set(&escrow_name(on_box.as_str()), &kek)
        .map_err(|e| CliError::Msg(e.0))?;
    if json {
        println!("{}", json!({"box": on_box.as_str(), "escrowed": true}));
    } else {
        println!("{}", t("ingress.escrowed", &[("box", on_box.as_str())]));
    }
    Ok(())
}

/// The first-time dashboard code, through the ingress route, so it never has to be read from a log the box user can read.
pub fn setup_code(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    on_box: &BoxName,
    json: bool,
) -> Result<(), CliError> {
    let approval = crate::approval_key_cli::obtain_for(runner, keys, on_box, "setup-code");
    let v = call(
        runner,
        on_box.as_str(),
        &json!({"op": "setup_code", "approval": approval.unwrap_or_default()}),
    )?;
    let code = zeroize::Zeroizing::new(v["value"].as_str().unwrap_or("").to_string());
    if code.is_empty() {
        return Err(CliError::Msg(t("ingress.bad_answer", &[])));
    }
    if json {
        println!("{}", json!({"box": on_box.as_str(), "code": code.as_str()}));
    } else {
        println!("{}", t("ingress.setup_code", &[("code", code.as_str())]));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ingress_client::testing;
    use crate::secrets::MemorySecrets;
    use ozbox_core::{Output, RecordingRunner};

    fn reply(r: &RecordingRunner, v: serde_json::Value) {
        r.reply(Output {
            status: Some(0),
            stdout: v.to_string(),
            stderr: String::new(),
        });
    }

    #[test]
    fn the_store_key_goes_to_the_keychain_and_is_not_printed_and_the_request_is_sealed() {
        let b = BoxName::new("esc-box").unwrap();
        testing::install("esc-box");
        let r = RecordingRunner::new();
        reply(&r, json!({"ok": true, "value": "KEK-SENTINEL-abcdef"}));
        let keys = MemorySecrets::default();
        escrow(&r, &keys, &b, true).unwrap();
        assert_eq!(
            keys.get("kek-escrow-esc-box").unwrap().as_deref(),
            Some("KEK-SENTINEL-abcdef")
        );
        let sent = testing::open_sent("esc-box", r.calls()[0].stdin.as_ref().unwrap());
        assert_eq!(sent["op"], "kek_export");
        // a box that gives nothing back stores nothing
        let r = RecordingRunner::new();
        reply(&r, json!({"ok": true}));
        let keys = MemorySecrets::default();
        assert!(escrow(&r, &keys, &b, true).is_err());
        assert!(keys.get("kek-escrow-esc-box").unwrap().is_none());
    }

    #[test]
    fn the_setup_code_is_asked_for_through_the_sealed_route() {
        let b = BoxName::new("code-box").unwrap();
        testing::install("code-box");
        let r = RecordingRunner::new();
        reply(&r, json!({"ok": true, "value": "ABCDE-23456"}));
        setup_code(&r, &MemorySecrets::default(), &b, true).unwrap();
        let sent = testing::open_sent("code-box", r.calls()[0].stdin.as_ref().unwrap());
        assert_eq!(sent["op"], "setup_code");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout:
                json!({"ok": false, "code": "x", "error": "there is no first-time code waiting"})
                    .to_string(),
            stderr: String::new(),
        });
        let e = setup_code(&r, &MemorySecrets::default(), &b, true).unwrap_err();
        assert!(matches!(e, CliError::Msg(m) if m.contains("no first-time code")));
    }
}
