//! After a box starts a new secrets store, its secrets service has a new key, and the one this computer pinned no longer matches:
//! the next `ozbox secrets import --box` would be refused with "not the one this computer pinned". This module is what
//! `ozbox upgrade` (and `ozbox admin <box> -- recover-secrets`) say about that right away, instead of leaving it for the first failed
//! import.
//!
//! * It reads the new key's fingerprint through the box's ingress account (the route `ozbox secrets ingress pin` uses, which no
//!   process of the box user is on). The fingerprint is worked out here from the key, never taken from the box's word.
//! * It **never changes a pin silently.** With a person at a terminal it shows the old and the new fingerprint and needs the box
//!   name typed, exactly as `ozbox secrets ingress pin --replace` does. Anywhere else (a pipe, `--json`, `--yes`) it changes
//!   nothing and says the one command to run.
//! * A box this computer has no pin for has nothing to replace: the first request pins it and says the fingerprint.

use std::io::{BufRead, IsTerminal};

use ozbox_core::CommandRunner;

use crate::ingress_client::{fetch_key, Pins};
use crate::messages::t;
use crate::run::upgrade::{Step, StepOutcome};

/// Whether there is a person at a terminal to type the confirmation: input and the prompt's output are both a terminal.
pub fn at_a_terminal() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// The prompt on the terminal: the question is printed, and the answer must be the box's name.
pub fn confirm_on_terminal(box_name: &str) -> impl FnMut(&str) -> bool + '_ {
    move |prompt| {
        eprint!("{prompt}");
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        line.trim() == box_name
    }
}

/// What to say, and (with a terminal) offer, once `box_name` has a new secrets store. `None` when there is nothing to say: this
/// computer pins no key for the box, so the first request will pin the new one.
pub fn after_new_store(
    runner: &dyn CommandRunner,
    pins: &dyn Pins,
    box_name: &str,
    interactive: bool,
    confirm: &mut dyn FnMut(&str) -> bool,
) -> Option<Step> {
    let old = pins.get(box_name)?;
    let fresh = match fetch_key(runner, box_name) {
        Ok(k) => k,
        Err(f) => {
            let why = match f.into_cli(box_name) {
                crate::run::CliError::Msg(m) => m,
                other => other.to_string(),
            };
            return Some(Step::new(
                StepOutcome::Failed,
                t(
                    "ingress.repin_unread",
                    &[("box", box_name), ("old", &old.fingerprint), ("why", &why)],
                ),
            ));
        }
    };
    if fresh == old {
        return Some(Step::new(
            StepOutcome::Skipped,
            t("ingress.repin_unchanged", &[("box", box_name)]),
        ));
    }
    let args = [
        ("box", box_name),
        ("old", old.fingerprint.as_str()),
        ("now", fresh.fingerprint.as_str()),
    ];
    if !interactive {
        return Some(Step::new(
            StepOutcome::Failed,
            t("ingress.repin_needed", &args),
        ));
    }
    let prompt = t(
        "ingress.pin_replace_prompt",
        &[
            ("box", box_name),
            ("pinned", &old.fingerprint),
            ("now", &fresh.fingerprint),
            ("word", box_name),
        ],
    );
    if !confirm(&prompt) {
        return Some(Step::new(
            StepOutcome::Failed,
            t("ingress.repin_declined", &args),
        ));
    }
    match pins.put(box_name, &fresh) {
        Ok(()) => Some(Step::new(StepOutcome::Done, t("ingress.repin_done", &args))),
        Err(why) => Some(Step::new(
            StepOutcome::Failed,
            format!("{} ({why})", t("ingress.repin_needed", &args)),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ingress_client::{testing::MemoryPins, Pin};
    use ozbox_core::{Output, RecordingRunner};
    use serde_json::json;

    fn box_key_answer(r: &RecordingRunner, name: &str, key: &ozbox_seal::ServiceKey) {
        r.reply(Output {
            status: Some(0),
            stdout: json!({"ok": true, "result": {
                "public": ozbox_seal::public_to_hex(&key.public()),
                "fingerprint": key.fingerprint(),
                "box": name,
            }})
            .to_string(),
            stderr: String::new(),
        });
    }

    fn pin_of(key: &ozbox_seal::ServiceKey) -> Pin {
        Pin {
            public_hex: ozbox_seal::public_to_hex(&key.public()),
            fingerprint: key.fingerprint(),
        }
    }

    /// The box's store was replaced, so its service has a new key and this computer still pins the old one. Never changed without the
    /// typed confirmation; the one command and BOTH fingerprints are said where nothing can be typed.
    #[test]
    fn a_new_key_is_never_pinned_without_a_confirmation_and_the_command_is_named() {
        let b = "dev-1";
        let old = ozbox_seal::ServiceKey::generate().unwrap();
        let new = ozbox_seal::ServiceKey::generate().unwrap();
        MemoryPins.put(b, &pin_of(&old)).unwrap();

        // no terminal (a pipe, --json, --yes): nothing changes and the exact command is said, with the new fingerprint
        let r = RecordingRunner::new();
        box_key_answer(&r, b, &new);
        let step =
            after_new_store(&r, &MemoryPins, b, false, &mut |_| panic!("no prompt")).unwrap();
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail
                .contains("ozbox secrets ingress pin --box dev-1 --replace")
                && step.detail.contains(&new.fingerprint())
                && step.detail.contains(&old.fingerprint()),
            "{}",
            step.detail
        );
        assert_eq!(
            MemoryPins.get(b).unwrap(),
            pin_of(&old),
            "the pin was not touched"
        );

        // a terminal, and the answer is not the box's name: still not changed, and it says so
        let r = RecordingRunner::new();
        box_key_answer(&r, b, &new);
        let mut asked = String::new();
        let step = after_new_store(&r, &MemoryPins, b, true, &mut |p| {
            asked = p.to_string();
            false
        })
        .unwrap();
        assert!(
            asked.contains(&old.fingerprint())
                && asked.contains(&new.fingerprint())
                && asked.contains("dev-1"),
            "{asked}"
        );
        assert!(
            step.detail.contains("nothing was changed") && step.detail.contains("--replace"),
            "{}",
            step.detail
        );
        assert_eq!(MemoryPins.get(b).unwrap(), pin_of(&old));

        // confirmed at a terminal: re-pinned, and the fingerprints are said
        let r = RecordingRunner::new();
        box_key_answer(&r, b, &new);
        let step = after_new_store(&r, &MemoryPins, b, true, &mut |_| true).unwrap();
        assert_eq!(step.outcome, StepOutcome::Done);
        assert!(step.detail.contains(&new.fingerprint()), "{}", step.detail);
        assert_eq!(MemoryPins.get(b).unwrap(), pin_of(&new));
    }

    #[test]
    fn an_unchanged_key_an_unpinned_box_and_an_unreadable_box_are_each_said_right() {
        let key = ozbox_seal::ServiceKey::generate().unwrap();
        // this computer pins nothing for the box: the first request pins it, so there is nothing to say
        let r = RecordingRunner::new();
        assert!(after_new_store(&r, &MemoryPins, "never-pinned", true, &mut |_| true).is_none());
        assert!(r.calls().is_empty(), "nothing was asked of the box");
        // the same key: nothing to do
        MemoryPins.put("same", &pin_of(&key)).unwrap();
        let r = RecordingRunner::new();
        box_key_answer(&r, "same", &key);
        let step =
            after_new_store(&r, &MemoryPins, "same", true, &mut |_| panic!("no prompt")).unwrap();
        assert_eq!(step.outcome, StepOutcome::Skipped);
        // the box cannot be reached: the command is still named, and the pin is kept
        MemoryPins.put("down", &pin_of(&key)).unwrap();
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(255),
            stdout: String::new(),
            stderr: "connection refused".into(),
        });
        let step = after_new_store(&r, &MemoryPins, "down", true, &mut |_| true).unwrap();
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail
                .contains("ozbox secrets ingress pin --box down --replace"),
            "{}",
            step.detail
        );
        assert_eq!(MemoryPins.get("down").unwrap(), pin_of(&key));
    }
}
