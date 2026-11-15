//! `ozbox adopt-fleet-key <box>`: move an existing AWS box's secrets store to the fleet's KMS key, in place (ADR 0029
//! Amendment 11).
//!
//! A box made before the fleet key existed keeps its store's key in a file on its system disk, and an upgrade replaces that
//! disk, so the store would be lost. `ozbox upgrade` cannot move the key: a new machine configured for KMS over a store the
//! file key still seals would never open it. So this is a separate, consented step, in three parts that each say what they do:
//!
//! 1. **Here, begin.** The box's root channel is asked first (it must answer, and the box must be on a file key that has not
//!    moved), a stale cancel mark on the box is taken away, and then the box's role is given the fleet key (for this box's own
//!    secrets only) and the box is marked as *moving*: the key goes on the box as the instance tag `ozbox-secrets-adopt`.
//!    That tag is **not** the label an upgrade reads as "kept" (`ozbox-secrets-key`), and while it is on, an upgrade is refused.
//! 2. **On the box.** Its root step (which reads that tag) re-wraps a copy of the store's keys under KMS while the service
//!    keeps serving, then swaps it in during a short stop, and the service restarts on KMS (`secrets_adopt`). What the store
//!    holds is kept. The box keeps its key file until step 3.
//! 3. **Here, finish.** Only when the box's **root** says (read through the cloud's own root channel, AWS Systems Manager
//!    Run Command, never over the box user's SSH, which that user can make say anything) that the service, the store and the
//!    copy on `/work` are all on KMS under this key, is the real label written, so the next upgrade keeps the store. Then the
//!    box destroys its key file, and this command waits for the box to say it did and says what it saw.
//!
//! **Cancel** is two parts in this order: the box's root records a cancel mark under the box's lock (which a move cannot run
//! past, so the check and the act are one step on the box) and takes a store that already moved back under its file key; only
//! when the root channel then says the box is on its file key with the mark in place is the tag and the grant taken away.
//!
//! A box whose own program is older than this feature cannot do part 2; the service's state says so (`adopt=kms`), and this
//! command refuses before it changes anything. Such a box (a box made on 0.1.1 or earlier) is upgraded first, accepting a
//! new store, and then moved.

use ozbox_core::{BoxRecord, BoxState};
use ozbox_provider_aws::{RootCommand, SecretsKeyStage, SecretsKeyStep};
use serde::Serialize;

use super::{print_json, CliError, Flags, Result};
use crate::messages::t;
use crate::secrets_adopt_facts::{Facts, Kek, Probe};
use crate::secrets_state::State;
use crate::serve::agent::AgentError;

/// What the box says about its store over the box user's SSH: the service's state (when it has written one) and whether the
/// unit is active. **Only for courtesy checks** (is this a box that can do its part): the box user can forge it, so nothing
/// lasting or destructive is ever decided from it.
pub type StateAnswer = std::result::Result<(Option<State>, bool), AgentError>;

/// What the command needs from the world, so the sandbox and the tests supply their own.
pub struct Deps<'a> {
    /// The box as it is now.
    pub get: &'a dyn Fn() -> Result<BoxRecord>,
    /// The fleet key configured on this computer, if any.
    pub configured: Option<(String, String)>,
    /// What the change would do, as lines for a person (nothing is changed).
    pub preview: &'a dyn Fn(&BoxRecord, SecretsKeyStep) -> Result<Vec<String>>,
    /// Plan again and apply one in-place step.
    pub apply: &'a dyn Fn(&BoxRecord, SecretsKeyStep) -> Result<()>,
    /// The service's own state on the box, asked over the box user's route. Courtesy only.
    pub state: &'a dyn Fn(&BoxRecord) -> StateAnswer,
    /// A fixed program run as root on the box through the cloud's root channel; what it printed. `Err` carries why.
    pub root: &'a dyn Fn(&BoxRecord, RootCommand) -> std::result::Result<String, String>,
    /// The cloud's own record of the box's tags: `Ok(true)` only when a read that WORKED listed neither key label on the
    /// instance. `Ok(false)` when one is there, `Err` when the read failed (never "no tag").
    pub tags_absent: &'a dyn Fn(&BoxRecord) -> std::result::Result<bool, String>,
    /// Ask the box to read its instance tags now (the root helper's `configure-box-secrets`); the box does it again every
    /// 15 minutes anyway, so a refusal here is not fatal.
    pub trigger: &'a dyn Fn(&BoxRecord) -> std::result::Result<(), String>,
    pub pause: &'a dyn Fn(u64),
    /// The person's consent (`--yes` is consent; otherwise a prompt). Asked for the move and for the cancel.
    pub ask: &'a dyn Fn(&Flags, &str) -> Result<()>,
    /// The second consent before a cancel puts the pre-move copy back, which loses secrets: the person types the box's NAME,
    /// and `--yes` never stands for it.
    pub ask_name: &'a dyn Fn(&Flags, &str) -> Result<()>,
}

/// How many times, and how far apart, the box is asked whether it is on KMS before the command stops waiting.
const WAIT_POLLS: u32 = 18;
const WAIT_SECS: u64 = 10;
/// And how long it waits for the box to remove its key file once the label is written.
const FINISH_POLLS: u32 = 6;

#[derive(Serialize)]
struct Outcome<'a> {
    #[serde(rename = "box")]
    box_name: &'a str,
    /// `moved`, `moved_key_file_stays`, `cancelled`, `waiting` or `already`.
    result: &'a str,
}

fn finish_json(f: &Flags, name: &str, result: &str) -> Result<()> {
    if f.json {
        print_json(&Outcome {
            box_name: name,
            result,
        })?;
    }
    Ok(())
}

/// What the box's root says, strictly parsed. `Err` is a person's words: the root channel did not answer, or not in the
/// shape the box writes.
fn root_facts(
    deps: &Deps<'_>,
    rec: &BoxRecord,
    name: &str,
) -> std::result::Result<Facts, CliError> {
    let out = (deps.root)(rec, RootCommand::AdoptStatus).map_err(|why| {
        // a box whose program does not know the root check is OLDER, not unreachable
        if why == ozbox_provider_aws::ROOT_PROGRAM_OLDER {
            return CliError::Msg(t("adopt_key.err_root_older", &[("box", name)]));
        }
        CliError::Msg(t(
            "adopt_key.err_root_unreachable",
            &[("box", name), ("why", why.as_str())],
        ))
    })?;
    Facts::parse(&out).ok_or_else(|| CliError::Msg(t("adopt_key.err_root_older", &[("box", name)])))
}

pub fn command(deps: &Deps<'_>, name: &str, cancel: bool, f: &Flags) -> Result<()> {
    let say = |s: String| {
        if !f.json {
            println!("{s}");
        }
    };
    let rec = (deps.get)()?;
    let stage = ozbox_provider_aws::AwsBackend::secrets_key_stage(&rec);
    if let SecretsKeyStage::Fleet(arn) = &stage {
        say(t(
            "adopt_key.already",
            &[("box", name), ("key", arn.as_str())],
        ));
        return finish_json(f, name, "already");
    }
    if rec.state != BoxState::Running {
        return Err(CliError::Msg(t(
            "adopt_key.err_not_running",
            &[("box", name), ("state", &rec.state.to_string())],
        )));
    }

    if cancel {
        return cancel_move(deps, &rec, &stage, name, f, &say);
    }

    if stage == SecretsKeyStage::File {
        let Some((arn, _fleet)) = &deps.configured else {
            return Err(CliError::Msg(t("adopt_key.err_no_key", &[("box", name)])));
        };
        // Ask the box BEFORE anything is changed: it must say that it keeps its key in a file, is ready, and has a program new
        // enough to do its part. A box that cannot is never left half-moved. (The box user's answer: a courtesy.)
        match (deps.state)(&rec) {
            Err(e) => {
                return Err(CliError::Msg(t(
                    "adopt_key.err_unreachable",
                    &[("box", name), ("why", &e.to_string())],
                )))
            }
            Ok((None, _)) => {
                return Err(CliError::Msg(t("adopt_key.err_older", &[("box", name)])));
            }
            Ok((Some(st), _)) => {
                if !st.ready {
                    return Err(CliError::Msg(if st.is_no_escrow() {
                        t("adopt_key.err_lost", &[("box", name)])
                    } else {
                        t(
                            "adopt_key.err_not_ready",
                            &[("box", name), ("why", st.text.as_str())],
                        )
                    }));
                }
                if st.kek.as_deref() != Some("file") {
                    return Err(CliError::Msg(t(
                        "adopt_key.err_not_file",
                        &[
                            ("box", name),
                            ("kek", st.kek.as_deref().unwrap_or("not said")),
                        ],
                    )));
                }
                if !st.adopt {
                    return Err(CliError::Msg(t("adopt_key.err_older", &[("box", name)])));
                }
            }
        }
        // And the box's ROOT must agree, through the channel the box user is not in: the same facts every later decision uses.
        let facts = root_facts(deps, &rec, name)?;
        // a box that already moved and kept what a move leaves, but carries no label: the state a lost race leaves
        if facts.moved_and_kept() {
            return Err(CliError::Msg(t("adopt_key.err_stranded", &[("box", name)])));
        }
        if facts.store_kek != Kek::File
            || facts.service_kek != Kek::File
            || !facts.service_ready
            || facts.settings_key.is_some()
            || facts.busy
        {
            return Err(CliError::Msg(t(
                "adopt_key.err_not_file",
                &[("box", name), ("kek", "something other than a file key")],
            )));
        }
        // L5: with the key granted, the instance role's credentials can open this box's KMS-wrapped copy on /work; the box user
        // must not be able to reach them. The guard that stops it is checked by the box's root, not assumed.
        if !facts.metadata_guard {
            return Err(CliError::Msg(t("adopt_key.err_no_guard", &[("box", name)])));
        }
        say(t(
            "adopt_key.intro",
            &[("box", name), ("key", arn.as_str())],
        ));
        for l in (deps.preview)(&rec, SecretsKeyStep::Begin)? {
            say(format!("  {l}"));
        }
        say(t("adopt_key.promise", &[("box", name)]));
        if f.dry_run {
            say(t("admin.dry_run", &[]));
            return Ok(());
        }
        (deps.ask)(f, name)?;
        // A cancel mark an earlier cancel left on the box would hold the move; it goes first, under the box's lock.
        let armed = (deps.root)(&rec, RootCommand::AdoptArm).map_err(|why| {
            CliError::Msg(t(
                "adopt_key.err_root_unreachable",
                &[("box", name), ("why", why.as_str())],
            ))
        })?;
        if armed.lines().next() != Some("arm=ok") {
            return Err(CliError::Msg(t("adopt_key.err_busy", &[("box", name)])));
        }
        (deps.apply)(&rec, SecretsKeyStep::Begin)?;
        say(t("adopt_key.begun", &[("box", name)]));
    } else {
        // already moving (an earlier run was interrupted or the box had not answered): carry on from where it stands
        say(t("adopt_key.resuming", &[("box", name)]));
        if f.dry_run {
            say(t("admin.dry_run", &[]));
            return Ok(());
        }
        // a cancel that was recorded on the box and not finished here: the box will not move, so waiting is pointless
        if root_facts(deps, &rec, name)?.cancelled {
            return Err(CliError::Msg(t("adopt_key.err_marked", &[("box", name)])));
        }
    }

    // Part 2 happens on the box; ask it to look at its tags now, then ask its root what it says.
    let rec = (deps.get)()?;
    let SecretsKeyStage::Pending(arn) = ozbox_provider_aws::AwsBackend::secrets_key_stage(&rec)
    else {
        return Err(CliError::Msg(t(
            "adopt_key.err_not_moving",
            &[("box", name)],
        )));
    };
    if let Err(why) = (deps.trigger)(&rec) {
        say(t("adopt_key.trigger_failed", &[("why", why.as_str())]));
    }
    let mut committable = false;
    let mut backoff = 0;
    for poll in 0..WAIT_POLLS {
        if let Ok(out) = (deps.root)(&rec, RootCommand::AdoptStatus) {
            if let Some(facts) = Facts::parse(&out) {
                if facts.committable(&arn) {
                    committable = true;
                    break;
                }
                backoff = facts.move_backoff_mins;
            }
        }
        if poll + 1 < WAIT_POLLS {
            (deps.pause)(WAIT_SECS);
        }
    }
    if !committable {
        if backoff > 0 {
            say(t(
                "adopt_key.backoff",
                &[("box", name), ("mins", &backoff.to_string())],
            ));
        }
        say(t("adopt_key.waiting", &[("box", name)]));
        finish_json(f, name, "waiting")?;
        return Err(CliError::Msg(t("adopt_key.err_waiting", &[("box", name)])));
    }
    // Part 3: the box's root said so; now the label an upgrade reads. Its facts are read once more right before the apply: a
    // second operator may have cancelled while this one waited, and the tag swap must not land over that.
    let rec = (deps.get)()?;
    if !root_facts(deps, &rec, name)?.committable(&arn) {
        return Err(CliError::Msg(t("adopt_key.err_changed", &[("box", name)])));
    }
    (deps.apply)(&rec, SecretsKeyStep::Finish)?;
    // The box destroys its key file once it sees the label (its timer, or now); wait for it to say so and say what it did.
    let rec = (deps.get)()?;
    if let Err(why) = (deps.trigger)(&rec) {
        say(t("adopt_key.trigger_failed", &[("why", why.as_str())]));
    }
    for poll in 0..FINISH_POLLS {
        if let Ok(out) = (deps.root)(&rec, RootCommand::AdoptStatus) {
            if Facts::parse(&out).is_some_and(|facts| facts.finished()) {
                say(t("adopt_key.done", &[("box", name)]));
                return finish_json(f, name, "moved");
            }
        }
        if poll + 1 < FINISH_POLLS {
            (deps.pause)(WAIT_SECS);
        }
    }
    say(t("adopt_key.done_key_file_stays", &[("box", name)]));
    finish_json(f, name, "moved_key_file_stays")
}

/// `--cancel`: the box's root records the cancel and puts a moved store back first; the grant goes only when it says it is done.
fn cancel_move(
    deps: &Deps<'_>,
    rec: &BoxRecord,
    stage: &SecretsKeyStage,
    name: &str,
    f: &Flags,
    say: &dyn Fn(String),
) -> Result<()> {
    if !matches!(stage, SecretsKeyStage::Pending(_)) {
        // No label on the box: either nothing is moving, or the box is STRANDED (moved, with no label and no grant left).
        return cancel_stranded(deps, rec, name, f, say);
    }
    // The root channel must be there before anything is promised: without it the box cannot be told, and the grant stays.
    let before = root_facts(deps, rec, name)?;
    if before.busy {
        return Err(CliError::Msg(t("adopt_key.err_busy", &[("box", name)])));
    }
    say(t("adopt_key.cancel_intro", &[("box", name)]));
    for l in (deps.preview)(rec, SecretsKeyStep::Cancel)? {
        say(format!("  {l}"));
    }
    if f.dry_run {
        say(t("admin.dry_run", &[]));
        return Ok(());
    }
    (deps.ask)(f, name)?;
    // On the box, under its lock: the mark is written (no move starts or finishes past it) and a store that already moved is
    // re-wrapped back under its file key. Then, and only then, the facts are read again.
    let mut which = RootCommand::AdoptCancel;
    let mut offered = false;
    let confirmed = loop {
        let out = (deps.root)(rec, which).map_err(|why| {
            CliError::Msg(t(
                "adopt_key.err_cancel_unreachable",
                &[("box", name), ("why", why.as_str())],
            ))
        })?;
        let first = out.lines().next().unwrap_or("");
        let rest: String = out.lines().skip(1).collect::<Vec<_>>().join("\n");
        if first == "cancel=busy" {
            return Err(CliError::Msg(t("adopt_key.err_busy", &[("box", name)])));
        }
        if let Some(why) = first.strip_prefix("cancel=failed:") {
            let said = Facts::parse(&rest);
            // N3 and R2: the store cannot be re-wrapped back. The copy made before the move is on the box, and putting it back
            // loses what was saved since, so it is offered ONLY when the box's root says the key service itself refuses it
            // (an access-denied answer: never a timeout, never a blocked network), and asked for twice, the second time by
            // name. `--yes` is neither.
            if which == RootCommand::AdoptCancel
                && !offered
                && !f.yes
                && said.as_ref().is_some_and(Facts::copy_restore_justified)
            {
                offered = true;
                say(t(
                    "adopt_key.cancel_copy_offer",
                    &[("box", name), ("why", why.trim())],
                ));
                (deps.ask_name)(f, name)?;
                // read again right before the lossy step: the grant may have been given back while the person decided
                if !root_facts(deps, rec, name)?.copy_restore_justified() {
                    return Err(CliError::Msg(t("adopt_key.err_changed", &[("box", name)])));
                }
                which = RootCommand::AdoptCancelFromCopy;
                continue;
            }
            if said
                .as_ref()
                .is_some_and(|x| x.moved_and_kept() && x.kms_probe != Probe::Denied)
            {
                say(t("adopt_key.cancel_copy_not_offered", &[("box", name)]));
            }
            return Err(CliError::Msg(t(
                "adopt_key.err_cancel_failed",
                &[("box", name), ("why", why.trim())],
            )));
        }
        break first == "cancel=ok"
            && Facts::parse(&rest).is_some_and(|facts| facts.cancel_confirmed());
    };
    if !confirmed {
        return Err(CliError::Msg(t(
            "adopt_key.err_cancel_unsure",
            &[("box", name)],
        )));
    }
    // read once more right before the grant goes: a second operator's Begin since the box confirmed would have taken the mark
    // away, and removing the tag and the grant then would strand a store that moved for that operator
    if !root_facts(deps, rec, name)?.cancel_confirmed() {
        return Err(CliError::Msg(t("adopt_key.err_changed", &[("box", name)])));
    }
    (deps.apply)(rec, SecretsKeyStep::Cancel)?;
    say(t("adopt_key.cancelled", &[("box", name)]));
    finish_json(f, name, "cancelled")
}

/// `--cancel` on a box that carries no label. When the box's root says it moved and kept what a move leaves (the store on KMS,
/// its key file, the copy of the store made before the move), the cloud's own tag list shows neither label (a read that worked),
/// and the key service itself refuses the box's role (an access-denied answer), the grant is gone and the store cannot be
/// opened: the copy made before the move is the way back. It loses every secret saved since, so the person is asked twice, the
/// second time by the box's name, and `--yes` is neither. Anything less than all of that changes nothing.
fn cancel_stranded(
    deps: &Deps<'_>,
    rec: &BoxRecord,
    name: &str,
    f: &Flags,
    say: &dyn Fn(String),
) -> Result<()> {
    let not_moving = || CliError::Msg(t("adopt_key.err_not_moving", &[("box", name)]));
    let facts = root_facts(deps, rec, name)?;
    if !facts.moved_and_kept() {
        return Err(not_moving());
    }
    match (deps.tags_absent)(rec) {
        Ok(true) => {}
        Ok(false) => return Err(not_moving()),
        Err(why) => {
            return Err(CliError::Msg(t(
                "adopt_key.err_tags_unread",
                &[("box", name), ("why", why.as_str())],
            )))
        }
    }
    match facts.kms_probe {
        Probe::Denied => {}
        Probe::Ok => {
            return Err(CliError::Msg(t(
                "adopt_key.err_kms_answers",
                &[("box", name)],
            )))
        }
        Probe::Failed | Probe::Na => {
            return Err(CliError::Msg(t(
                "adopt_key.err_kms_unchecked",
                &[("box", name)],
            )))
        }
    }
    say(t("adopt_key.cancel_stranded_intro", &[("box", name)]));
    if f.dry_run {
        say(t("admin.dry_run", &[]));
        return Ok(());
    }
    if f.yes {
        return Err(CliError::Msg(t(
            "adopt_key.err_stranded_needs_person",
            &[("box", name)],
        )));
    }
    (deps.ask)(f, name)?;
    (deps.ask_name)(f, name)?;
    // everything is read again, from the cloud and from the box's root, right before the lossy step
    if !(deps.tags_absent)(rec).is_ok_and(|absent| absent)
        || !root_facts(deps, rec, name)?.copy_restore_justified()
    {
        return Err(CliError::Msg(t("adopt_key.err_changed", &[("box", name)])));
    }
    let out = (deps.root)(rec, RootCommand::AdoptCancelFromCopy).map_err(|why| {
        CliError::Msg(t(
            "adopt_key.err_cancel_unreachable",
            &[("box", name), ("why", why.as_str())],
        ))
    })?;
    let first = out.lines().next().unwrap_or("");
    let rest: String = out.lines().skip(1).collect::<Vec<_>>().join("\n");
    if first == "cancel=busy" {
        return Err(CliError::Msg(t("adopt_key.err_busy", &[("box", name)])));
    }
    if let Some(why) = first.strip_prefix("cancel=failed:") {
        return Err(CliError::Msg(t(
            "adopt_key.err_cancel_failed",
            &[("box", name), ("why", why.trim())],
        )));
    }
    if first != "cancel=ok" || !Facts::parse(&rest).is_some_and(|x| x.cancel_confirmed()) {
        return Err(CliError::Msg(t(
            "adopt_key.err_cancel_unsure",
            &[("box", name)],
        )));
    }
    say(t("adopt_key.cancelled_stranded", &[("box", name)]));
    finish_json(f, name, "cancelled")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets_adopt_facts::tests::{on_file, on_kms};
    use std::cell::{Cell, RefCell};

    const ARN: &str = "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";

    fn record(stage: &SecretsKeyStage, state: BoxState) -> BoxRecord {
        let mut spec = ozbox_core::BoxSpec::new(
            ozbox_core::BoxName::new("main").unwrap(),
            ozbox_core::Size::S,
        );
        match stage {
            SecretsKeyStage::Fleet(k) => {
                spec.labels
                    .insert(ozbox_provider_aws::SECRETS_KEY_LABEL.into(), k.clone());
            }
            SecretsKeyStage::Pending(k) => {
                spec.labels
                    .insert(ozbox_provider_aws::SECRETS_ADOPT_LABEL.into(), k.clone());
            }
            SecretsKeyStage::File => {}
        }
        BoxRecord {
            spec,
            state,
            provider: "aws".into(),
            provider_id: Some("i-1".into()),
            machine_type: Some("m7i.xlarge".into()),
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        }
    }

    type Said = std::result::Result<(Option<State>, bool), String>;

    /// A box and a laptop, scripted. `ssh` is what the BOX USER's answer says (it can be anything); `facts` is what the box's
    /// ROOT says, and is the only thing that decides.
    struct World {
        stage: RefCell<SecretsKeyStage>,
        state: BoxState,
        configured: Option<(String, String)>,
        ssh: RefCell<Said>,
        facts: RefCell<Facts>,
        /// `Err`: the root channel does not answer
        root_up: Cell<bool>,
        log: RefCell<Vec<String>>,
        trigger_ok: bool,
        /// the box moves to KMS (and its copy follows) once it has been asked to look at its tags
        moves_when_triggered: Cell<bool>,
        /// once the label is there the box removes its key file when asked to look
        finishes_when_labelled: Cell<bool>,
        /// what the root helper prints for a cancel, instead of really doing it
        cancel_reply: RefCell<Option<String>>,
        /// what the root helper prints for the cancel from the pre-move copy (when None, it works)
        copy_reply: RefCell<Option<String>>,
        /// the person's answers to the prompts, in order (none left: yes)
        answers: RefCell<Vec<bool>>,
        /// the box's program is older than the root check
        root_older: Cell<bool>,
        /// what the cloud's own tag list says: `Ok(true)` no label on the instance, `Ok(false)` one there, `Err` unreadable
        tags_gone: RefCell<std::result::Result<bool, String>>,
    }

    impl World {
        fn new(stage: SecretsKeyStage, ssh: State) -> Self {
            Self {
                stage: RefCell::new(stage),
                state: BoxState::Running,
                configured: Some((ARN.into(), "dev".into())),
                ssh: RefCell::new(Ok((Some(ssh), true))),
                facts: RefCell::new(on_file()),
                root_up: Cell::new(true),
                log: RefCell::new(vec![]),
                trigger_ok: true,
                moves_when_triggered: Cell::new(true),
                finishes_when_labelled: Cell::new(true),
                cancel_reply: RefCell::new(None),
                copy_reply: RefCell::new(None),
                answers: RefCell::new(vec![]),
                tags_gone: RefCell::new(Ok(true)),
                root_older: Cell::new(false),
            }
        }
        fn run(&self, cancel: bool, f: &Flags) -> Result<()> {
            let deps = Deps {
                get: &|| Ok(record(&self.stage.borrow(), self.state)),
                configured: self.configured.clone(),
                preview: &|_, step| {
                    self.log.borrow_mut().push(format!("preview {step:?}"));
                    Ok(vec![
                        "aws_iam_role_policy_attachment.fleet_key[0]: create".into()
                    ])
                },
                apply: &|_, step| {
                    self.log.borrow_mut().push(format!("apply {step:?}"));
                    let mut s = self.stage.borrow_mut();
                    *s = match (step, s.clone()) {
                        (SecretsKeyStep::Begin, _) => SecretsKeyStage::Pending(ARN.into()),
                        (SecretsKeyStep::Finish, SecretsKeyStage::Pending(k)) => {
                            SecretsKeyStage::Fleet(k)
                        }
                        (SecretsKeyStep::Cancel, _) => SecretsKeyStage::File,
                        (_, other) => other,
                    };
                    Ok(())
                },
                state: &|_| self.ssh.borrow().clone().map_err(AgentError::Unreachable),
                root: &|_, which| {
                    self.log.borrow_mut().push(format!("root {which:?}"));
                    if !self.root_up.get() {
                        return Err("AccessDeniedException: ssm:SendCommand".into());
                    }
                    if self.root_older.get() {
                        return Err(ozbox_provider_aws::ROOT_PROGRAM_OLDER.into());
                    }
                    let mut facts = self.facts.borrow_mut();
                    match which {
                        RootCommand::AdoptStatus => {
                            // the box's own timer: once labelled it removes its key file
                            if matches!(*self.stage.borrow(), SecretsKeyStage::Fleet(_))
                                && self.finishes_when_labelled.get()
                                && facts.store_kek == Kek::Kms
                            {
                                facts.key_file = false;
                                facts.backup = false;
                            }
                            Ok(facts.render())
                        }
                        RootCommand::AdoptArm => {
                            facts.cancelled = false;
                            Ok("arm=ok\n".into())
                        }
                        RootCommand::AdoptCancelFromCopy => {
                            if let Some(r) = self.copy_reply.borrow().clone() {
                                return Ok(r);
                            }
                            *facts = Facts {
                                cancelled: true,
                                ..on_file()
                            };
                            Ok(format!("cancel=ok\n{}", facts.render()))
                        }
                        RootCommand::AdoptCancel => {
                            if let Some(r) = self.cancel_reply.borrow().clone() {
                                return Ok(r);
                            }
                            *facts = Facts {
                                cancelled: true,
                                ..on_file()
                            };
                            Ok(format!("cancel=ok\n{}", facts.render()))
                        }
                    }
                },
                trigger: &|_| {
                    self.log.borrow_mut().push("trigger".into());
                    if self.moves_when_triggered.get()
                        && matches!(*self.stage.borrow(), SecretsKeyStage::Pending(_))
                    {
                        *self.facts.borrow_mut() = on_kms();
                    }
                    if self.trigger_ok {
                        Ok(())
                    } else {
                        Err("not answering".into())
                    }
                },
                tags_absent: &|_| {
                    self.log.borrow_mut().push("tags".into());
                    self.tags_gone.borrow().clone()
                },
                pause: &|_| self.log.borrow_mut().push("pause".into()),
                ask: &|_, _| self.answer("ask"),
                ask_name: &|f, _| {
                    // `--yes` never stands for the box's name
                    if f.yes {
                        self.log.borrow_mut().push("ask_name refused --yes".into());
                        return Err(CliError::Msg("a name is typed by a person".into()));
                    }
                    self.answer("ask_name")
                },
            };
            command(&deps, "main", cancel, f)
        }
        fn answer(&self, which: &str) -> Result<()> {
            self.log.borrow_mut().push(which.into());
            let yes = {
                let mut a = self.answers.borrow_mut();
                if a.is_empty() {
                    true
                } else {
                    a.remove(0)
                }
            };
            if yes {
                Ok(())
            } else {
                Err(CliError::Msg("aborted; nothing was changed".into()))
            }
        }
        fn did(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
        fn changed(&self) -> Vec<String> {
            self.did()
                .into_iter()
                .filter(|l| {
                    l.starts_with("apply")
                        || l == "root AdoptArm"
                        || l == "root AdoptCancel"
                        || l == "root AdoptCancelFromCopy"
                })
                .collect()
        }
    }

    fn yes() -> Flags {
        Flags {
            yes: true,
            dry_run: false,
            json: false,
        }
    }

    fn file_box() -> State {
        State::ready("", "file", Some(false))
    }

    #[test]
    fn a_file_keyed_box_is_armed_granted_asked_and_only_then_labelled_on_the_roots_word() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.run(false, &yes()).unwrap();
        let log = w.did();
        let at = |s: &str| log.iter().position(|l| l == s).unwrap();
        // the box's root is asked, the stale mark goes, the grant, the box is asked to look, and the real label last
        assert!(
            at("root AdoptArm") < at("apply Begin")
                && at("apply Begin") < at("trigger")
                && at("trigger") < at("apply Finish"),
            "{log:?}"
        );
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Fleet(ARN.into()));
        // M4: after the label the box is asked again, and its root says the key file is gone
        assert!(at("apply Finish") < log.iter().rposition(|l| l == "root AdoptStatus").unwrap());
        assert!(w.facts.borrow().finished());
    }

    #[test]
    fn a_dry_run_changes_nothing_and_shows_the_plan() {
        let w = World::new(SecretsKeyStage::File, file_box());
        let f = Flags {
            yes: false,
            dry_run: true,
            json: false,
        };
        w.run(false, &f).unwrap();
        assert_eq!(w.changed(), Vec::<String>::new());
        assert!(w.did().contains(&"preview Begin".to_string()));
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::File);
    }

    /// Nothing is changed about a box that cannot do its part, or whose store is not the kind this moves.
    #[test]
    fn a_box_that_cannot_be_moved_is_refused_before_anything_changes() {
        let mut older = file_box();
        older.adopt = false;
        let cases: Vec<(State, &str)> = vec![
            (older, "older"),
            (State::ready("", "tpm2", None), "tpm2"),
            (State::ready("", "kms", None), "kms"),
            (
                State::not_ready(
                    "the key is gone",
                    crate::secrets_state::NO_ESCROW_CODE,
                    Some("file"),
                    Some(false),
                ),
                "recover-secrets",
            ),
            (
                State::not_ready("starting", "transient", Some("file"), None),
                "not ready",
            ),
        ];
        for (said, needle) in cases {
            let w = World::new(SecretsKeyStage::File, said);
            let e = w.run(false, &yes()).unwrap_err().to_string();
            assert!(e.contains("Nothing was changed"), "{needle}: {e}");
            assert!(w.changed().is_empty(), "{needle}: {:?}", w.did());
        }
        // a box that says nothing (a program from before the state existed)
        let w = World::new(SecretsKeyStage::File, file_box());
        *w.ssh.borrow_mut() = Ok((None, false));
        assert!(w
            .run(false, &yes())
            .unwrap_err()
            .to_string()
            .contains("older"));
        assert!(w.changed().is_empty());
        // a box that cannot be asked
        let w = World::new(SecretsKeyStage::File, file_box());
        *w.ssh.borrow_mut() = Err("timed out".into());
        assert!(w
            .run(false, &yes())
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        assert!(w.changed().is_empty());
        // H2: the box user says "file" but the box's ROOT cannot be reached, or says something else: nothing is changed
        let w = World::new(SecretsKeyStage::File, file_box());
        w.root_up.set(false);
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(
            e.contains("Systems Manager") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(w.changed().is_empty());
        let w = World::new(SecretsKeyStage::File, file_box());
        *w.facts.borrow_mut() = on_kms();
        assert!(w.run(false, &yes()).is_err());
        assert!(w.changed().is_empty());
        // no fleet key configured here
        let mut w = World::new(SecretsKeyStage::File, file_box());
        w.configured = None;
        assert!(w
            .run(false, &yes())
            .unwrap_err()
            .to_string()
            .contains("secrets_key_arn"));
        assert!(w.changed().is_empty());
        // a box that is not running
        let mut w = World::new(SecretsKeyStage::File, file_box());
        w.state = BoxState::Paused;
        assert!(w.run(false, &yes()).is_err());
        assert!(w.changed().is_empty());
    }

    /// The box does not say it is on KMS in time: nothing is claimed (no real label), the command fails saying to run it
    /// again, and an upgrade stays refused by the pending mark.
    #[test]
    fn a_box_that_does_not_say_it_is_on_kms_is_never_labelled() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.moves_when_triggered.set(false);
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(e.contains("run it again"), "{e}");
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
        assert!(!w.did().iter().any(|l| l == "apply Finish"));
        assert!(w.did().iter().filter(|l| *l == "pause").count() >= 5);
        // run again once the box has moved: it carries on from the pending mark and finishes
        *w.facts.borrow_mut() = on_kms();
        w.run(false, &yes()).unwrap();
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Fleet(ARN.into()));
        assert_eq!(w.did().iter().filter(|l| *l == "apply Begin").count(), 1);
    }

    /// H2: the box user's answer says "on KMS" and the move had NOT happened (the likeliest first outcome: the grant has not
    /// propagated). The label is not written, whatever the SSH answer says, however many times it is asked.
    #[test]
    fn a_forged_answer_over_ssh_never_writes_the_label() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.moves_when_triggered.set(false);
        *w.ssh.borrow_mut() = Ok((Some(State::ready("", "kms", None)), true));
        w.stage.replace(SecretsKeyStage::Pending(ARN.into()));
        assert!(w.run(false, &yes()).is_err());
        assert!(
            !w.did().iter().any(|l| l == "apply Finish"),
            "{:?}",
            w.did()
        );
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
        // a root channel that is down is never read as "yes" either
        w.root_up.set(false);
        assert!(w.run(false, &yes()).is_err());
        assert!(!w.did().iter().any(|l| l == "apply Finish"));
    }

    /// M4: the copy on /work has not followed (the saver is slow or failing): the box is not committable, so the label is not
    /// written, and an upgrade that rebuilt from /work would not meet a file-wrapped copy under a KMS label.
    #[test]
    fn the_label_waits_for_the_copy_on_work_to_follow() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.moves_when_triggered.set(false);
        w.stage.replace(SecretsKeyStage::Pending(ARN.into()));
        *w.facts.borrow_mut() = Facts {
            persist_kek: Kek::File,
            ..on_kms()
        };
        assert!(w.run(false, &yes()).is_err());
        assert!(!w.did().iter().any(|l| l == "apply Finish"));
    }

    /// M4: the label is written but the box does not say it removed its key file: the words say the key file stays, never that
    /// it is gone, and the result says so.
    #[test]
    fn a_key_file_that_is_still_there_is_never_reported_gone() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.finishes_when_labelled.set(false);
        w.run(false, &yes()).unwrap();
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Fleet(ARN.into()));
        assert!(w.facts.borrow().key_file);
        let said = t("adopt_key.done_key_file_stays", &[("box", "main")]);
        assert!(
            said.contains("has not yet said") && said.contains("next check"),
            "{said}"
        );
        assert!(
            w.did().iter().filter(|l| *l == "root AdoptStatus").count() >= FINISH_POLLS as usize
        );
    }

    #[test]
    fn a_failed_trigger_is_said_and_the_box_is_still_asked() {
        let mut w = World::new(SecretsKeyStage::File, file_box());
        w.trigger_ok = false;
        w.run(false, &yes()).unwrap();
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Fleet(ARN.into()));
    }

    /// H1: the cancel asks the box's root to record it (under the box's lock) BEFORE anything is taken away, and takes the
    /// tag and the grant away only after the root says it is back on its file key with the cancel in place.
    #[test]
    fn cancel_records_on_the_box_first_and_revokes_only_after_the_box_confirms() {
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        w.run(true, &yes()).unwrap();
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::File);
        let log = w.did();
        let at = |s: &str| log.iter().position(|l| l == s).unwrap();
        assert!(at("root AdoptCancel") < at("apply Cancel"), "{log:?}");
        // a box that had already moved is taken back by the same command (the box re-wraps it); the laptop still revokes only
        // once the box says so
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        *w.facts.borrow_mut() = on_kms();
        w.run(true, &yes()).unwrap();
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::File);
        assert!(w.facts.borrow().cancel_confirmed());
    }

    /// H1, the race: the box moves between the laptop's first look and its cancel. The cancel on the box finds a moved box and
    /// cannot take it back (or the box says anything but a confirmed return to file): the grant is NOT revoked.
    #[test]
    fn a_cancel_the_box_does_not_confirm_never_revokes() {
        let moved_unconfirmed = format!("cancel=ok\n{}", {
            Facts {
                cancelled: true,
                ..on_kms()
            }
            .render()
        });
        for (reply, why) in [
            ("cancel=busy\n".to_string(), "busy"),
            ("cancel=failed: KMS cannot be used\n".to_string(), "failed"),
            (moved_unconfirmed, "ok but still on KMS"),
            ("cancel=ok\n".to_string(), "ok with no facts"),
            ("cancel=ok\nnonsense\n".to_string(), "ok with forged facts"),
            (String::new(), "nothing"),
        ] {
            let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
            *w.cancel_reply.borrow_mut() = Some(reply);
            assert!(w.run(true, &yes()).is_err(), "{why}");
            assert!(
                !w.did().contains(&"apply Cancel".to_string()),
                "{why}: {:?}",
                w.did()
            );
            assert_eq!(
                *w.stage.borrow(),
                SecretsKeyStage::Pending(ARN.into()),
                "{why}"
            );
        }
        // the root channel is down: nothing is recorded and nothing is revoked
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        w.root_up.set(false);
        let e = w.run(true, &yes()).unwrap_err().to_string();
        assert!(
            e.contains("Systems Manager") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(w.changed().is_empty(), "{:?}", w.did());
        // a move running on the box right now: not even the cancel is sent
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        w.facts.borrow_mut().busy = true;
        assert!(w.run(true, &yes()).is_err());
        assert!(w.changed().is_empty());
        // the box user's SSH answer (forged "file") changes none of this
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        *w.facts.borrow_mut() = on_kms();
        *w.cancel_reply.borrow_mut() = Some("cancel=failed: x\n".into());
        assert!(w.run(true, &yes()).is_err());
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
    }

    #[test]
    fn cancel_refuses_a_box_that_is_not_moving_and_a_dry_run_changes_nothing() {
        let w = World::new(SecretsKeyStage::File, file_box());
        assert!(w.run(true, &yes()).is_err());
        assert!(w.changed().is_empty());
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        let f = Flags {
            yes: false,
            dry_run: true,
            json: false,
        };
        w.run(true, &f).unwrap();
        assert!(w.changed().is_empty());
        assert!(w.did().contains(&"preview Cancel".to_string()));
    }

    /// Resuming a move whose cancel was recorded on the box but not finished here says so instead of waiting for nothing.
    #[test]
    fn a_resumed_move_on_a_box_with_a_recorded_cancel_says_so() {
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        *w.facts.borrow_mut() = Facts {
            cancelled: true,
            ..on_file()
        };
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(
            e.contains("cancel recorded") && e.contains("--cancel"),
            "{e}"
        );
        assert!(!w.did().contains(&"apply Finish".to_string()));
    }

    #[test]
    fn a_box_already_on_the_fleet_key_has_nothing_to_move() {
        let w = World::new(
            SecretsKeyStage::Fleet(ARN.into()),
            State::ready("", "kms", None),
        );
        w.run(false, &yes()).unwrap();
        assert!(w.did().is_empty());
    }

    /// The command's words never promise more than the box has said.
    #[test]
    fn the_words_name_what_is_kept_and_what_is_not_claimed() {
        let said = t("adopt_key.promise", &[("box", "main")]);
        // M3: the outage is named, not "a few seconds" alone; it grows with the store
        assert!(
            said.contains("per secret") && said.contains("minute"),
            "{said}"
        );
        assert!(said.contains("kept") && said.contains("refuse"), "{said}");
        let done = t("adopt_key.done", &[("box", "main")]);
        // L1: the escrow residual is said, and "gone" is attributed to the box's root, never asserted
        assert!(
            done.contains("root says") && done.contains("escrowed"),
            "{done}"
        );
        // the retired "finish instead of cancel" message and the old claims are gone
        assert!(!said.contains("for a few seconds, re-wraps"));
    }

    fn prompting() -> Flags {
        Flags {
            yes: false,
            dry_run: false,
            json: false,
        }
    }

    /// L5: Begin refuses a box whose metadata guard is not loaded, before anything changes.
    #[test]
    fn begin_refuses_a_box_without_the_metadata_guard() {
        let w = World::new(SecretsKeyStage::File, file_box());
        w.facts.borrow_mut().metadata_guard = false;
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(
            e.contains("metadata guard") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(w.changed().is_empty(), "{:?}", w.did());
    }

    /// What the box's root says when KMS REFUSES it: moved, key file and copy there, and the probe says "access denied".
    fn denied() -> Facts {
        Facts {
            kms_probe: Probe::Denied,
            ..on_kms()
        }
    }

    /// N3 and R2: a cancel that cannot re-wrap offers the pre-move copy ONLY when the box's root says the key service itself
    /// refuses it, asks the person to type the box's NAME, reads the box again, and only then sends the lossy command. `--yes`
    /// is not that consent, and a refusal sends nothing.
    #[test]
    fn a_cancel_that_cannot_rewrap_offers_the_copy_only_on_a_refusal_and_asks_by_name() {
        let stranded = |probe: Facts| {
            let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
            *w.facts.borrow_mut() = probe.clone();
            *w.cancel_reply.borrow_mut() = Some(format!(
                "cancel=failed: KMS cannot be used\n{}",
                probe.render()
            ));
            w
        };
        // the key service refuses: the first consent, then the name, then a fresh read, and the grant goes only after the root confirms
        let w = stranded(denied());
        w.run(true, &prompting()).unwrap();
        let log = w.did();
        assert_eq!(log.iter().filter(|l| *l == "ask").count(), 1, "{log:?}");
        assert_eq!(
            log.iter().filter(|l| *l == "ask_name").count(),
            1,
            "{log:?}"
        );
        let at = |s: &str| log.iter().position(|l| l == s).unwrap();
        assert!(
            at("root AdoptCancel") < at("ask_name")
                && at("ask_name") < at("root AdoptCancelFromCopy")
                && at("root AdoptCancelFromCopy") < at("apply Cancel"),
            "{log:?}"
        );
        // the person declines the name: nothing lossy is sent, nothing is revoked
        let w = stranded(denied());
        *w.answers.borrow_mut() = vec![true, false];
        assert!(w.run(true, &prompting()).is_err());
        assert!(
            !w.did().iter().any(|l| l == "root AdoptCancelFromCopy"),
            "{:?}",
            w.did()
        );
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
        // --yes is not consent to lose data: it is not even offered, and the copy is not used
        let w = stranded(denied());
        let e = w.run(true, &yes()).unwrap_err().to_string();
        assert!(e.contains("could not take the store back"), "{e}");
        assert!(
            !w.did()
                .iter()
                .any(|l| l == "root AdoptCancelFromCopy" || l.starts_with("ask_name")),
            "{:?}",
            w.did()
        );
        assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
        // a blocked egress list, a timeout, a check that could not run, or a KMS that answers: NOT a revoked grant, so the copy
        // is not offered, however the person answers
        for probe in [Probe::Failed, Probe::Ok, Probe::Na] {
            let w = stranded(Facts {
                kms_probe: probe,
                ..on_kms()
            });
            let e = w.run(true, &prompting()).unwrap_err().to_string();
            assert!(
                e.contains("could not take the store back"),
                "{probe:?}: {e}"
            );
            assert!(
                !w.did()
                    .iter()
                    .any(|l| l == "root AdoptCancelFromCopy" || l == "ask_name"),
                "{probe:?}: {:?}",
                w.did()
            );
            assert_eq!(*w.stage.borrow(), SecretsKeyStage::Pending(ARN.into()));
        }
        // the grant came back while the person typed the name: the fresh read stops it
        let w = stranded(denied());
        *w.facts.borrow_mut() = on_kms();
        let e = w.run(true, &prompting()).unwrap_err().to_string();
        assert!(e.contains("says something else now"), "{e}");
        assert!(!w.did().iter().any(|l| l == "root AdoptCancelFromCopy"));
    }

    /// R2: a box that moved and then lost its label and its grant (a lost race) is reached by `--cancel` only after the cloud's
    /// own tag list (a read that worked) shows no label AND the box's root says the key service refuses it; the person types the
    /// box's name; and nothing is applied on AWS (there is no tag or grant left to take away).
    #[test]
    fn a_stranded_box_is_put_back_only_after_the_cloud_and_the_root_both_say_so_and_a_person_types_its_name(
    ) {
        let stranded = || {
            let w = World::new(SecretsKeyStage::File, file_box());
            *w.facts.borrow_mut() = denied();
            w
        };
        let w = stranded();
        w.run(true, &prompting()).unwrap();
        let log = w.did();
        let at = |s: &str| log.iter().position(|l| l == s).unwrap();
        assert!(
            at("tags") < at("ask_name") && at("ask_name") < at("root AdoptCancelFromCopy"),
            "{log:?}"
        );
        assert!(!log.iter().any(|l| l.starts_with("apply")), "{log:?}");
        assert!(w.facts.borrow().cancel_confirmed());
        // a label is on the box in the cloud: not stranded
        let w = stranded();
        *w.tags_gone.borrow_mut() = Ok(false);
        assert!(w.run(true, &prompting()).is_err());
        assert!(w.changed().is_empty(), "{:?}", w.did());
        // the tag list could not be read: that is never "no label"
        let w = stranded();
        *w.tags_gone.borrow_mut() = Err("RequestLimitExceeded".into());
        let e = w.run(true, &prompting()).unwrap_err().to_string();
        assert!(
            e.contains("RequestLimitExceeded") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(w.changed().is_empty(), "{:?}", w.did());
        // the key service answers, could not be asked, or was not asked: not stranded
        for probe in [Probe::Ok, Probe::Failed, Probe::Na] {
            let w = stranded();
            *w.facts.borrow_mut() = Facts {
                kms_probe: probe,
                ..on_kms()
            };
            let e = w.run(true, &prompting()).unwrap_err().to_string();
            assert!(e.contains("Nothing was changed"), "{probe:?}: {e}");
            assert!(w.changed().is_empty(), "{probe:?}: {:?}", w.did());
        }
        // --yes is not enough, and a dry run changes nothing
        let w = stranded();
        let e = w.run(true, &yes()).unwrap_err().to_string();
        assert!(e.contains("needs a person"), "{e}");
        assert!(w.changed().is_empty(), "{:?}", w.did());
        let w = stranded();
        w.run(
            true,
            &Flags {
                yes: false,
                dry_run: true,
                json: false,
            },
        )
        .unwrap();
        assert!(w.changed().is_empty(), "{:?}", w.did());
        // the person declines the name
        let w = stranded();
        *w.answers.borrow_mut() = vec![true, false];
        assert!(w.run(true, &prompting()).is_err());
        assert!(w.changed().is_empty(), "{:?}", w.did());
        // the box is not in that state at all (a file box, nothing moved): there is nothing to cancel
        let w = World::new(SecretsKeyStage::File, file_box());
        assert!(w.run(true, &prompting()).is_err());
        assert!(w.changed().is_empty());
        // and adopt-fleet-key itself says what the box is, and changes nothing
        let w = stranded();
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(
            e.contains("carries no label") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(w.changed().is_empty(), "{:?}", w.did());
    }

    /// R4: a box whose own program is older than the root check is said to be OLDER in the words, not unreachable.
    #[test]
    fn a_box_with_an_older_program_is_said_to_be_older_and_the_policy_is_not_blamed() {
        for cancel in [false, true] {
            let stage = if cancel {
                SecretsKeyStage::Pending(ARN.into())
            } else {
                SecretsKeyStage::File
            };
            let w = World::new(stage, file_box());
            w.root_older.set(true);
            let e = w.run(cancel, &yes()).unwrap_err().to_string();
            assert!(
                e.contains("older") && !e.contains("operator_adopt_policy_json"),
                "{e}"
            );
            assert!(w.changed().is_empty(), "{:?}", w.did());
        }
    }

    /// N3: facts are read again right before each apply. A second operator's Begin (or a delayed command) that changed the
    /// box since it was last read stops the apply, and nothing is revoked or labelled.
    #[test]
    fn the_box_is_read_again_right_before_the_apply() {
        // cancel: the root confirmed, then a Begin elsewhere took the mark away before this one applied
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        *w.cancel_reply.borrow_mut() = Some(format!(
            "cancel=ok\n{}",
            Facts {
                cancelled: true,
                ..on_file()
            }
            .render()
        ));
        // the status the second read sees: the mark is gone
        *w.facts.borrow_mut() = on_file();
        let e = w.run(true, &yes()).unwrap_err().to_string();
        assert!(e.contains("says something else now"), "{e}");
        assert!(
            !w.did().iter().any(|l| l == "apply Cancel"),
            "{:?}",
            w.did()
        );
        // finish: a cancel recorded elsewhere while this one waited
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        w.moves_when_triggered.set(false);
        *w.facts.borrow_mut() = Facts {
            cancelled: true,
            ..on_kms()
        };
        assert!(w.run(false, &yes()).is_err());
        assert!(
            !w.did().iter().any(|l| l == "apply Finish"),
            "{:?}",
            w.did()
        );
    }

    /// N6: when the move cannot finish because the box's store keeps changing, the command waits, changes nothing, and has the
    /// words for how long the box waits (what it prints is its stdout; the words are pinned here).
    #[test]
    fn a_box_that_is_backing_off_is_waited_on_and_the_words_name_the_wait() {
        let w = World::new(SecretsKeyStage::Pending(ARN.into()), file_box());
        w.moves_when_triggered.set(false);
        *w.facts.borrow_mut() = Facts {
            move_backoff_mins: 45,
            ..on_file()
        };
        let e = w.run(false, &yes()).unwrap_err().to_string();
        assert!(e.contains("has not said its store is on KMS"), "{e}");
        assert!(!w.did().iter().any(|l| l == "apply Finish"));
        let words = t("adopt_key.backoff", &[("box", "main"), ("mins", "45")]);
        assert!(
            words.contains("45 more minutes") && words.contains("Nothing was lost"),
            "{words}"
        );
    }
}
