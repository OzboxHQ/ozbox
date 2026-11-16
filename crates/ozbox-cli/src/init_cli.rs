//! `ozbox init`: the guided first-run setup in the terminal. The steps and checks live in [`crate::init`]; this file
//! only asks, shows each plan, confirms, and prints.

use std::io::{BufRead, IsTerminal, Write};

use serde_json::{json, Value};

use crate::init::{
    guardrails, CheckState, Finding, HttpLatency, Init, InitPaths, Prepared, ProbeState, SetupFile,
    SubnetState, Target,
};
use crate::messages::t;
use crate::netguard::UreqClient;
use crate::secrets::SecretStore;
use crate::settings::Settings;

pub struct Args {
    pub provider: Option<String>,
    pub profile: Option<String>,
    pub region: Option<String>,
    pub budget: Option<f64>,
    pub alert_email: Option<String>,
    pub alert_from: Option<String>,
    pub two_factor: bool,
    /// How you will reach your boxes: `session`, `headscale`, `tailscale` or `cloudflare`. Asked when left out.
    pub access: Option<String>,
    /// A zip of the built `ozbox-issuer` program: with it, setup also plans the off-box issuer for Production secrets.
    pub issuer_package: Option<String>,
    /// The package's SHA-256 (hex) from the signed release's manifest or a reproducible build; required with the package.
    pub issuer_package_sha256: Option<String>,
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

/// Where answers come from. A terminal asks; a script (or a test) answers from a list.
pub trait Ask {
    fn interactive(&self) -> bool;
    fn line(&mut self, prompt: &str) -> Option<String>;
}

pub struct Terminal;

impl Ask for Terminal {
    fn interactive(&self) -> bool {
        std::io::stdin().is_terminal()
    }
    fn line(&mut self, prompt: &str) -> Option<String> {
        let mut err = std::io::stderr();
        let _ = write!(err, "{prompt}");
        let _ = err.flush();
        let mut s = String::new();
        std::io::stdin().lock().read_line(&mut s).ok()?;
        Some(s.trim().to_string())
    }
}

fn fail(f: Finding) -> String {
    f.to_string()
}

fn show(out: &mut dyn Write, json: bool, s: String) {
    if !json {
        let _ = writeln!(out, "{s}");
    }
}

fn show_plan(out: &mut dyn Write, json: bool, p: &Prepared) {
    if json {
        return;
    }
    let _ = writeln!(out, "\n{}", p.summary);
    if p.noop {
        let _ = writeln!(out, "  {}", t("init.cli_nothing", &[]));
    }
    for (i, c) in p.changes.iter().enumerate() {
        let _ = writeln!(out, "  {}. [{:?}] {}", i + 1, c.risk, c.description);
    }
    for n in &p.notes {
        let _ = writeln!(out, "  {n}");
    }
    if let Some(e) = p.estimate_usd_month.filter(|e| *e > 0.0) {
        let _ = writeln!(
            out,
            "  {}",
            t("init.cli_estimate", &[("usd", &format!("{e:.2}"))])
        );
    }
}

/// Every mutating step is shown first. `--dry-run` stops here; `--yes` skips the question; a script without `--yes`
/// is refused rather than left hanging.
fn confirm(a: &Args, ask: &mut dyn Ask, what: &str) -> Result<bool, String> {
    match answer(a, ask, what)? {
        Answer::Yes => Ok(true),
        Answer::DryRun => Ok(false),
        Answer::No => Err(t("init.cli_aborted", &[])),
    }
}

/// What the person (or the flags) said about a shown plan.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Yes,
    /// Asked, and the answer was not yes.
    No,
    /// `--dry-run`: nothing is applied and nobody is asked.
    DryRun,
}

/// The question behind [`confirm`], with a "no" kept apart from a refusal: only a script with no `--yes` is an error.
fn answer(a: &Args, ask: &mut dyn Ask, what: &str) -> Result<Answer, String> {
    if a.dry_run {
        return Ok(Answer::DryRun);
    }
    if a.yes {
        return Ok(Answer::Yes);
    }
    if !ask.interactive() {
        return Err(t("init.cli_refuse_no_tty", &[("step", what)]));
    }
    let r = ask.line(&t("init.cli_proceed", &[])).unwrap_or_default();
    Ok(if matches!(r.to_ascii_lowercase().as_str(), "y" | "yes") {
        Answer::Yes
    } else {
        Answer::No
    })
}

/// What happened to each step, for the summary printed at the end.
#[derive(Default)]
struct Ledger {
    applied: Vec<String>,
    skipped: Vec<String>,
    in_place: Vec<String>,
    failed: Vec<String>,
}

impl Ledger {
    fn json(&self) -> Value {
        json!({
            "applied": self.applied,
            "skipped": self.skipped,
            "already_in_place": self.in_place,
            "failed": self.failed,
        })
    }

    fn print(&self, out: &mut dyn Write, json: bool) {
        let rows = [
            ("init.sum_applied", &self.applied),
            ("init.sum_skipped", &self.skipped),
            ("init.sum_in_place", &self.in_place),
            ("init.sum_failed", &self.failed),
        ];
        if rows.iter().all(|(_, v)| v.is_empty()) {
            return;
        }
        show(out, json, t("init.sum_title", &[]));
        for (key, v) in rows {
            if !v.is_empty() {
                show(
                    out,
                    json,
                    format!("  {}", t(key, &[("steps", &v.join(", "))])),
                );
            }
        }
    }
}

/// Whether to apply an OPTIONAL step's plan. Declining it (or having no terminal and no `--yes`) skips just this step, says so,
/// and setup goes on to the next; it never ends the run (the state bucket is the only step that does, and it asks through
/// [`answer`] itself). An unchanged plan needs no question and counts as already in place.
fn optional_go(
    a: &Args,
    ask: &mut dyn Ask,
    out: &mut dyn Write,
    ledger: &mut Ledger,
    step: (&str, &str),
    effect: &str,
    noop: bool,
) -> bool {
    let (what, label) = step;
    if noop {
        ledger.in_place.push(label.to_string());
        return true;
    }
    let why = match answer(a, ask, what) {
        Ok(Answer::Yes) => return true,
        Ok(Answer::DryRun) => t("init.why_dry_run", &[]),
        Ok(Answer::No) => t("init.why_declined", &[]),
        Err(why) => why,
    };
    show(
        out,
        a.json,
        t(
            "init.step_skipped",
            &[("step", label), ("why", &why), ("effect", effect)],
        ),
    );
    ledger.skipped.push(label.to_string());
    false
}

/// Whether to apply the adopt command's step. It is optional (it only matters to move an existing box onto the fleet key), so a
/// "no", or no terminal and no `--yes`, skips THIS step with a message and setup goes on to the box policy; it never ends setup
/// (unlike the key step's prompt, which was already there).
fn adopt_step_go(a: &Args, ask: &mut dyn Ask, out: &mut dyn Write, noop: bool) -> bool {
    if noop {
        return true;
    }
    match confirm(a, ask, "adopt command") {
        Ok(go) => go,
        Err(why) => {
            show(out, a.json, t("init.adopt_skipped", &[("why", &why)]));
            false
        }
    }
}

pub struct Env<'a> {
    pub init: &'a Init<'a>,
    pub settings_path: Option<std::path::PathBuf>,
    pub secrets: &'a dyn SecretStore,
    pub paired_chats: usize,
    pub hcloud_token: Option<String>,
    pub now_ms: u64,
}

pub fn run(
    a: &Args,
    env: &Env<'_>,
    ask: &mut dyn Ask,
    out: &mut dyn Write,
) -> Result<Value, String> {
    let init = env.init;
    let provider = match &a.provider {
        Some(p) => p.clone(),
        None if ask.interactive() && !a.yes => {
            show(out, a.json, t("init.cli_choose", &[]));
            match ask.line("> ").unwrap_or_default().as_str() {
                "2" | "aws" => "aws".into(),
                "3" | "hcloud" => "hcloud".into(),
                _ => "fake".into(),
            }
        }
        None => return Err(t("init.cli_need_provider", &[])),
    };
    let mut target = Target {
        provider: provider.clone(),
        profile: a.profile.clone(),
        region: a.region.clone(),
    };
    target.validate().map_err(fail)?;
    let mut steps: Vec<Value> = Vec::new();
    let mut ledger = Ledger::default();

    if provider == "fake" {
        let p = Prepared::config_only(&t("init.sum_sandbox", &[]), &t("init.chg_sandbox", &[]));
        show_plan(out, a.json, &p);
        if confirm(a, ask, "sandbox")? {
            let g = guardrails(&Settings::default(), env.secrets, 0);
            init.finish(&target, false, &g, env.now_ms).map_err(fail)?;
            show(out, a.json, t("init.cli_sandbox_done", &[]));
        } else {
            show(out, a.json, t("init.cli_dry", &[]));
        }
        return Ok(json!({ "provider": "fake", "completed": !a.dry_run }));
    }

    if provider == "aws" {
        let id = init.sign_in(&target).map_err(fail)?;
        let account = id.account.clone();
        show(out, a.json, t("init.cli_signed_in", &[("arn", &id.arn)]));
        steps.push(json!({ "step": "sign_in", "identity": id }));

        let perms = init.permissions(&target).map_err(fail)?;
        for p in &perms.probes {
            let mark = match p.state {
                ProbeState::Allowed => t("init.mark_ok", &[]),
                ProbeState::Denied => t("init.mark_denied", &[]),
                ProbeState::Unknown => t("init.mark_unknown", &[]),
            };
            show(out, a.json, format!("  [{mark}] {}", p.label));
            if p.state != ProbeState::Allowed {
                if let Some(d) = &p.detail {
                    show(out, a.json, format!("      {d}"));
                }
            }
        }
        if !perms.ok {
            return Err(t("init.cli_perm_denied", &[]));
        }
        steps.push(json!({ "step": "permissions", "report": perms }));

        if target.region.is_none() {
            show(out, a.json, t("init.cli_measuring", &[]));
            let r = init.regions(&target).map_err(fail)?;
            for c in r.candidates.iter().take(6) {
                let ms = c.ms.map_or("-".to_string(), |m| format!("{m} ms"));
                show(out, a.json, format!("  {} ({}) {ms}", c.region, c.name));
            }
            let suggested = r.suggested.clone();
            let pick = match (&suggested, ask.interactive() && !a.yes) {
                (Some(s), true) => {
                    let r = ask
                        .line(&t("init.cli_region_prompt", &[("region", s)]))
                        .unwrap_or_default();
                    if r.is_empty() {
                        s.clone()
                    } else {
                        r
                    }
                }
                (Some(s), false) if a.yes => s.clone(),
                _ => return Err(t("init.cli_need_region", &[])),
            };
            target.region = Some(pick);
            target.validate().map_err(fail)?;
            steps.push(json!({ "step": "region", "report": r }));
        }

        let bucket = init.plan_bucket(&target, &account).map_err(fail)?;
        show_plan(out, a.json, &bucket);
        let mut foundation = true;
        if !bucket.noop {
            // The one required step: everything after it keeps its state there, so declining it ends the run.
            match answer(a, ask, "state bucket")? {
                Answer::Yes => {
                    init.apply(&target, &bucket).map_err(fail)?;
                    ledger.applied.push(t("init.step_bucket", &[]));
                }
                Answer::DryRun => {
                    foundation = false;
                    ledger.skipped.push(t("init.step_bucket", &[]));
                }
                Answer::No => return Err(t("init.cli_bucket_required", &[])),
            }
        } else {
            init.apply(&target, &bucket).map_err(fail)?;
            ledger.in_place.push(t("init.step_bucket", &[]));
        }
        steps.push(json!({ "step": "state_bucket", "plan": bucket }));
        if foundation {
            // A configuration that already names its subnet is using a network: plan nothing (a second one would cost a NAT
            // gateway every month), check the subnet is there and go on.
            if let Some(subnet) = init.configured_subnet() {
                match init.check_subnet(&target, &subnet).map_err(fail)? {
                    SubnetState::Found => {
                        show(
                            out,
                            a.json,
                            t("init.subnet_existing", &[("subnet", &subnet)]),
                        );
                    }
                    SubnetState::Missing => {
                        return Err(t("init.subnet_missing", &[("subnet", &subnet)]));
                    }
                    SubnetState::Unknown(why) => {
                        show(
                            out,
                            a.json,
                            t(
                                "init.subnet_unverified",
                                &[("subnet", &subnet), ("why", &why)],
                            ),
                        );
                    }
                }
                ledger
                    .in_place
                    .push(t("init.step_network_existing", &[("subnet", &subnet)]));
                steps.push(json!({ "step": "network", "existing_subnet": subnet }));
            } else {
                let net = init.plan_network(&target, &account).map_err(fail)?;
                show_plan(out, a.json, &net);
                let label = t("init.step_network", &[]);
                let effect = t("init.effect_network", &[]);
                if optional_go(
                    a,
                    ask,
                    out,
                    &mut ledger,
                    ("network", &label),
                    &effect,
                    net.noop,
                ) {
                    init.apply(&target, &net).map_err(fail)?;
                    if !net.noop {
                        ledger.applied.push(label);
                    }
                }
                steps.push(json!({ "step": "network", "plan": net }));
            }
            // The fleet's secrets key, made with this identity (never the daily operator role), shown and approved like the rest.
            // A failure here never stops setup: boxes keep a file key, and the message says what to ask an administrator for.
            let perm = init.key_permission(&target, &id);
            let missing = match &perm {
                crate::init::KeyPermission::Denied(m) => Some(m.join(", ")),
                _ => None,
            };
            if let Some(m) = &missing {
                show(out, a.json, t("init.key_denied", &[("missing", m)]));
                steps.push(json!({ "step": "secrets_key", "permission": perm }));
            } else {
                if perm == crate::init::KeyPermission::Unknown {
                    show(out, a.json, t("init.key_unknown", &[]));
                }
                match init.plan_key(&target, &account) {
                    Ok(key) => {
                        show_plan(out, a.json, &key);
                        let label = t("init.step_key", &[]);
                        let effect = t("init.effect_key", &[]);
                        let go = optional_go(
                            a,
                            ask,
                            out,
                            &mut ledger,
                            ("secrets key", &label),
                            &effect,
                            key.noop,
                        );
                        if go {
                            match init.apply(&target, &key) {
                                Ok(_) => {
                                    if !key.noop {
                                        ledger.applied.push(label);
                                    }
                                }
                                Err(f) => {
                                    show(out, a.json, f.to_string());
                                    show(out, a.json, t("init.key_unknown", &[]));
                                    ledger.failed.push(label);
                                }
                            }
                        }
                        steps.push(
                            json!({ "step": "secrets_key", "plan": key, "permission": perm }),
                        );
                    }
                    Err(f) => {
                        show(out, a.json, f.to_string());
                        // an adoption refusal is not a permission question: the hint would point the wrong way
                        if !f.code.starts_with("adopt_") {
                            show(out, a.json, t("init.key_unknown", &[]));
                        }
                    }
                }
            }
            // The adopt command's document and its operator policy: a step of its own, made with the permissions it needs
            // (Systems Manager documents, not the key's KMS set). A failure never stops setup or the key above.
            let aperm = init.adopt_permission(&target, &id);
            if let crate::init::KeyPermission::Denied(m) = &aperm {
                show(
                    out,
                    a.json,
                    t("init.adopt_denied", &[("missing", &m.join(", "))]),
                );
                steps.push(json!({ "step": "adopt_command", "permission": aperm }));
            } else {
                if aperm == crate::init::KeyPermission::Unknown {
                    show(out, a.json, t("init.adopt_unknown", &[]));
                }
                match init.plan_adopt(&target, &account) {
                    Ok(ad) => {
                        show_plan(out, a.json, &ad);
                        let label = t("init.step_adopt", &[]);
                        if ad.noop {
                            ledger.in_place.push(label.clone());
                        }
                        if adopt_step_go(a, ask, out, ad.noop) {
                            match init.apply(&target, &ad) {
                                Ok(done) => {
                                    if !ad.noop {
                                        ledger.applied.push(label.clone());
                                    }
                                    if let Some(f) = &done.operator_adopt_policy_file {
                                        show(
                                            out,
                                            a.json,
                                            t("init.adopt_policy_written", &[("path", f)]),
                                        );
                                    }
                                }
                                Err(f) => {
                                    show(out, a.json, f.to_string());
                                    show(out, a.json, t("init.adopt_unknown", &[]));
                                    ledger.failed.push(label);
                                }
                            }
                        } else {
                            ledger.skipped.push(label);
                        }
                        steps.push(
                            json!({ "step": "adopt_command", "plan": ad, "permission": aperm }),
                        );
                    }
                    Err(f) => {
                        show(out, a.json, f.to_string());
                        if !f.code.starts_with("adopt_") {
                            show(out, a.json, t("init.adopt_unknown", &[]));
                        }
                    }
                }
            }
            // The account's policies for boxes' roles (Session Manager, and with the key and bucket above, the fleet key and session logs), made once with this identity, after the key so it can name it. Boxes cannot be created or
            // upgraded without it, so a failure says what to ask an administrator for and never stops the rest of setup.
            match init.plan_box_policy(&target, &account) {
                Ok(bp) => {
                    show_plan(out, a.json, &bp);
                    let label = t("init.step_box_policy", &[]);
                    let effect = t("init.effect_box_policy", &[]);
                    if optional_go(
                        a,
                        ask,
                        out,
                        &mut ledger,
                        ("box policy", &label),
                        &effect,
                        bp.noop,
                    ) {
                        match init.apply(&target, &bp) {
                            Ok(_) => {
                                if !bp.noop {
                                    ledger.applied.push(label);
                                }
                            }
                            Err(f) => {
                                show(out, a.json, f.to_string());
                                show(out, a.json, t("init.box_policy_denied", &[]));
                                ledger.failed.push(label);
                            }
                        }
                    }
                    steps.push(json!({ "step": "box_policy", "plan": bp }));
                }
                Err(f) => {
                    show(out, a.json, f.to_string());
                    if !f.code.starts_with("adopt_") {
                        show(out, a.json, t("init.box_policy_denied", &[]));
                    }
                }
            }
            if let Some(pkg) = &a.issuer_package {
                let iss = init
                    .plan_issuer(
                        &target,
                        &account,
                        std::path::Path::new(pkg),
                        a.issuer_package_sha256.as_deref().unwrap_or(""),
                    )
                    .map_err(fail)?;
                show_plan(out, a.json, &iss);
                let label = t("init.step_issuer", &[]);
                let effect = t("init.effect_issuer", &[]);
                if optional_go(
                    a,
                    ask,
                    out,
                    &mut ledger,
                    ("issuer", &label),
                    &effect,
                    iss.noop,
                ) {
                    init.apply(&target, &iss).map_err(fail)?;
                    if !iss.noop {
                        ledger.applied.push(label);
                    }
                }
                steps.push(json!({ "step": "issuer", "plan": iss }));
            }
        } else {
            show(out, a.json, t("init.cli_network_later", &[]));
        }
    } else {
        let tok = env.hcloud_token.as_deref();
        init.hcloud_sign_in(tok).map_err(fail)?;
        show(out, a.json, t("init.cli_hcloud_ok", &[]));
        if target.region.is_none() {
            let locs = init.hcloud_locations(tok.unwrap_or(""));
            target.region = match (a.yes, locs.first()) {
                (true, Some(l)) => Some(l.clone()),
                _ if ask.interactive() => ask
                    .line(&t("init.cli_hcloud_region", &[("list", &locs.join(", "))]))
                    .filter(|s| !s.is_empty()),
                _ => None,
            };
            if target.region.is_none() {
                return Err(t("init.cli_need_region", &[]));
            }
            target.validate().map_err(fail)?;
        }
    }

    // How the person will reach their boxes. Nothing is opened or installed here: it explains the ways in, preselects the
    // provider's own session service, and prints the command that sets the chosen one up. Changeable at any time.
    let access = choose_access(a, ask, out, &provider)?;
    steps.push(json!({ "step": "access", "path": access }));
    for hook in AFTER_ACCESS {
        hook(a, ask, out, &mut steps)?;
    }

    // Budget and alerts: the guard rail. Every channel is the person's own (own bot, own key); keys go to the
    // secret store, never to a command line or file.
    let mut settings = match &env.settings_path {
        Some(p) => Settings::load_from(p).map_err(|e| e.to_string())?,
        None => Settings::default(),
    };
    let mut changed = false;
    if let Some(b) = a.budget {
        settings.budget.monthly_usd = Some(b);
        changed = true;
    }
    if let (Some(to), Some(from)) = (&a.alert_email, &a.alert_from) {
        settings.apps.email.enabled = true;
        settings.apps.email.to = vec![to.clone()];
        settings.apps.email.from = from.clone();
        changed = true;
        if let Ok(key) = std::env::var("OZBOX_ALERT_EMAIL_API_KEY") {
            env.secrets
                .set("email-api-key", &key)
                .map_err(|e| e.to_string())?;
        }
    }
    if changed && !a.dry_run {
        settings.validate().map_err(|e| e.to_string())?;
        if let Some(p) = &env.settings_path {
            settings.save_to(p).map_err(|e| e.to_string())?;
        }
    }
    let g = guardrails(&settings, env.secrets, env.paired_chats);
    show(
        out,
        a.json,
        t(
            "init.cli_guard",
            &[
                ("budget", if g.budget_set { "set" } else { "missing" }),
                (
                    "alerts",
                    &if g.channels.is_empty() {
                        "missing".to_string()
                    } else {
                        g.channels.join(", ")
                    },
                ),
            ],
        ),
    );
    steps.push(json!({ "step": "guardrails", "report": g }));

    // Security baseline.
    let mut ack = a.two_factor;
    if provider == "aws" {
        let id = init.sign_in(&target).map_err(fail)?;
        let sec = init.security(&target, &id).map_err(fail)?;
        for i in &sec.items {
            let m = match i.state {
                CheckState::Pass => t("init.mark_ok", &[]),
                CheckState::Fail => t("init.mark_fail", &[]),
                CheckState::Reminder => t("init.mark_check", &[]),
            };
            show(out, a.json, format!("  [{m}] {}", i.message));
        }
        if sec.blocking {
            return Err(t("init.cli_blocked", &[]));
        }
        steps.push(json!({ "step": "security", "report": sec }));
    }
    if !ack && ask.interactive() && !a.yes && !a.dry_run {
        let r = ask.line(&t("init.cli_two_factor", &[])).unwrap_or_default();
        ack = matches!(r.to_ascii_lowercase().as_str(), "y" | "yes");
    }
    ledger.print(out, a.json);
    if a.dry_run {
        show(out, a.json, t("init.cli_dry", &[]));
        return Ok(
            json!({ "provider": provider, "completed": false, "dry_run": true, "steps": steps, "summary": ledger.json() }),
        );
    }
    // Without a private subnet (the network step was skipped) the setup cannot be marked complete; say so rather than fail late.
    if provider == "aws" && init.configured_subnet().is_none() {
        show(out, a.json, t("init.cli_incomplete", &[]));
        return Ok(
            json!({ "provider": provider, "completed": false, "steps": steps, "summary": ledger.json() }),
        );
    }
    let file: SetupFile = init.finish(&target, ack, &g, env.now_ms).map_err(fail)?;
    show(out, a.json, t("init.cli_done", &[]));
    Ok(
        json!({ "provider": provider, "completed": file.completed, "steps": steps, "summary": ledger.json() }),
    )
}

/// A step that runs after the access path and before the budget: it may ask, print and add to the report, and must change
/// nothing until the person has confirmed.
type StepHook = fn(&Args, &mut dyn Ask, &mut dyn Write, &mut Vec<Value>) -> Result<(), String>;

/// The hook for steps that come after how you reach your boxes. Empty today. The planned "models" step goes here: it asks
/// which provider keys and cloud accounts you have, suggests a model for each kind of task with its price, and uses nothing
/// until you confirm.
const AFTER_ACCESS: &[StepHook] = &[];

/// The ways in, in the order they are offered. The first is the default.
pub const ACCESS_PATHS: [&str; 4] = ["session", "headscale", "tailscale", "cloudflare"];

/// Explain every way to reach a box and let the person pick one (the provider's session service is preselected: Enter
/// takes it). Not a prompt in a script or with `--yes`: those take `--access`, else the default.
fn choose_access(
    a: &Args,
    ask: &mut dyn Ask,
    out: &mut dyn Write,
    provider: &str,
) -> Result<String, String> {
    if let Some(p) = &a.access {
        let p = p.trim().to_ascii_lowercase();
        return if ACCESS_PATHS.contains(&p.as_str()) {
            Ok(p)
        } else {
            Err(t("init.access_bad", &[]))
        };
    }
    let default = ACCESS_PATHS[0];
    if !(ask.interactive() && !a.yes && !a.dry_run) {
        return Ok(default.to_string());
    }
    let session = if provider == "aws" {
        t("init.access_session_aws", &[])
    } else {
        t("init.access_session_other", &[])
    };
    for (n, key) in [
        (1, session),
        (2, t("init.access_headscale", &[])),
        (3, t("init.access_tailscale", &[])),
        (4, t("init.access_cloudflare", &[])),
    ] {
        show(out, a.json, format!("  {n}. {key}"));
    }
    let answer = ask.line(&t("init.access_prompt", &[])).unwrap_or_default();
    let pick = match answer.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "session" => "session",
        "2" | "headscale" => "headscale",
        "3" | "tailscale" => "tailscale",
        "4" | "cloudflare" => "cloudflare",
        _ => return Err(t("init.access_bad", &[])),
    };
    show(out, a.json, t(&format!("init.access_next_{pick}"), &[]));
    Ok(pick.to_string())
}

/// The real thing: real command runner, real HTTP, the real config directory.
/// `ozbox harden`: the opt-in AWS security services (ADR 0035). The set asked for is the whole desired state.
pub struct HardenArgs {
    pub profile: Option<String>,
    pub region: Option<String>,
    pub opts: crate::init::SecurityOpts,
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

pub fn harden(
    a: &HardenArgs,
    init: &Init<'_>,
    ask: &mut dyn Ask,
    out: &mut dyn Write,
) -> Result<Value, String> {
    let region = a
        .region
        .clone()
        .or_else(|| {
            crate::config::Config::load()
                .ok()
                .and_then(|c| c.aws.and_then(|s| s.region))
        })
        .ok_or_else(|| t("init.cli_need_region", &[]))?;
    let target = Target {
        provider: "aws".into(),
        profile: a.profile.clone(),
        region: Some(region),
    };
    target.validate().map_err(fail)?;
    let id = init.sign_in(&target).map_err(fail)?;
    let prepared = init
        .plan_security(&target, &id.account, &a.opts)
        .map_err(fail)?;
    show_plan(out, a.json, &prepared);
    let args = Args {
        provider: Some("aws".into()),
        profile: a.profile.clone(),
        region: None,
        budget: None,
        alert_email: None,
        alert_from: None,
        two_factor: false,
        access: None,
        issuer_package: None,
        issuer_package_sha256: None,
        yes: a.yes,
        dry_run: a.dry_run,
        json: a.json,
    };
    let mut applied = None;
    if prepared.noop {
        show(out, a.json, t("init.cli_nothing", &[]));
    } else if confirm(&args, ask, "security services")? {
        applied = Some(init.apply(&target, &prepared).map_err(fail)?);
    }
    Ok(json!({ "plan": prepared, "applied": applied }))
}

pub fn run_harden_real(a: &HardenArgs) -> Result<(), String> {
    let paths = InitPaths::detect().ok_or_else(|| t("init.cli_no_home", &[]))?;
    let http = UreqClient;
    let latency = HttpLatency(&http);
    let init = Init {
        runner: &ozbox_core::SystemRunner,
        http: &http,
        latency: &latency,
        paths,
        retry_delay: std::time::Duration::from_secs(3),
    };
    let v = harden(a, &init, &mut Terminal, &mut std::io::stdout())?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    Ok(())
}

pub fn run_real(a: &Args) -> Result<(), String> {
    let paths = InitPaths::detect().ok_or_else(|| t("init.cli_no_home", &[]))?;
    let http = UreqClient;
    let latency = HttpLatency(&http);
    let init = Init {
        runner: &ozbox_core::SystemRunner,
        http: &http,
        latency: &latency,
        paths,
        retry_delay: std::time::Duration::from_secs(3),
    };
    let secrets = crate::serve::secret_store();
    let settings_path = Settings::path();
    let chats = settings_path
        .as_ref()
        .map(|p| {
            crate::state::ServerState::load(&p.with_file_name("state.json"))
                .telegram
                .chats
                .len()
        })
        .unwrap_or(0);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let env = Env {
        init: &init,
        settings_path,
        secrets: secrets.as_ref(),
        paired_chats: chats,
        hcloud_token: std::env::var("HCLOUD_TOKEN").ok(),
        now_ms,
    };
    let mut out = std::io::stdout();
    let v = run(a, &env, &mut Terminal, &mut out)?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::init::Latency;
    use crate::netguard::FakeHttp;
    use crate::secrets::MemorySecrets;
    use ozbox_core::{Output, RecordingRunner};
    use std::time::Duration;

    struct NoLatency;
    impl Latency for NoLatency {
        fn rtt(&self, _: &str) -> Option<Duration> {
            Some(Duration::from_millis(20))
        }
    }
    struct Script(Vec<String>, bool);
    impl Ask for Script {
        fn interactive(&self) -> bool {
            self.1
        }
        fn line(&mut self, _: &str) -> Option<String> {
            if self.0.is_empty() {
                None
            } else {
                Some(self.0.remove(0))
            }
        }
    }
    fn args() -> Args {
        Args {
            provider: Some("fake".into()),
            profile: None,
            region: None,
            budget: None,
            alert_email: None,
            alert_from: None,
            two_factor: false,
            access: None,
            issuer_package: None,
            issuer_package_sha256: None,
            yes: true,
            dry_run: false,
            json: false,
        }
    }
    fn with_init<R>(
        dir: &std::path::Path,
        runner: &RecordingRunner,
        f: impl FnOnce(&Init<'_>) -> R,
    ) -> R {
        let http = FakeHttp::default();
        let init = Init {
            runner,
            http: &http,
            latency: &NoLatency,
            paths: InitPaths {
                config: dir.join("config.toml"),
                setup: dir.join("setup.json"),
                plugin_cache: dir.join("cache"),
                work: dir.join("work"),
                modules: dir.join("modules"),
            },
            retry_delay: Duration::ZERO,
        };
        f(&init)
    }
    fn go(
        a: &Args,
        dir: &std::path::Path,
        runner: &RecordingRunner,
        answers: Vec<&str>,
        tty: bool,
    ) -> (Result<Value, String>, String) {
        let secrets = MemorySecrets::default();
        with_init(dir, runner, |init| {
            let env = Env {
                init,
                settings_path: Some(dir.join("settings.json")),
                secrets: &secrets,
                paired_chats: 0,
                hcloud_token: None,
                now_ms: 5,
            };
            let mut out = Vec::new();
            let mut ask = Script(answers.into_iter().map(String::from).collect(), tty);
            let r = run(a, &env, &mut ask, &mut out);
            (r, String::from_utf8_lossy(&out).into_owned())
        })
    }
    fn o(s: i32, so: &str, se: &str) -> Output {
        Output {
            status: Some(s),
            stdout: so.into(),
            stderr: se.into(),
        }
    }

    #[test]
    fn the_access_path_defaults_to_the_provider_session_service_and_can_be_chosen() {
        let a = args();
        let mut out = Vec::new();
        // a script (no terminal) takes the default, without asking
        let mut ask = Script(vec![], false);
        assert_eq!(
            choose_access(&a, &mut ask, &mut out, "aws").unwrap(),
            "session"
        );
        assert!(out.is_empty());
        // --access names one
        let named = Args {
            access: Some("Headscale".into()),
            issuer_package: None,
            issuer_package_sha256: None,
            ..args()
        };
        assert_eq!(
            choose_access(&named, &mut ask, &mut out, "aws").unwrap(),
            "headscale"
        );
        let bad = Args {
            access: Some("vpn".into()),
            issuer_package: None,
            issuer_package_sha256: None,
            ..args()
        };
        assert!(choose_access(&bad, &mut ask, &mut out, "aws").is_err());
        // on a terminal every way is explained, Enter takes the preselected one, and a number picks another
        let tty = Args {
            yes: false,
            ..args()
        };
        let mut out = Vec::new();
        let mut ask = Script(vec!["".into()], true);
        assert_eq!(
            choose_access(&tty, &mut ask, &mut out, "aws").unwrap(),
            "session"
        );
        let text = String::from_utf8_lossy(&out).into_owned();
        for word in ["Session Manager", "Headscale", "Tailscale", "Cloudflare"] {
            assert!(text.contains(word), "{word} is not explained: {text}");
        }
        let mut out = Vec::new();
        let mut ask = Script(vec!["2".into()], true);
        assert_eq!(
            choose_access(&tty, &mut ask, &mut out, "hcloud").unwrap(),
            "headscale"
        );
        assert!(String::from_utf8_lossy(&out).contains("ozbox mesh setup"));
        let mut ask = Script(vec!["9".into()], true);
        assert!(choose_access(&tty, &mut ask, &mut Vec::new(), "aws").is_err());
    }

    #[test]
    fn the_sandbox_completes_without_touching_a_cloud() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let (res, out) = go(&args(), d.path(), &r, vec![], false);
        assert_eq!(res.unwrap()["completed"], true);
        assert!(out.contains("sandbox") || out.contains("Sandbox"));
        assert!(r.calls().is_empty());
        assert!(SetupFile::load(&d.path().join("setup.json")).completed);
    }

    #[test]
    fn dry_run_changes_nothing_and_a_script_without_yes_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let mut a = args();
        a.dry_run = true;
        let (res, _) = go(&a, d.path(), &r, vec![], false);
        assert_eq!(res.unwrap()["completed"], false);
        assert!(!d.path().join("config.toml").exists());
        let mut a = args();
        a.yes = false;
        let (res, _) = go(&a, d.path(), &r, vec![], false);
        assert!(res.unwrap_err().contains("--yes"));
        // A terminal that answers no stops too.
        let (res, _) = go(&a, d.path(), &r, vec!["n"], true);
        assert!(res.is_err());
        assert!(!d.path().join("config.toml").exists());
    }

    #[test]
    fn a_no_or_a_missing_terminal_skips_only_the_adopt_step_and_setup_goes_on() {
        // an unchanged plan needs no question
        let mut out = Vec::new();
        assert!(adopt_step_go(
            &args(),
            &mut Script(vec![], false),
            &mut out,
            true
        ));
        // --yes applies
        assert!(adopt_step_go(
            &args(),
            &mut Script(vec![], false),
            &mut out,
            false
        ));
        let mut a = args();
        a.yes = false;
        // a terminal that answers no: skipped with a message, and not an error that would end setup
        let mut out = Vec::new();
        assert!(!adopt_step_go(
            &a,
            &mut Script(vec!["n".into()], true),
            &mut out,
            false
        ));
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(
            text.contains("Skipped the adopt command's document"),
            "{text}"
        );
        assert!(text.contains("setup goes on"), "{text}");
        // no terminal and no --yes: the same skip, naming the reason
        let mut out = Vec::new();
        assert!(!adopt_step_go(
            &a,
            &mut Script(vec![], false),
            &mut out,
            false
        ));
        let text = String::from_utf8_lossy(&out).to_string();
        assert!(
            text.contains("Skipped the adopt command's document"),
            "{text}"
        );
        assert!(text.contains("--yes"), "{text}");
        // the call site never propagates the prompt's error, so the box-policy step after it still runs
        let src = include_str!("init_cli.rs");
        // built by concatenation, so this test's own text can never satisfy it
        let call = format!("{}{}", "adopt_step_go(a, ask, ", "out, ad.noop)");
        assert!(src.contains(&call));
        assert!(!src.contains(&format!("{}\"adopt command\")?", "confirm(a, ask, ")));
    }

    #[test]
    fn no_provider_and_no_terminal_is_a_clear_error() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let mut a = args();
        a.provider = None;
        let (res, _) = go(&a, d.path(), &r, vec![], false);
        assert!(res.is_err());
    }

    #[test]
    fn aws_runs_every_step_in_order_and_ends_with_a_saved_setup() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("modules/aws-box")).unwrap();
        std::fs::create_dir_all(d.path().join("modules/aws-network")).unwrap();
        std::fs::create_dir_all(d.path().join("modules/aws-secrets-key")).unwrap();
        std::fs::create_dir_all(d.path().join("modules/aws-adopt-command")).unwrap();
        std::fs::create_dir_all(d.path().join("modules/aws-box-policy")).unwrap();
        let r = RecordingRunner::new();
        let sso = r#"{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Op_1/me"}"#;
        r.reply(o(0, sso, "")); // sign in
        for _ in 0..6 {
            r.reply(o(254, "", "DryRunOperation"));
        }
        r.reply(o(254, "", "404 Not Found")); // head-bucket
        for _ in 0..5 {
            r.reply(o(0, "", "")); // bucket changes
        }
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        for _ in 0..3 {
            r.reply(o(0, "", ""));
        }
        r.reply(o(2, "  # aws_vpc.this will be created\n", ""));
        r.reply(o(0, "", "")); // apply
        r.reply(o(0, r#"{"private_subnet_id":{"value":"subnet-0abc"}}"#, ""));
        // the secrets key: the permission check cannot run (unknown), then its plan is empty (already there)
        r.reply(o(254, "", "AccessDenied")); // get-role
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        r.reply(o(0, r#"{"Aliases":[]}"#, "")); // no alias to adopt
        r.reply(o(0, "", "")); // plan: nothing to do
                               // an existing key is still read back and recorded, so a config that lacks it is repaired
        r.reply(o(
            0,
            r#"{"key_arn":{"value":"arn:aws:kms:us-east-1:123456789012:key/abc"},"fleet":{"value":"ozbox"}}"#,
            "",
        ));
        // the adopt command's document, a step of its own: unknown permission, an empty plan, and its policy read back
        r.reply(o(254, "", "AccessDenied")); // get-role
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        r.reply(o(254, "", "InvalidDocument")); // no document to adopt
        r.reply(o(0, "", "")); // plan: nothing to do
        r.reply(o(0, r#"{"Version":"2012-10-17","Statement":[]}"#, ""));
        // the box Session Manager policy: head-bucket, version, init, plan with nothing to do
        r.reply(o(0, "", ""));
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        for _ in 0..3 {
            r.reply(o(254, "", "NoSuchEntity")); // none of the three policies exists yet
        }
        r.reply(o(0, "", "")); // plan: nothing to do
        r.reply(o(0, sso, "")); // sign in again for the security check
        let mut a = args();
        a.provider = Some("aws".into());
        a.region = Some("us-east-1".into());
        a.budget = Some(100.0);
        a.alert_email = Some("me@example.com".into());
        a.alert_from = Some("oz@example.com".into());
        a.two_factor = true;
        // The email key is not in the store, so the guard rail asks for it.
        let (res, text) = go(&a, d.path(), &r, vec![], false);
        let err = res.unwrap_err();
        assert!(err.contains("budget") || err.contains("alert"), "{err}");
        // the key step never stopped setup, and said it could not check the permission
        assert!(
            text.contains(
                "could not check whether this identity may create the fleet's secrets key"
            ),
            "{text}"
        );
        // the adopt document is a step of its own, with its own permission message
        assert!(
            text.contains(
                "could not check whether this identity may make the adopt command's document"
            ),
            "{text}"
        );
        assert!(text.contains("operator-adopt-policy.json"), "{text}");
        // Everything up to the guard rail was done and recorded; nothing is marked complete.
        let c = crate::config::Config::load_from(&d.path().join("config.toml")).unwrap();
        assert_eq!(c.aws.unwrap().subnet_id.as_deref(), Some("subnet-0abc"));
        assert!(!SetupFile::load(&d.path().join("setup.json")).completed);
    }

    const SSO: &str = r#"{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Op_1/me"}"#;

    fn modules(d: &std::path::Path) {
        for m in [
            "aws-box",
            "aws-network",
            "aws-secrets-key",
            "aws-adopt-command",
            "aws-box-policy",
        ] {
            std::fs::create_dir_all(d.join("modules").join(m)).unwrap();
        }
    }

    /// Sign-in, the permission probes and a bucket that has to be made.
    fn script_to_bucket(r: &RecordingRunner) {
        r.reply(o(0, SSO, ""));
        for _ in 0..6 {
            r.reply(o(254, "", "DryRunOperation"));
        }
        r.reply(o(254, "", "404 Not Found")); // head-bucket
        for _ in 0..5 {
            r.reply(o(0, "", "")); // bucket changes
        }
    }

    /// The key, adopt and box-policy steps, each with nothing to change, then the security check's sign-in.
    fn script_after_network(r: &RecordingRunner) {
        // the secrets key: unknown permission, nothing to adopt, an empty plan, its outputs read back
        r.reply(o(254, "", "AccessDenied")); // get-role
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        r.reply(o(0, r#"{"Aliases":[]}"#, "")); // no alias to adopt
        r.reply(o(0, "", "")); // plan: nothing to do
        r.reply(o(
            0,
            r#"{"key_arn":{"value":"arn:aws:kms:us-east-1:123456789012:key/abc"},"fleet":{"value":"ozbox"}}"#,
            "",
        ));
        // the adopt command's document: unknown permission, nothing to adopt, an empty plan, its policy read back
        r.reply(o(254, "", "AccessDenied")); // get-role
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        r.reply(o(254, "", "InvalidDocument")); // no document to adopt
        r.reply(o(0, "", "")); // plan: nothing to do
        r.reply(o(0, r#"{"Version":"2012-10-17","Statement":[]}"#, ""));
        // the box Session Manager policy: head-bucket, version, init, nothing to adopt, an empty plan
        r.reply(o(0, "", "")); // box policy: head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        r.reply(o(0, "", "")); // init
        r.reply(o(0, "", "")); // state list: empty
        for _ in 0..3 {
            r.reply(o(254, "", "NoSuchEntity")); // none of the three policies exists yet
        }
        r.reply(o(0, "", "")); // plan: nothing to do
        r.reply(o(0, SSO, ""));
    }

    fn aws_args() -> Args {
        let mut a = args();
        a.provider = Some("aws".into());
        a.region = Some("us-east-1".into());
        a.budget = Some(100.0);
        a.alert_email = Some("me@example.com".into());
        a.alert_from = Some("oz@example.com".into());
        a.two_factor = true;
        a
    }

    fn ran(r: &RecordingRunner, needle: &str) -> bool {
        r.calls()
            .iter()
            .any(|c| c.args.iter().any(|x| x.contains(needle)))
    }

    #[test]
    fn a_configured_subnet_means_no_network_plan_and_the_box_policy_is_still_reached() {
        let d = tempfile::tempdir().unwrap();
        modules(d.path());
        std::fs::write(
            d.path().join("config.toml"),
            "provider = \"aws\"\n[aws]\nsubnet_id = \"subnet-0abc\"\n",
        )
        .unwrap();
        let r = RecordingRunner::new();
        script_to_bucket(&r);
        r.reply(o(0, r#"{"Subnets":[{"SubnetId":"subnet-0abc"}]}"#, "")); // describe-subnets
        script_after_network(&r);
        let mut a = aws_args();
        a.yes = false;
        // only the bucket is asked: a network question would take the next answer, and none is given
        let (res, text) = go(&a, d.path(), &r, vec!["y"], true);
        // setup ends only at the guard rail (no email key in the store), as in the full journey above
        let err = res.unwrap_err();
        assert!(err.contains("budget"), "{err}\n{text}");
        assert!(
            text.contains("Using the subnet your configuration already names"),
            "{text}"
        );
        assert!(
            !ran(&r, "ozbox/network/us-east-1.tfstate"),
            "no network was planned"
        );
        assert!(ran(&r, "describe-subnets"));
        assert!(!text.contains("Private network in"), "{text}");
        assert!(
            text.contains("box Session Manager policy"),
            "the box policy step ran: {text}"
        );
        assert!(text.contains("existing subnet subnet-0abc"), "{text}");
    }

    #[test]
    fn declining_the_network_skips_it_and_setup_goes_on_to_the_next_steps() {
        let d = tempfile::tempdir().unwrap();
        modules(d.path());
        let r = RecordingRunner::new();
        script_to_bucket(&r);
        r.reply(o(0, "", "")); // head-bucket
        r.reply(o(0, r#"{"terraform_version":"1.10.3"}"#, ""));
        for _ in 0..3 {
            r.reply(o(0, "", ""));
        }
        r.reply(o(2, "  # aws_vpc.this will be created\n", "")); // plan: a network to make
        script_after_network(&r);
        let mut a = aws_args();
        a.yes = false;
        let (res, text) = go(&a, d.path(), &r, vec!["y", "n"], true);
        let v =
            res.unwrap_or_else(|e| panic!("declining an optional step ended setup: {e}\n{text}"));
        assert!(
            text.contains("Skipped: private network (you answered no)"),
            "{text}"
        );
        assert!(text.contains("Already in place: "), "{text}");
        assert!(
            text.contains("box Session Manager policy"),
            "the later steps ran: {text}"
        );
        assert!(
            !r.calls()
                .iter()
                .any(|c| c.args.iter().any(|x| x == "apply")),
            "the network was not applied"
        );
        assert_eq!(v["completed"], false, "no subnet: not marked complete");
        assert!(text.contains("not marked complete"), "{text}");
        assert_eq!(v["summary"]["skipped"][0], "private network");
    }

    #[test]
    fn declining_the_required_state_bucket_stops_and_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        modules(d.path());
        let r = RecordingRunner::new();
        script_to_bucket(&r);
        let mut a = aws_args();
        a.yes = false;
        let (res, _) = go(&a, d.path(), &r, vec!["n"], true);
        let e = res.unwrap_err();
        assert!(e.contains("state bucket is required"), "{e}");
        for write in [
            "create-bucket",
            "put-bucket-versioning",
            "put-bucket-policy",
        ] {
            assert!(!ran(&r, write), "{write} ran");
        }
        assert!(!d.path().join("config.toml").exists());
    }
}
