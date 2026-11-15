//! `ozbox box-egress <box>` and `ozbox box-patch <box>`: the owner's side of the box's own guards (ADR 0034, 0035).
//! Both only build the request and hand it to the same root path as `ozbox admin` (`host-guard ...`), so a change is shown
//! first, confirmed, run by the box's root helper and recorded there. Neither can run anything else on the box.

use ozbox_core::{BoxName, Provider};

use super::admin::{self, HostGuard};
use super::{CliError, Flags, Result};
use crate::box_egress::{preset_catalogue, Declaration, Mode};
use crate::messages::t;
use crate::patch_guard::Rule;
use crate::serve::agent::BoxAgent;

pub struct EgressArgs {
    pub mode: Option<String>,
    pub presets: Vec<String>,
    pub hosts: Vec<String>,
    pub list_presets: bool,
    pub skip_log_first: bool,
    /// A fresh approval code for a change that turns the list off or widens it.
    pub approval: Option<String>,
}

fn with_approval(words: &mut Vec<String>, approval: Option<String>) {
    if let Some(a) = approval {
        words.extend(["--approval".to_string(), a]);
    }
}

/// `Declaration` for these flags on a box in `region` (empty off AWS).
pub fn declaration(a: &EgressArgs, region: &str) -> std::result::Result<Declaration, String> {
    let mut words = vec![a.mode.clone().unwrap_or_default()];
    if !region.is_empty() {
        words.extend(["--region".to_string(), region.to_string()]);
    }
    for p in &a.presets {
        words.extend(["--preset".to_string(), p.clone()]);
    }
    for h in &a.hosts {
        words.extend(["--host".to_string(), h.clone()]);
    }
    Declaration::from_words(&words)
}

/// Whether enforcing now respects "log first": the box must already be in log (or enforce) mode.
pub fn log_first_ok(current_mode_line: &str) -> bool {
    current_mode_line.contains("mode=log") || current_mode_line.contains("mode=enforce")
}

pub(super) fn egress(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    repo: &str,
    name: BoxName,
    a: EgressArgs,
    f: &Flags,
) -> Result<()> {
    if a.list_presets {
        for (n, d) in preset_catalogue() {
            println!("{n:<18} {d}");
        }
        return Ok(());
    }
    if a.mode.is_none() {
        // no change asked: show what the list has seen
        return admin::command(
            p,
            agent,
            repo,
            name,
            vec!["host-guard".into(), "egress".into(), "report".into()],
            f,
        );
    };
    let rec = p
        .get(&name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    let region = if rec.provider == "aws" {
        rec.spec.region.clone().unwrap_or_default()
    } else {
        String::new()
    };
    if rec.provider == "aws" && region.is_empty() {
        return Err(CliError::Msg(t("guard.no_aws_region", &[])));
    }
    let decl = declaration(&a, &region).map_err(CliError::Msg)?;
    if decl.mode == Mode::Enforce && !a.skip_log_first {
        let (ok, out) = agent
            .admin(&rec, "host-guard egress mode")
            .map_err(|e| CliError::Msg(e.to_string()))?;
        if !ok || !log_first_ok(&out) {
            return Err(CliError::Msg(t(
                "guard.log_first",
                &[("box", name.as_str())],
            )));
        }
    }
    let mut words = vec!["host-guard".to_string()];
    words.extend(HostGuard::EgressSet(decl).words());
    with_approval(&mut words, a.approval);
    admin::command(p, agent, repo, name, words, f)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn patch(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    repo: &str,
    name: BoxName,
    rule: Option<String>,
    from: Option<u32>,
    to: Option<u32>,
    idle: Option<u32>,
    approval: Option<String>,
    f: &Flags,
) -> Result<()> {
    let Some(rule) = rule else {
        return admin::command(
            p,
            agent,
            repo,
            name,
            vec!["host-guard".into(), "patch".into(), "status".into()],
            f,
        );
    };
    let mut words = vec![rule];
    for (flag, v) in [("--from", from), ("--to", to), ("--idle", idle)] {
        if let Some(v) = v {
            words.extend([flag.to_string(), v.to_string()]);
        }
    }
    let r = Rule::from_words(&words).map_err(CliError::Msg)?;
    let mut w = vec!["host-guard".to_string()];
    w.extend(HostGuard::PatchSet(r).words());
    with_approval(&mut w, approval);
    admin::command(p, agent, repo, name, w, f)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_make_a_checked_declaration_with_the_boxs_region() {
        let a = EgressArgs {
            mode: Some("log".into()),
            presets: vec!["github".into(), "bedrock".into()],
            hosts: vec!["api.example.com".into()],
            list_presets: false,
            skip_log_first: false,
            approval: None,
        };
        let d = declaration(&a, "eu-west-1").unwrap();
        assert_eq!(d.region, "eu-west-1");
        assert!(declaration(&a, "").is_err(), "bedrock needs a region");
        let bad = EgressArgs {
            mode: Some("log".into()),
            presets: vec![],
            hosts: vec!["*.x.com".into()],
            list_presets: false,
            skip_log_first: false,
            approval: None,
        };
        assert!(declaration(&bad, "").is_err());
    }

    #[test]
    fn enforcing_waits_for_the_box_to_have_been_in_log_mode() {
        assert!(log_first_ok("mode=log since=5"));
        assert!(log_first_ok("mode=enforce since=5"));
        assert!(!log_first_ok("mode=off since=0"));
    }

    #[test]
    fn the_request_a_declaration_makes_is_one_short_line_of_plain_words_the_box_parses_back() {
        let a = EgressArgs {
            mode: Some("enforce".into()),
            presets: vec!["github".into(), "anthropic".into(), "npm".into()],
            hosts: vec!["api.example.com".into()],
            list_presets: false,
            skip_log_first: false,
            approval: None,
        };
        let d = declaration(&a, "us-east-1").unwrap();
        let g = HostGuard::EgressSet(d.clone());
        let line = format!("host-guard {}", g.words().join(" "));
        assert!(line.len() <= 480, "{}", line.len());
        assert!(
            line.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)),
            "{line}"
        );
        let words: Vec<String> = line
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        assert_eq!(HostGuard::parse(&words).unwrap(), g);
    }

    #[test]
    fn an_approval_rides_on_the_request_and_the_box_binds_it_to_the_same_digest() {
        let a = EgressArgs {
            mode: Some("enforce".into()),
            presets: vec!["github".into(), "anthropic".into(), "npm".into()],
            hosts: vec!["api.example.com".into()],
            list_presets: false,
            skip_log_first: false,
            approval: Some("ABCD-EFGH-JKLM-NPQR".into()),
        };
        let d = declaration(&a, "us-east-1").unwrap();
        let mut words = vec!["host-guard".to_string()];
        words.extend(HostGuard::EgressSet(d.clone()).words());
        with_approval(&mut words, a.approval.clone());
        let act = admin::AdminAction::parse(&words).unwrap();
        let line = act.request_line();
        assert!(
            line.len() <= 480 && line.ends_with("--approval ABCD-EFGH-JKLM-NPQR"),
            "{line}"
        );
        // what the box parses back from that line: the same change and the same digest the plan showed
        let back: Vec<String> = line
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        let (rest, code) = crate::host_guard_cli::take_approval(&back).unwrap();
        assert_eq!(code.as_deref(), Some("ABCD-EFGH-JKLM-NPQR"));
        let g = HostGuard::parse(&rest).unwrap();
        assert_eq!(g, HostGuard::EgressSet(d));
        let mut box_words = vec!["egress".to_string(), "set".into()];
        if let HostGuard::EgressSet(d) = &g {
            box_words.extend(d.to_words());
        }
        assert_eq!(
            g.approval_binding().unwrap().1,
            crate::host_guard_cli::change_digest(&box_words)
        );
        // the plan names the digest when no approval is given
        let plain = admin::AdminAction::parse(&words[..words.len() - 2]).unwrap();
        assert!(plain.describe("dev").contains("--project egress --env "));
        // a read takes no approval
        assert!(admin::AdminAction::parse(&[
            "host-guard".into(),
            "egress".into(),
            "report".into(),
            "--approval".into(),
            "X".into()
        ])
        .is_err());
    }
}
