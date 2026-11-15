//! The root half of the box-wide egress list (ADR 0034): reads the declaration, resolves the names, renders the ruleset
//! (see `box_egress`), checks it with `nft -c`, loads it in one step, and keeps what a person reads back. It runs as root
//! on the box, from `ozbox admin <box> -- host-guard egress ...` and from a timer every two minutes.
//!
//! Refusals that keep a box reachable: a ruleset that does not pass `nft -c` is never loaded; `enforce` is refused while a
//! name the management path needs has no address yet (the previous rules stay); and an outage of the name service shrinks
//! nothing, because an address stays allowed for a day after its name last gave it.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ozbox_core::{CommandRunner, CommandSpec};

use crate::box_egress::{
    merge_blocked, merge_resolution, render_report, render_ruleset, Declaration, Fragment, Mode,
    State,
};

#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/ozbox`: the declaration and the fragments dropped in `egress.d/`.
    pub etc: PathBuf,
    /// `/var/lib/ozbox-egress`: what is shown back.
    pub var: PathBuf,
    /// `/etc/systemd/system`.
    pub units: PathBuf,
    /// Where the system's real name servers are listed.
    pub resolv: Vec<PathBuf>,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            etc: "/etc/ozbox".into(),
            var: "/var/lib/ozbox-egress".into(),
            units: "/etc/systemd/system".into(),
            resolv: vec![
                "/run/systemd/resolve/resolv.conf".into(),
                "/etc/resolv.conf".into(),
            ],
        }
    }
}

impl Paths {
    /// The secrets service's settings (`/etc/ozbox/secrets.env`), where a box on the fleet's KMS key names it.
    fn secrets_settings(&self) -> PathBuf {
        self.etc.join("secrets.env")
    }
    fn declaration(&self) -> PathBuf {
        self.etc.join("box-egress.json")
    }
    fn state(&self) -> PathBuf {
        self.var.join("state.json")
    }
}

pub struct Guard<'a> {
    pub runner: &'a dyn CommandRunner,
    pub paths: Paths,
    pub now: u64,
    pub resolve: &'a dyn Fn(&str) -> Option<Vec<IpAddr>>,
}

/// The system resolver, asked for one name: every address it gives, or `None` when it gives none.
pub fn system_resolve(host: &str) -> Option<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    let v: Vec<IpAddr> = (host, 0).to_socket_addrs().ok()?.map(|a| a.ip()).collect();
    (!v.is_empty()).then_some(v)
}

fn write_atomic(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    let io = |e: std::io::Error| format!("could not write {}: {e}", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    }
    let _ = mode;
    std::fs::rename(&tmp, path).map_err(io)
}

/// Name servers from a `resolv.conf`, without the local stub (its own queries are what the filter must see).
pub fn parse_resolvers(text: &str) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|r| r.trim().parse::<IpAddr>().ok())
        .filter(|ip| !ip.is_loopback())
        .collect();
    v.sort();
    v.dedup();
    v
}

const SERVICE: &str = "[Unit]\nDescription=Oz Box egress list: resolve names and load the packet filter\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/ozbox host-guard egress refresh\n\n[Install]\nWantedBy=multi-user.target\n";
const TIMER: &str = "[Unit]\nDescription=Oz Box egress list: keep the allowed addresses fresh\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=2min\nAccuracySec=15s\n\n[Install]\nWantedBy=timers.target\n";

/// The ruleset, the merged names and the names with no address.
type Rendered = (
    String,
    BTreeMap<String, crate::box_egress::HostState>,
    Vec<String>,
);

impl Guard<'_> {
    /// The declaration on disk. No file is `off` (nothing was ever declared); a file that cannot be read, does not parse or
    /// does not validate is an error, never `off`: an upgrade that tightens the checks, or a damaged file, must not open a
    /// box that was enforcing.
    pub fn declaration(&self) -> Result<Declaration, String> {
        let text = match std::fs::read_to_string(self.paths.declaration()) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Declaration::off()),
            Err(_) => return Err("the declaration could not be read".into()),
        };
        let d: Declaration = serde_json::from_str(&text)
            .map_err(|_| "the declaration on the box is not a declaration".to_string())?;
        d.validate()
            .map_err(|e| format!("the declaration on the box is not valid ({e})"))?;
        Ok(d)
    }

    /// The declaration a change is compared with: the one on disk, or, when that is unusable, the last one applied.
    pub fn in_force(&self) -> Declaration {
        self.declaration()
            .ok()
            .or_else(|| self.state().declaration)
            .unwrap_or_else(Declaration::off)
    }

    /// The declaration is unusable: keep (and, after a restart, load again) the ruleset of the last good refresh, record
    /// why in the state a person reads, and fail, so the timer's unit shows as failed.
    fn keep_last_good(&self, why: String) -> Result<String, String> {
        let mut st = self.state();
        st.error = Some(why.clone());
        let file = self.paths.var.join("ruleset.nft");
        let kept = if file.is_file() && st.mode != Some(Mode::Off) {
            let f = file.display().to_string();
            self.nft(&["-c", "-f", &f], None)
                .and_then(|()| self.nft(&["-f", &f], None))
                .is_ok()
        } else {
            false
        };
        write_atomic(
            &self.paths.state(),
            &serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
            0o644,
        )?;
        Err(if kept {
            format!("{why}; the rules from the last good refresh stay loaded")
        } else {
            format!("{why}; there were no earlier rules to keep, and nothing was changed")
        })
    }

    fn fragments(&self) -> Vec<Fragment> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(self.paths.etc.join("egress.d")) else {
            return out;
        };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        for f in files {
            if let Some(frag) = std::fs::read_to_string(f)
                .ok()
                .and_then(|t| Fragment::parse(&t).ok())
            {
                out.push(frag);
            }
        }
        out
    }

    fn state(&self) -> State {
        std::fs::read_to_string(self.paths.state())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn nft(&self, args: &[&str], stdin: Option<&str>) -> Result<(), String> {
        let mut c = CommandSpec::new("nft").args(args.iter().copied());
        if let Some(s) = stdin {
            c = c.stdin(s.as_bytes().to_vec());
        }
        let out = self
            .runner
            .run(&c)
            .map_err(|_| "the nft command could not be started".to_string())?;
        if out.status == Some(0) {
            Ok(())
        } else {
            let why: String = out
                .stderr
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .take(160)
                .collect();
            Err(format!("nft refused the ruleset: {why}"))
        }
    }

    fn systemctl(&self, args: &[&str]) {
        let _ = self
            .runner
            .run(&CommandSpec::new("systemctl").args(args.iter().copied()));
    }

    /// Record a new declaration, install the timer (or remove it for `off`), and make it take effect now.
    pub fn apply(&self, decl: &Declaration) -> Result<String, String> {
        decl.validate()?;
        let json = serde_json::to_string_pretty(decl).map_err(|e| e.to_string())?;
        // Refuse before anything is written when enforcing could not work.
        if decl.mode == Mode::Enforce {
            self.render(decl, true)?;
        }
        write_atomic(&self.paths.declaration(), &json, 0o644)?;
        if decl.mode == Mode::Off {
            self.systemctl(&["disable", "--now", "ozbox-egress.timer"]);
        } else {
            write_atomic(
                &self.paths.units.join("ozbox-egress.service"),
                SERVICE,
                0o644,
            )?;
            write_atomic(&self.paths.units.join("ozbox-egress.timer"), TIMER, 0o644)?;
            self.systemctl(&["daemon-reload"]);
            self.systemctl(&["enable", "--now", "ozbox-egress.timer"]);
        }
        let mut st = self.state();
        if st.mode != Some(decl.mode) || st.declaration.as_ref() != Some(decl) {
            st.since = if decl.mode == Mode::Off { 0 } else { self.now };
            if st.mode != Some(decl.mode) {
                st.blocked.clear();
            }
        }
        write_atomic(
            &self.paths.state(),
            &serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
            0o644,
        )?;
        self.refresh()
    }

    /// What the box may ALWAYS reach, whatever a declaration says: the key service its secrets store is wrapped by (`kms.<region>`
    /// from the key the secrets settings name). A request that tightens the list, leaves out the region, names another one or
    /// drops the preset cannot cut the store off from its key, which would strand a moved store and starve the grant probes the
    /// laptop's confirmations rest on. Read from the root-owned settings, never from the request.
    fn always(&self) -> Vec<crate::box_egress::Dest> {
        crate::box_egress::kms_always(
            crate::secrets_file::env_file(&self.paths.secrets_settings())
                .get("OZBOX_KMS_KEY_ID")
                .map(String::as_str),
        )
    }

    /// Resolve, render and check: the ruleset text and the merged names, or why not.
    fn render(&self, decl: &Declaration, strict: bool) -> Result<Rendered, String> {
        let mut dests = decl.destinations(&self.fragments());
        let always = self.always();
        for d in &always {
            if !dests.contains(d) {
                dests.push(d.clone());
            }
        }
        dests.sort();
        let mut fresh: BTreeMap<String, Option<Vec<IpAddr>>> = BTreeMap::new();
        for d in &dests {
            if d.host.parse::<IpAddr>().is_err() && !fresh.contains_key(&d.host) {
                fresh.insert(d.host.clone(), (self.resolve)(&d.host));
            }
        }
        let (known, empty) = merge_resolution(&self.state().hosts, &fresh, self.now);
        if strict && decl.mode == Mode::Enforce {
            let control = Declaration {
                mode: Mode::Log,
                region: decl.region.clone(),
                presets: vec!["aws-control".into()],
                hosts: vec![],
            };
            let mut core: Vec<String> = if decl.region.is_empty() {
                vec![]
            } else {
                control
                    .destinations(&[])
                    .into_iter()
                    .map(|d| d.host)
                    .collect()
            };
            core.extend(always.iter().map(|d| d.host.clone()));
            if let Some(h) = empty.iter().find(|h| core.contains(h)) {
                return Err(format!(
                    "will not enforce: {h}, which the box's management path needs, has no address yet, and enforcing now could cut the box off. The previous rules stay."
                ));
            }
        }
        let mut resolvers = Vec::new();
        for p in &self.paths.resolv {
            if let Ok(t) = std::fs::read_to_string(p) {
                resolvers = parse_resolvers(&t);
                if !resolvers.is_empty() {
                    break;
                }
            }
        }
        Ok((
            render_ruleset(decl.mode, &dests, &known, &resolvers),
            known,
            empty,
        ))
    }

    /// Bring the loaded rules in line with the declaration and the names' current addresses; tally what was blocked.
    pub fn refresh(&self) -> Result<String, String> {
        let decl = match self.declaration() {
            Ok(d) => d,
            Err(why) => return self.keep_last_good(why),
        };
        let mut st = self.state();
        st.error = None;
        if decl.mode == Mode::Off {
            // `add` first so the `delete` cannot fail on a box that never had the table
            let _ = self.nft(
                &["-f", "-"],
                Some("add table inet ozbox_egress\ndelete table inet ozbox_egress\n"),
            );
            // nothing to fall back to once the list is off
            let _ = std::fs::remove_file(self.paths.var.join("ruleset.nft"));
            st.mode = Some(Mode::Off);
            st.refreshed_at = self.now;
            write_atomic(
                &self.paths.state(),
                &serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
                0o644,
            )?;
            return Ok("The egress list is off; no rules are loaded.".into());
        }
        let (rules, known, empty) = self.render(
            &decl,
            decl.mode == Mode::Enforce && st.mode != Some(Mode::Enforce),
        )?;
        let file = self.paths.var.join("ruleset.nft");
        write_atomic(&file, &rules, 0o600)?;
        let f = file.display().to_string();
        self.nft(&["-c", "-f", &f], None)?;
        self.nft(&["-f", &f], None)?;
        // what the kernel noted since the last look
        let since = if st.journal_cursor == 0 {
            st.since
        } else {
            st.journal_cursor
        };
        let out = self.runner.run(&CommandSpec::new("journalctl").args([
            "-k",
            "--no-pager",
            "-o",
            "short-unix",
            "-g",
            "ozbox-egress-",
            &format!("--since=@{since}"),
        ]));
        if let Ok(o) = out {
            if o.status == Some(0) {
                merge_blocked(&mut st.blocked, &o.stdout, self.now, 200);
            }
        }
        st.journal_cursor = self.now;
        st.mode = Some(decl.mode);
        st.refreshed_at = self.now;
        st.hosts = known;
        st.unresolved = empty;
        st.declaration = Some(decl.clone());
        if st.since == 0 {
            st.since = self.now;
        }
        write_atomic(
            &self.paths.state(),
            &serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
            0o644,
        )?;
        Ok(format!(
            "The egress list is {}: {} names, {} without an address yet.",
            decl.mode.as_str(),
            st.hosts.len(),
            st.unresolved.len()
        ))
    }

    /// What a person reads. Any user may ask: it reads only the file the refresh wrote.
    pub fn report(&self) -> String {
        render_report(&self.state(), self.now)
    }

    pub fn state_json(&self) -> String {
        serde_json::to_string_pretty(&self.state()).unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn paths(d: &Path) -> Paths {
        Paths {
            etc: d.join("etc"),
            var: d.join("var"),
            units: d.join("units"),
            resolv: vec![d.join("resolv.conf")],
        }
    }

    fn res(h: &str) -> Option<Vec<IpAddr>> {
        match h {
            "nores.example.com" => None,
            _ => Some(vec!["203.0.113.5".parse().unwrap()]),
        }
    }

    fn decl(words: &str) -> Declaration {
        Declaration::from_words(
            &words
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn name_servers_are_read_without_the_local_stub() {
        let r = parse_resolvers("# x\nnameserver 127.0.0.53\nnameserver 10.0.0.2\nnameserver 10.0.0.2\nnameserver 2001:db8::1\nsearch x\n");
        assert_eq!(
            r,
            [
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn log_mode_is_checked_then_loaded_with_a_timer_and_a_state_a_person_can_read() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("resolv.conf"), "nameserver 10.0.0.2\n").unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 5_000,
            resolve: &res,
        };
        let msg = g.apply(&decl("log --preset github")).unwrap();
        assert!(msg.contains("log"), "{msg}");
        let calls = r.calls();
        let nft: Vec<&CommandSpec> = calls.iter().filter(|c| c.program == "nft").collect();
        // checked first, loaded second, both the same file
        assert_eq!(nft[0].args[0], "-c");
        assert_eq!(nft[1].args[0], "-f");
        assert!(calls.iter().any(|c| c.program == "systemctl"
            && c.args.contains(&"ozbox-egress.timer".to_string())
            && c.args.contains(&"enable".to_string())));
        assert!(d.path().join("units/ozbox-egress.timer").is_file());
        let rules = std::fs::read_to_string(d.path().join("var/ruleset.nft")).unwrap();
        assert!(
            rules.contains("203.0.113.5 . tcp . 443") && rules.contains("ip daddr { 10.0.0.2 }")
        );
        assert!(g.report().contains("Egress list: log"));
        // the declaration is what is persisted, and nothing in the state is a secret
        assert!(
            std::fs::read_to_string(d.path().join("etc/box-egress.json"))
                .unwrap()
                .contains("github")
        );
    }

    #[test]
    fn a_ruleset_nft_refuses_is_never_loaded() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        // apply: systemctl daemon-reload, systemctl enable, then the nft check, which fails
        r.reply(Output::default());
        r.reply(Output::default());
        r.reply(Output {
            status: Some(1),
            stderr: "Error: syntax\nmore".into(),
            ..Output::default()
        });
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 1,
            resolve: &res,
        };
        let e = g.apply(&decl("log --preset github")).unwrap_err();
        assert!(e.contains("nft refused the ruleset: Error: syntax"), "{e}");
        let nft: Vec<Vec<String>> = r
            .calls()
            .into_iter()
            .filter(|c| c.program == "nft")
            .map(|c| c.args)
            .collect();
        assert_eq!(nft.len(), 1, "only the check ran");
        assert_eq!(nft[0][0], "-c");
    }

    #[test]
    fn enforce_is_refused_while_the_management_path_has_no_address_and_nothing_is_written() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        fn none(_: &str) -> Option<Vec<IpAddr>> {
            None
        }
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 1,
            resolve: &none,
        };
        let e = g
            .apply(&decl("enforce --region us-east-1 --preset github"))
            .unwrap_err();
        assert!(
            e.contains("will not enforce") && e.contains("amazonaws.com"),
            "{e}"
        );
        assert!(!d.path().join("etc/box-egress.json").exists());
        assert!(r.calls().is_empty(), "no command ran");
        // with addresses, the same declaration is accepted
        let g2 = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 1,
            resolve: &res,
        };
        assert!(g2
            .apply(&decl("enforce --region us-east-1 --preset github"))
            .is_ok());
    }

    #[test]
    fn off_removes_the_rules_and_the_timer_and_is_the_default_without_a_declaration() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 9,
            resolve: &res,
        };
        g.apply(&decl("log --preset github")).unwrap();
        g.apply(&decl("off")).unwrap();
        let calls = r.calls();
        assert!(calls
            .iter()
            .any(|c| c.program == "systemctl" && c.args.contains(&"disable".to_string())));
        let del = calls.iter().rev().find(|c| c.program == "nft").unwrap();
        assert!(String::from_utf8_lossy(del.stdin.as_ref().unwrap())
            .contains("delete table inet ozbox_egress"));
        // no file at all means off
        let d2 = tempfile::tempdir().unwrap();
        let g2 = Guard {
            runner: &r,
            paths: paths(d2.path()),
            now: 9,
            resolve: &res,
        };
        assert!(g2.report().contains("not set up"));
        assert!(g2.refresh().unwrap().contains("off"));
    }

    /// After a good `log` apply, the declaration on disk becomes `text`; the next refresh must keep the last good rules.
    fn refresh_with_a_broken_declaration(text: &str) {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 50,
            resolve: &res,
        };
        g.apply(&decl("enforce --preset github")).unwrap();
        let before = r.calls().len();
        std::fs::write(d.path().join("etc/box-egress.json"), text).unwrap();
        let e = g.refresh().unwrap_err();
        assert!(
            e.contains("not") && e.contains("last good refresh stay loaded"),
            "{e}"
        );
        let after: Vec<CommandSpec> = r.calls().into_iter().skip(before).collect();
        // the last good ruleset is checked and loaded again; the table is never deleted
        assert!(after.iter().all(|c| c.program == "nft"), "{after:?}");
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].args[0], "-c");
        assert!(after[1].args.last().unwrap().ends_with("ruleset.nft"));
        assert!(!after.iter().any(|c| c
            .stdin
            .as_ref()
            .is_some_and(|i| String::from_utf8_lossy(i).contains("delete table"))));
        // the state still says enforce, and says what is wrong
        let st: State = serde_json::from_str(&g.state_json()).unwrap();
        assert_eq!(st.mode, Some(Mode::Enforce));
        assert!(st.error.is_some());
        assert!(g.report().starts_with("PROBLEM: "), "{}", g.report());
        // what a change is compared with is still the enforced declaration
        assert_eq!(g.in_force().mode, Mode::Enforce);
        // a good declaration clears the problem
        g.apply(&decl("enforce --preset github")).unwrap();
        let st: State = serde_json::from_str(&g.state_json()).unwrap();
        assert!(st.error.is_none());
    }

    #[test]
    fn a_declaration_that_does_not_parse_keeps_the_last_good_rules_and_says_so() {
        refresh_with_a_broken_declaration("{ not json");
    }

    #[test]
    fn a_declaration_that_parses_but_does_not_validate_keeps_the_last_good_rules() {
        refresh_with_a_broken_declaration(r#"{"mode":"off","presets":["no-such-preset"]}"#);
    }

    #[test]
    fn a_broken_declaration_with_nothing_earlier_changes_nothing_and_fails() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 50,
            resolve: &res,
        };
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/box-egress.json"), "[]").unwrap();
        let e = g.refresh().unwrap_err();
        assert!(e.contains("no earlier rules"), "{e}");
        assert!(r.calls().is_empty(), "no nft command ran");
        // after `off`, the old ruleset is gone, so a later broken file loads nothing either
        g.apply(&decl("log --preset github")).unwrap();
        g.apply(&decl("off")).unwrap();
        assert!(!d.path().join("var/ruleset.nft").exists());
        std::fs::write(d.path().join("etc/box-egress.json"), "[]").unwrap();
        let n = r.calls().len();
        assert!(g.refresh().is_err());
        assert_eq!(r.calls().len(), n);
    }

    #[test]
    fn what_the_kernel_logged_is_tallied_into_the_report() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 100,
            resolve: &res,
        };
        g.apply(&decl("log --preset github")).unwrap();
        // next refresh: nft -c, nft -f, then journalctl answers
        r.reply(Output {
            status: Some(0),
            ..Output::default()
        });
        r.reply(Output {
            status: Some(0),
            ..Output::default()
        });
        r.reply(Output { status: Some(0), stdout: "150.0 b kernel: ozbox-egress-would-block: OUT=e DST=198.51.100.9 PROTO=TCP SPT=1 DPT=443\n".into(), ..Output::default() });
        let g2 = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 200,
            resolve: &res,
        };
        g2.refresh().unwrap();
        let rep = g2.report();
        assert!(rep.contains("198.51.100.9:443/tcp  x1"), "{rep}");
        let j = r
            .calls()
            .into_iter()
            .find(|c| c.program == "journalctl")
            .unwrap();
        assert!(j.args.iter().any(|a| a.starts_with("--since=@")));
    }
}
