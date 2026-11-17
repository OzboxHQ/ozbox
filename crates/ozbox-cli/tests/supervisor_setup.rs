//! The supervisor's move to a user of its own, run for real in a temporary folder with the system tools replaced by
//! recorders. It checks what a live box needs: the old dashboard's settings are carried over and the old unit is kept for a
//! rollback, a second run changes nothing, an old unit with arguments the step does not know stops it, and `--finish`
//! destroys the old copies only once the new dashboard is running.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Rig {
    dir: tempfile::TempDir,
}

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/cloud-init/scripts/ozbox-supervisor-setup.sh")
}

fn tool(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

const OLD_UNIT: &str = "[Service]\nExecStart=/work/home/ozbox/ozbox-dashboard/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com --tunnel cloudflare\n";

impl Rig {
    fn new(old_unit: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        for d in [
            "bin",
            "etc",
            "work/home/ozbox/ozbox-dashboard/state",
            "work/home/ozbox/.config/systemd/user",
            "work/home/ozbox/.ssh",
            "units",
        ] {
            std::fs::create_dir_all(r.join(d)).unwrap();
        }
        let h = r.join("work/home/ozbox/ozbox-dashboard");
        std::fs::write(h.join("config.toml"), "x = 1\n").unwrap();
        std::fs::write(h.join("auth.toml"), "y = 2\n").unwrap();
        std::fs::write(h.join("state/sessions.json"), "{}").unwrap();
        std::fs::write(
            r.join("work/home/ozbox/.ssh/id_ed25519"),
            "PRIVATE-KEY-SENTINEL",
        )
        .unwrap();
        // the box user wrote this; run as the supervisor it would run the box user's command
        std::fs::write(
            r.join("work/home/ozbox/.ssh/config"),
            "Host *\n  ProxyCommand sh -c 'echo OWNED >/tmp/owned'\n  LocalCommand id\n",
        )
        .unwrap();
        if let Some(u) = old_unit {
            std::fs::write(
                r.join("work/home/ozbox/.config/systemd/user/ozbox-dashboard.service"),
                u,
            )
            .unwrap();
        }
        let b = r.join("bin");
        let log = r.join("calls.log");
        let l = log.display();
        tool(&b, "id", &format!("case \"$*\" in '-u ozbox') echo 1500;; '-nG ozbox-supervisor') if [ -e '{0}/ingroup' ]; then echo 'ozbox-supervisor ozbox'; else echo ozbox-supervisor; fi;; ozbox-supervisor) [ -e '{0}/user' ];; *) exit 1;; esac", r.display()));
        tool(
            &b,
            "gpasswd",
            &format!(
                "echo gpasswd \"$@\" >>'{l}'; rm -f '{0}/ingroup'",
                r.display()
            ),
        );
        tool(
            &b,
            "useradd",
            &format!("echo useradd \"$@\" >>'{l}'; touch '{0}/user'", r.display()),
        );
        tool(&b, "usermod", &format!("echo usermod \"$@\" >>'{l}'"));
        tool(&b, "chown", &format!("echo chown \"$@\" >>'{l}'"));
        tool(&b, "passwd", "exit 0");
        tool(
            &b,
            "shred",
            &format!("echo shred \"$@\" >>'{l}'; shift; rm -f \"$@\" 2>/dev/null; exit 0"),
        );
        tool(&b, "runuser", &format!("echo runuser \"$@\" >>'{l}'"));
        tool(
            &b,
            "systemd-run",
            &format!("echo systemd-run \"$@\" >>'{l}'"),
        );
        tool(&b, "install", &format!("echo install \"$@\" >>'{l}'"));
        tool(&b, "systemctl", &format!("echo systemctl \"$@\" >>'{l}'; case \"$1\" in restart) touch '{0}/active';; disable) [ \"$2\" = --now ] && rm -f '{0}/active';; is-active) [ -e '{0}/active' ];; esac; exit 0", r.display()));
        // the installed daemon: one that takes its socket from systemd carries the marker (G1 N4)
        std::fs::write(r.join("ozboxd"), "ELF....ozbox-listenfd-protocol-1....").unwrap();
        // the dashboard answers on its port (a test that wants it silent points the probe at `false`)
        tool(&b, "probe", "exit 0");
        tool(&b, "probe-silent", "exit 1");
        Self { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_env(args, &[])
    }

    fn run_env(&self, args: &[&str], extra: &[(&str, &std::path::Path)]) -> Output {
        let r = self.dir.path();
        let b = r.join("bin");
        Command::new("bash")
            .arg(script())
            .args(args)
            .env("OZBOX_ETC", r.join("etc"))
            .env("OZBOX_WORK", r.join("work"))
            .env("OZBOX_SYSTEMD_DIR", r.join("units"))
            .env("OZBOX_SYSTEMCTL", b.join("systemctl"))
            .env("OZBOX_USERADD", b.join("useradd"))
            .env("OZBOX_USERMOD", b.join("usermod"))
            .env("OZBOX_ID", b.join("id"))
            .env("OZBOX_CHOWN", b.join("chown"))
            .env("OZBOX_PASSWD", b.join("passwd"))
            .env("OZBOX_SHRED", b.join("shred"))
            .env("OZBOX_RUNUSER", b.join("runuser"))
            .env("OZBOX_SYSTEMD_RUN", b.join("systemd-run"))
            .env("OZBOX_RETRY_DELAYS", "0 0")
            .env("OZBOX_GPASSWD", b.join("gpasswd"))
            .env("OZBOX_DAEMON_BIN", r.join("ozboxd"))
            .env("OZBOX_DASHBOARD_SETTLE_S", "0")
            .env("OZBOX_DASHBOARD_PROBE", b.join("probe"))
            .env("OZBOX_DASHBOARD_PROBE_S", "0")
            .envs(extra.iter().map(|(k, v)| (*k, v.as_os_str())))
            .output()
            .unwrap()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
    }
    fn unit(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("units/ozbox-dashboard.service"))
            .unwrap_or_default()
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn the_dashboard_moves_to_its_own_user_with_its_settings_and_the_old_unit_is_kept_for_a_rollback() {
    let rig = Rig::new(Some(OLD_UNIT));
    let o = rig.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    let u = rig.unit();
    // a root-owned program, its own user, its own folder, the supervisor socket, nothing of the box user's
    for want in [
        "User=ozbox-supervisor",
        "ExecStart=/usr/local/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com --tunnel cloudflare",
        "OZBOX_SUPERVISOR_SOCKET=/run/ozbox-secrets/supervisor/supervisor.sock",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "LimitCORE=0",
    ] {
        assert!(u.contains(want), "{want}\n{u}");
    }
    assert!(!u.contains("/work/home/ozbox") && !u.contains("User=ozbox\n"));
    // H1: the dashboard is not a member of the box user's group, in the unit or in the user
    assert!(!u.contains("SupplementaryGroups"), "{u}");
    let w = rig.dir.path().join("work");
    // settings and state were copied into the supervisor's folder
    assert_eq!(
        std::fs::read_to_string(w.join("ozbox-supervisor/config.toml")).unwrap(),
        "x = 1\n"
    );
    assert!(w.join("ozbox-supervisor/state/sessions.json").exists());
    // nothing of the box user's `~/.ssh` is copied: its config can run a command as the supervisor
    assert!(
        !w.join("ozbox-supervisor/home/.ssh").exists(),
        "no ssh keys or config are copied"
    );
    // the old copies are still there until --finish, and the old unit is renamed, not deleted
    assert!(w.join("home/ozbox/ozbox-dashboard/config.toml").exists());
    assert!(w
        .join("home/ozbox/.config/systemd/user/ozbox-dashboard.service.migrated")
        .exists());
    assert!(!w
        .join("home/ozbox/.config/systemd/user/ozbox-dashboard.service")
        .exists());
    let l = rig.log();
    assert!(l.contains("useradd") && l.contains("--shell /usr/sbin/nologin"));
    // never made a member of the box user's group, never added to it
    assert!(
        !l.contains("--groups") && !l.contains("usermod") && !l.contains("-aG"),
        "{l}"
    );
    assert!(l.contains("runuser -u ozbox -- env XDG_RUNTIME_DIR=/run/user/1500 systemctl --user disable --now ozbox-dashboard.service"));
    assert!(l.contains("systemctl restart ozbox-dashboard.service"));
    // the old user unit was stopped before the new one started
    assert!(
        l.find("--user disable --now").unwrap()
            < l.find("systemctl restart ozbox-dashboard").unwrap()
    );
}

#[test]
fn a_second_run_changes_nothing_and_does_not_restart_anything_twice_over_the_files() {
    let rig = Rig::new(Some(OLD_UNIT));
    assert!(rig.run(&[]).status.success());
    let before = rig.unit();
    let useradds = rig.log().matches("useradd").count();
    // the box user edits the old copy afterwards: it is not read again
    std::fs::write(
        rig.dir
            .path()
            .join("work/home/ozbox/ozbox-dashboard/config.toml"),
        "x = 999\n",
    )
    .unwrap();
    let o = rig.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(rig.unit(), before);
    assert_eq!(rig.log().matches("useradd").count(), useradds);
    assert_eq!(
        std::fs::read_to_string(rig.dir.path().join("work/ozbox-supervisor/config.toml")).unwrap(),
        "x = 1\n"
    );
}

#[test]
fn an_old_unit_with_arguments_the_step_does_not_know_is_not_copied() {
    for bad in [
        "ExecStart=/x/ozbox serve --bind 0.0.0.0 --port 7878 --public-url https://a.example.com\n",
        "ExecStart=/x/ozbox serve --port 7878 --public-url https://a.example.com; rm -rf /\n",
        "ExecStart=/x/ozbox serve --bind 127.0.0.1 --port 80 --public-url https://a.example.com\n",
        "ExecStart=/x/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://a.example.com --tunnel evil\n",
        "ExecStart=/x/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://A_b.example.com\n",
        "ExecStart=/x/ozbox run --port 7878\n",
    ] {
        let rig = Rig::new(Some(&format!("[Service]\n{bad}")));
        let o = rig.run(&[]);
        assert!(!o.status.success(), "{bad}");
        assert!(rig.unit().is_empty(), "{bad}");
    }
}

#[test]
fn a_box_with_no_dashboard_gets_the_user_and_nothing_else() {
    let rig = Rig::new(None);
    let o = rig.run(&[]);
    assert!(
        o.status.success() && text(&o).contains("no dashboard is installed"),
        "{}",
        text(&o)
    );
    assert!(rig.unit().is_empty() && rig.log().contains("useradd"));
}

#[test]
fn finish_destroys_the_old_copies_only_after_the_new_dashboard_runs() {
    let rig = Rig::new(Some(OLD_UNIT));
    let w = rig.dir.path().join("work");
    // before anything was moved
    assert!(!rig.run(&["--finish"]).status.success());
    assert!(w.join("home/ozbox/ozbox-dashboard/config.toml").exists());
    assert!(rig.run(&[]).status.success());
    let o = rig.run(&["--finish"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!w.join("home/ozbox/ozbox-dashboard/config.toml").exists());
    assert!(!w.join("home/ozbox/ozbox-dashboard/state").exists());
    // the box user's own ssh keys are not ours to destroy, and the supervisor's copy stays
    assert!(w.join("home/ozbox/.ssh/id_ed25519").exists());
    assert!(w.join("ozbox-supervisor/config.toml").exists());
}

#[test]
fn a_dashboard_that_does_not_start_puts_the_old_one_back() {
    let rig = Rig::new(Some(OLD_UNIT));
    // a service manager that never reports the new unit active
    let b = rig.dir.path().join("bin");
    tool(
        &b,
        "systemctl",
        &format!(
            "echo systemctl \"$@\" >>'{}'; case \"$1\" in is-active) exit 1;; esac; exit 0",
            rig.dir.path().join("calls.log").display()
        ),
    );
    let o = Command::new("bash")
        .arg(script())
        .env("OZBOX_ETC", rig.dir.path().join("etc"))
        .env("OZBOX_WORK", rig.dir.path().join("work"))
        .env("OZBOX_SYSTEMD_DIR", rig.dir.path().join("units"))
        .env("OZBOX_SYSTEMCTL", b.join("systemctl"))
        .env("OZBOX_USERADD", b.join("useradd"))
        .env("OZBOX_USERMOD", b.join("usermod"))
        .env("OZBOX_ID", b.join("id"))
        .env("OZBOX_CHOWN", b.join("chown"))
        .env("OZBOX_PASSWD", b.join("passwd"))
        .env("OZBOX_RUNUSER", b.join("runuser"))
        .env("OZBOX_SYSTEMD_RUN", b.join("systemd-run"))
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(rig
        .dir
        .path()
        .join("work/home/ozbox/.config/systemd/user/ozbox-dashboard.service")
        .exists());
    assert!(rig
        .log()
        .contains("--user enable --now ozbox-dashboard.service"));
}

/// A box user's service manager that says its old dashboard is not running (a dashboard staged by `ozbox dashboard
/// install` never ran as the box user).
fn box_user_dashboard_not_running(rig: &Rig) {
    let log = rig.dir.path().join("calls.log");
    tool(
        &rig.dir.path().join("bin"),
        "runuser",
        &format!(
            "echo runuser \"$@\" >>'{}'; case \"$*\" in *is-active*) exit 3;; esac; exit 0",
            log.display()
        ),
    );
}

/// A security review (2026-11-11): the install left the dashboard running as the box user. Now the install only stages it
/// and the root helper starts it as its own user; when that start fails, nothing is started as the box user instead.
#[test]
fn a_staged_dashboard_that_does_not_start_is_never_started_as_the_box_user() {
    let rig = Rig::new(Some(OLD_UNIT));
    box_user_dashboard_not_running(&rig);
    let b = rig.dir.path().join("bin");
    tool(
        &b,
        "systemctl",
        &format!(
            "echo systemctl \"$@\" >>'{}'; case \"$1\" in is-active) exit 1;; esac; exit 0",
            rig.dir.path().join("calls.log").display()
        ),
    );
    let o = rig.run(&[]);
    assert!(!o.status.success());
    assert!(
        text(&o).contains("not started as the box user"),
        "{}",
        text(&o)
    );
    assert!(!rig.log().contains("--user enable --now"), "{}", rig.log());
}

#[test]
fn the_sign_in_settings_must_be_the_ones_the_persons_computer_sent() {
    // the sha256 of the rig's staged auth.toml, as the person's computer computes it from what it sent
    let have: String = ring::digest::digest(&ring::digest::SHA256, b"y = 2\n")
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // the box user rewrote the file after the person's computer wrote it: refused, nothing copied or started
    let rig = Rig::new(Some(OLD_UNIT));
    let o = rig.run(&["--expect-auth", &"0".repeat(64)]);
    assert!(!o.status.success());
    assert!(
        text(&o).contains("not the ones your computer sent"),
        "{}",
        text(&o)
    );
    assert!(rig.unit().is_empty());
    assert!(!rig
        .dir
        .path()
        .join("work/ozbox-supervisor/auth.toml")
        .exists());
    assert!(!rig.log().contains("restart ozbox-dashboard"));
    // the file the person's computer sent: moved and started
    if Command::new("sha256sum").arg("--version").output().is_ok() {
        let rig = Rig::new(Some(OLD_UNIT));
        let o = rig.run(&["--expect-auth", &have]);
        assert!(o.status.success(), "{}", text(&o));
        assert!(rig
            .dir
            .path()
            .join("work/ozbox-supervisor/auth.toml")
            .exists());
    }
    // a value that is not a sha256 is refused before anything
    let rig = Rig::new(Some(OLD_UNIT));
    assert!(!rig.run(&["--expect-auth", "x; id"]).status.success());
}

/// The old dashboard.env becomes the supervisor's EnvironmentFile and the box user can write it: only plain settings are
/// carried, never a library preload, a path, a socket or a store the unit sets itself.
#[test]
fn only_plain_settings_are_carried_into_the_supervisors_environment() {
    let rig = Rig::new(Some(OLD_UNIT));
    std::fs::write(
        rig.dir.path().join("work/home/ozbox/ozbox-dashboard/dashboard.env"),
        "LD_PRELOAD=/work/home/ozbox/evil.so\nOZBOX_SECRET_SOCKET=/tmp/fake.sock\nOZBOX_BIN=/tmp/x\nPATH=/tmp\nOZBOX_LOG_LEVEL=debug\nOZBOX_NOTE=a b\n",
    )
    .unwrap();
    let o = rig.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    let env = std::fs::read_to_string(rig.dir.path().join("work/ozbox-supervisor/dashboard.env"))
        .unwrap();
    assert_eq!(env, "OZBOX_LOG_LEVEL=debug\n");
}

/// The move of a dashboard that ran as the box user (an older install), end to end: the box user's unit is stopped and
/// set aside, the system unit runs, and `--finish` leaves nothing of the old one to start or read.
#[test]
fn an_existing_box_user_dashboard_moves_and_finish_leaves_nothing_of_it() {
    let rig = Rig::new(Some(OLD_UNIT));
    let w = rig.dir.path().join("work");
    let o = rig.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("runs as ozbox-supervisor"));
    let l = rig.log();
    assert!(l.contains("--user disable --now ozbox-dashboard.service"));
    assert!(l.contains("systemctl enable ozbox-dashboard.service"));
    assert!(
        rig.dir.path().join("active").exists(),
        "the system unit runs"
    );
    let o = rig.run(&["--finish"]);
    assert!(o.status.success(), "{}", text(&o));
    let units = w.join("home/ozbox/.config/systemd/user");
    assert!(!units.join("ozbox-dashboard.service").exists());
    assert!(!units.join("ozbox-dashboard.service.migrated").exists());
    for f in ["config.toml", "auth.toml", "state"] {
        assert!(
            !w.join("home/ozbox/ozbox-dashboard").join(f).exists(),
            "{f}"
        );
    }
    // a rollback after finish has nothing of the box user's to put back
    let o = rig.run(&["--rollback"]);
    assert!(
        o.status.success() && text(&o).contains("no old dashboard to put back"),
        "{}",
        text(&o)
    );
    assert!(!units.join("ozbox-dashboard.service").exists());
    assert!(
        rig.dir.path().join("active").exists(),
        "the supervisor's dashboard keeps running"
    );
}

/// H1: a box moved by an earlier version has the supervisor in the box user's group. The setup takes it out,
/// and restarts a running dashboard (it keeps the groups it started with).
#[test]
fn an_existing_supervisor_is_taken_out_of_the_box_users_group_and_the_dashboard_restarted() {
    let rig = Rig::new(Some(OLD_UNIT));
    assert!(rig.run(&[]).status.success());
    std::fs::write(rig.dir.path().join("ingroup"), "").unwrap();
    let before = rig.log().matches("restart ozbox-dashboard.service").count();
    let o = rig.run(&["--socket-only"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        rig.log().contains("gpasswd -d ozbox-supervisor ozbox"),
        "{}",
        rig.log()
    );
    assert!(
        rig.log().matches("restart ozbox-dashboard.service").count() > before,
        "{}",
        rig.log()
    );
    // not in it any more: a second run leaves it alone
    let n = rig.log().matches("gpasswd").count();
    assert!(rig.run(&["--socket-only"]).status.success());
    assert_eq!(rig.log().matches("gpasswd").count(), n);
}

/// C1: the dashboard's socket to the daemon is bound by systemd as root in a folder root owns and handed to the
/// daemon. Nothing root runs here names a path under /run/ozboxd (the box user owns it and could plant a link there).
#[test]
fn the_dashboards_socket_is_a_root_owned_socket_unit_and_no_root_step_touches_the_box_users_folder()
{
    let rig = Rig::new(None);
    stateful_systemctl(&rig);
    let o = rig.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    let units = rig.dir.path().join("units");
    let sock = std::fs::read_to_string(units.join("ozboxd-supervisor.socket")).unwrap();
    for want in [
        "ListenStream=/run/ozbox-supervisor-api/daemon.sock",
        "SocketUser=root",
        "SocketGroup=ozbox-supervisor",
        "SocketMode=0660",
        "DirectoryMode=0755",
        "Service=ozboxd.service",
    ] {
        assert!(sock.contains(want), "{want}\n{sock}");
    }
    let drop_in =
        std::fs::read_to_string(units.join("ozboxd.service.d/10-supervisor-socket.conf")).unwrap();
    assert!(
        drop_in.contains("Sockets=ozboxd-supervisor.socket"),
        "{drop_in}"
    );
    let l = rig.log();
    assert!(
        l.contains("systemctl enable ozboxd-supervisor.socket"),
        "{l}"
    );
    // enabled only (G1 F5): a stopped daemon stays stopped, and the daemon's `Wants=` brings the socket up with it
    assert!(
        !l.contains("start ozboxd-supervisor.socket") && !l.contains("start ozboxd.service"),
        "{l}"
    );
    // no `install`, `chown`, `chmod` or mkdir under /run/ozboxd: the log has no mention of it and neither has the script's code
    assert!(!l.contains("/run/ozboxd") && !l.contains("install "), "{l}");
    let code: String = std::fs::read_to_string(script())
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("/run/ozboxd") && !code.contains("run/ozboxd"),
        "a root step names the box user's folder"
    );
    assert!(!sock.contains("/run/ozboxd") && !drop_in.contains("/run/ozboxd"));
}

#[test]
fn a_running_daemon_is_restarted_once_when_the_socket_unit_is_new_and_not_again() {
    let rig = Rig::new(None);
    // the box has an active daemon (the rig's service manager reports every unit active once `restart` was seen)
    let b = rig.dir.path().join("bin");
    let log = rig.dir.path().join("calls.log");
    tool(
        &b,
        "systemctl",
        &format!("echo systemctl \"$@\" >>'{}'; exit 0", log.display()),
    );
    assert!(rig.run(&["--socket-only"]).status.success());
    assert!(
        rig.log().contains("systemctl stop ozboxd.service")
            && rig.log().contains("systemctl start ozboxd.service"),
        "{}",
        rig.log()
    );
    let n = rig.log().matches("stop ozboxd.service").count();
    assert!(rig.run(&["--socket-only"]).status.success());
    assert_eq!(
        rig.log().matches("stop ozboxd.service").count(),
        n,
        "an unchanged unit restarts nothing"
    );
}

#[test]
fn the_socket_only_step_touches_nothing_of_the_dashboard() {
    let rig = Rig::new(Some(OLD_UNIT));
    let o = rig.run(&["--socket-only"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(rig.unit().is_empty(), "no dashboard unit written");
    assert!(!rig.log().contains("ozbox-dashboard"), "{}", rig.log());
    assert!(rig.log().contains("useradd"));
}

/// A leftover from before: an `ssh_config` an earlier move copied from the box user is removed.
#[test]
fn an_ssh_config_an_earlier_move_copied_is_removed() {
    let rig = Rig::new(None);
    let ssh = rig.dir.path().join("work/ozbox-supervisor/home/.ssh");
    std::fs::create_dir_all(ssh.join("config.d")).unwrap();
    std::fs::write(ssh.join("config"), "ProxyCommand x\n").unwrap();
    std::fs::write(ssh.join("rc"), "id\n").unwrap();
    std::fs::write(ssh.join("id_ed25519"), "K").unwrap();
    // a runuser that runs the command after `-u <user> --`, as the real one does, for the supervisor's removal only
    let log = rig.dir.path().join("calls.log");
    tool(
        &rig.dir.path().join("bin"),
        "runuser",
        &format!("echo runuser \"$@\" >>'{}'; case \"$*\" in '-u ozbox-supervisor -- '*) shift 3; \"$@\";; esac; exit 0", log.display()),
    );
    assert!(rig.run(&[]).status.success());
    for f in ["config", "config.d", "rc"] {
        assert!(!ssh.join(f).exists(), "{f}");
    }
    // G1 N6: removed as the supervisor, never by root's own `rm` after a check on a folder the supervisor can swap for a link
    assert!(
        rig.log().contains("runuser -u ozbox-supervisor -- rm -rf"),
        "{}",
        rig.log()
    );
    let code = std::fs::read_to_string(script()).unwrap();
    assert!(
        !code
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .any(|l| l.trim_start().starts_with("rm -rf \"$d")),
        "root removes inside the supervisor's folder"
    );
    assert!(
        ssh.join("id_ed25519").exists(),
        "keys are the owner's to remove"
    );
}

fn unit_text(rig: &Rig, name: &str) -> String {
    std::fs::read_to_string(rig.dir.path().join("units").join(name)).unwrap_or_default()
}

/// A service manager that reports per unit what is active, from files in the rig, and records every call.
fn stateful_systemctl(rig: &Rig) {
    let r = rig.dir.path();
    tool(
        &r.join("bin"),
        "systemctl",
        &format!(
            "echo systemctl \"$@\" >>'{0}/calls.log'; case \"$1\" in is-active) [ -e '{0}/up-'\"$3\" ]; exit $?;; start) touch '{0}/up-'\"$2\"; [ \"$2\" = ozboxd.service ] && touch '{0}/up-ozboxd-supervisor.socket';; stop) rm -f '{0}/up-'\"$2\";; esac; exit 0",
            r.display()
        ),
    );
}

fn mark_up(rig: &Rig, unit: &str) {
    std::fs::write(rig.dir.path().join(format!("up-{unit}")), "").unwrap();
}

/// G1 N1: a socket unit is ordered before sockets.target, which basic.target waits for, and a service is ordered after
/// basic.target, so `After=<service>` in the socket unit is an ordering cycle at every boot after the first.
#[test]
fn the_socket_unit_orders_itself_after_no_service() {
    let rig = Rig::new(None);
    assert!(rig.run(&[]).status.success());
    let sock = unit_text(&rig, "ozboxd-supervisor.socket");
    for l in sock.lines() {
        let l = l.trim_start();
        assert!(
            !l.starts_with("After=") && !l.starts_with("Requires=") && !l.starts_with("BindsTo="),
            "ordering in the socket unit: {l}"
        );
    }
    assert!(!sock.contains("ozbox-secrets.service"), "{sock}");
    // the daemon's drop-in orders the service after the socket, which is the one direction that is safe
    assert!(
        unit_text(&rig, "ozboxd.service.d/10-supervisor-socket.conf")
            .contains("After=ozboxd-supervisor.socket")
    );
}

/// `systemd-analyze verify` on the units as written, where systemd is installed (CI's Linux runners; skipped elsewhere).
#[test]
fn systemd_analyze_finds_no_ordering_cycle_in_the_rendered_units() {
    if Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("systemd-analyze is not installed here: skipped");
        return;
    }
    let rig = Rig::new(None);
    assert!(rig.run(&[]).status.success());
    let d = rig.dir.path().join("verify");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::copy(
        rig.dir.path().join("units/ozboxd-supervisor.socket"),
        d.join("ozboxd-supervisor.socket"),
    )
    .unwrap();
    // the secrets service the real units order against, with default dependencies (a service is after basic.target): an
    // `After=ozbox-secrets.service` in the socket unit makes a cycle only when this one is in the set (G1 F6)
    std::fs::write(
        d.join("ozbox-secrets.service"),
        "[Unit]\nDescription=secrets\n[Service]\nExecStart=/bin/true\n",
    )
    .unwrap();
    std::fs::write(
        d.join("ozboxd.service"),
        format!(
            "[Unit]\nDescription=x\n{}\n[Service]\nExecStart=/bin/true\n",
            "Wants=ozboxd-supervisor.socket\nAfter=ozboxd-supervisor.socket"
        ),
    )
    .unwrap();
    let o = Command::new("systemd-analyze")
        .args(["verify", "--man=no"])
        .arg(d.join("ozboxd-supervisor.socket"))
        .arg(d.join("ozboxd.service"))
        .arg(d.join("ozbox-secrets.service"))
        .output()
        .unwrap();
    let t = text(&o).to_lowercase();
    assert!(!t.contains("cycle") && !t.contains("ordering"), "{t}");
}

/// G1 N2: a dashboard moved by the earlier version has `SupplementaryGroups=ozbox` in its unit, which systemd grants at every
/// start whatever /etc/group says. The socket-only upgrade removes the line, reloads, and only then restarts.
#[test]
fn the_socket_only_upgrade_takes_the_group_out_of_an_old_dashboard_unit() {
    let rig = Rig::new(None);
    let old = "[Service]\nUser=ozbox-supervisor\nGroup=ozbox-supervisor\nSupplementaryGroups=ozbox\nExecStart=/usr/local/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com\n";
    std::fs::write(rig.dir.path().join("units/ozbox-dashboard.service"), old).unwrap();
    // /etc/group no longer lists it (an earlier run took it out), so only the unit still grants the group
    mark_up(&rig, "ozbox-dashboard.service");
    stateful_systemctl(&rig);
    mark_up(&rig, "ozbox-dashboard.service");
    let o = rig.run(&["--socket-only"]);
    assert!(o.status.success(), "{}", text(&o));
    let u = rig.unit();
    assert!(!u.contains("SupplementaryGroups"), "{u}");
    assert!(
        u.contains("ExecStart=/usr/local/bin/ozbox serve"),
        "the rest of the unit is kept\n{u}"
    );
    let l = rig.log();
    let reload = l.find("systemctl daemon-reload").unwrap();
    let restart = l.find("systemctl restart ozbox-dashboard.service").unwrap();
    assert!(reload < restart, "reloaded before the restart\n{l}");
}

/// G1 N3 and F4: systemd refuses to start a socket whose service is already running. With the files unchanged and the socket
/// down (after a start-limit failure, say), the order is explicit: stop the daemon, start the socket, start the daemon.
#[test]
fn a_socket_that_is_down_while_the_daemon_runs_is_brought_back_by_stopping_then_starting_in_order()
{
    let rig = Rig::new(None);
    stateful_systemctl(&rig);
    assert!(rig.run(&["--socket-only"]).status.success());
    // now both are up; the socket goes down, the daemon keeps running
    mark_up(&rig, "ozboxd.service");
    std::fs::remove_file(rig.dir.path().join("up-ozboxd-supervisor.socket")).ok();
    let before = rig.log().len();
    let o = rig.run(&["--socket-only"]);
    assert!(o.status.success(), "{}", text(&o));
    let now = rig.log()[before..].to_string();
    let stop = now
        .find("systemctl stop ozboxd.service")
        .unwrap_or_else(|| panic!("{now}"));
    let sock = now
        .find("systemctl start ozboxd-supervisor.socket")
        .unwrap_or_else(|| panic!("{now}"));
    let start = now
        .find("systemctl start ozboxd.service")
        .unwrap_or_else(|| panic!("{now}"));
    assert!(
        stop < sock && sock < start,
        "stop daemon, start socket, start daemon: {now}"
    );
    assert!(
        !now.contains("systemctl restart"),
        "no restart job, whose ordering is systemd's to decide: {now}"
    );
    assert!(
        !text(&o).contains("did not start") && !text(&o).contains("not up after"),
        "{}",
        text(&o)
    );
    // and with the daemon NOT running (first boot, or an operator's `systemctl stop ozboxd`) nothing is started or restarted:
    // the socket is only enabled and the daemon's `Wants=` brings it up when the daemon starts (G1 F5, N8)
    let rig = Rig::new(None);
    stateful_systemctl(&rig);
    assert!(rig.run(&["--socket-only"]).status.success());
    assert!(
        rig.log()
            .contains("systemctl enable ozboxd-supervisor.socket"),
        "{}",
        rig.log()
    );
    assert!(
        !rig.log().contains("systemctl start") && !rig.log().contains("restart"),
        "a stopped daemon stays stopped\n{}",
        rig.log()
    );
}

/// G1 N4: a daemon that does not carry the marker would ignore the descriptor and leave a listening socket inheritable by
/// every run. No socket unit and no drop-in are written for it, and a leftover pair is removed.
#[test]
fn no_socket_is_handed_to_a_daemon_that_does_not_take_one() {
    let rig = Rig::new(None);
    std::fs::write(rig.dir.path().join("ozboxd"), "ELF an older daemon").unwrap();
    let o = rig.run(&["--socket-only"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("does not take its socket from systemd"),
        "{}",
        text(&o)
    );
    assert!(unit_text(&rig, "ozboxd-supervisor.socket").is_empty());
    assert!(!rig
        .dir
        .path()
        .join("units/ozboxd.service.d/10-supervisor-socket.conf")
        .exists());
    assert!(
        !rig.log().contains("start ozboxd-supervisor.socket"),
        "{}",
        rig.log()
    );
    // a pair left by a newer daemon is taken away when the daemon is rolled back
    let rig = Rig::new(None);
    assert!(rig.run(&["--socket-only"]).status.success());
    assert!(!unit_text(&rig, "ozboxd-supervisor.socket").is_empty());
    std::fs::write(rig.dir.path().join("ozboxd"), "ELF an older daemon").unwrap();
    assert!(rig.run(&["--socket-only"]).status.success());
    assert!(unit_text(&rig, "ozboxd-supervisor.socket").is_empty());
    assert!(!rig
        .dir
        .path()
        .join("units/ozboxd.service.d/10-supervisor-socket.conf")
        .exists());
    assert!(
        rig.log().contains("disable --now ozboxd-supervisor.socket"),
        "{}",
        rig.log()
    );
    // the daemon is never probed by running it
    let code = std::fs::read_to_string(script()).unwrap();
    assert!(
        !code.contains("\"$daemon_bin\" --"),
        "the daemon is checked by its file, not by running it"
    );
}

/// G1 F8: the marker the script greps for is the one the daemon's own library says it logs (and image.yml greps the release
/// build for it). A reworded constant with the script left alone would make every box skip its dashboard socket.
#[test]
fn the_setup_scripts_marker_is_the_daemons_marker() {
    let lib = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ozbox-listenfd/src/lib.rs"),
    )
    .unwrap();
    let line = lib
        .lines()
        .find(|l| l.contains("pub const DAEMON_MARKER"))
        .unwrap();
    let marker = line.split('"').nth(1).unwrap();
    let sh = std::fs::read_to_string(script()).unwrap();
    assert!(
        sh.contains(&format!("grep -aq '{marker}' \"$daemon_bin\"")),
        "the script's literal differs from {marker}"
    );
    let ci = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/image.yml"),
    )
    .unwrap();
    assert!(
        ci.contains(&format!("LC_ALL=C grep -aqF '{marker}'")),
        "the image build does not check the release daemon for {marker}"
    );
}

/// ADR 0043: the dashboard's unit makes the folder for the agent socket, and the setup adds the Oz Box tools to the coding agents'
/// settings AS the box user (never the dashboard's user), best effort, on every run.
#[test]
fn the_unit_makes_the_agent_socket_folder_and_the_box_user_gets_the_agent_settings() {
    let rig = Rig::new(Some(OLD_UNIT));
    let bin = rig.dir.path().join("ozbox-bin");
    std::fs::write(&bin, "#!/bin/sh\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let o = rig.run_env(&[], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    let u = rig.unit();
    for want in [
        "RuntimeDirectory=ozbox-agent-mcp",
        "RuntimeDirectoryMode=0755",
    ] {
        assert!(u.contains(want), "{want}\n{u}");
    }
    // the settings are written as the box user, with the box user's own home, by the program
    let l = rig.log();
    let call = l
        .lines()
        .find(|l| l.contains("agent-mcp install"))
        .unwrap_or_else(|| panic!("no agent settings step:\n{l}"));
    assert!(call.starts_with("runuser -u ozbox -- env HOME="), "{call}");
    assert!(call.contains("ozbox-bin agent-mcp install"), "{call}");
    assert!(
        !call.contains("ozbox-supervisor"),
        "never as the dashboard's user: {call}"
    );
    // the socket-only step brings it too (a program upgrade runs that one)
    let rig = Rig::new(Some(OLD_UNIT));
    std::fs::write(rig.dir.path().join("ozbox-bin"), "#!/bin/sh\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            rig.dir.path().join("ozbox-bin"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let o = rig.run_env(
        &["--socket-only"],
        &[("OZBOX_BIN", &rig.dir.path().join("ozbox-bin"))],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(rig.log().contains("agent-mcp install"), "{}", rig.log());
}

const MOVED_UNIT_WITHOUT_THE_DOOR: &str = "[Service]\nUser=ozbox-supervisor\nExecStart=/usr/local/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com --tunnel cloudflare\n";

fn executable(rig: &Rig, name: &str) -> PathBuf {
    let p = rig.dir.path().join(name);
    std::fs::write(&p, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// ADR 0043 a box whose dashboard already moved has the OLD unit, without the folder the door's socket needs. A
/// program upgrade runs `--socket-only`; it must bring the unit up to date, restart the dashboard, and only then write the
/// engines' settings. Nothing else in the unit changes (port, public name and tunnel are read back from it).
#[test]
fn a_program_upgrade_brings_the_agent_socket_folder_to_a_dashboard_that_already_moved() {
    let rig = Rig::new(None);
    std::fs::write(
        rig.dir.path().join("units/ozbox-dashboard.service"),
        MOVED_UNIT_WITHOUT_THE_DOOR,
    )
    .unwrap();
    std::fs::write(rig.dir.path().join("active"), "").unwrap(); // the dashboard is running
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let bin = executable(&rig, "ozbox-bin");
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    let u = rig.unit();
    for want in [
        "RuntimeDirectory=ozbox-agent-mcp",
        "RuntimeDirectoryMode=0755",
        "--port 7878",
        "https://ozbox.example.com --tunnel cloudflare",
    ] {
        assert!(u.contains(want), "{want}\n{u}");
    }
    let l = rig.log();
    let restart = l
        .lines()
        .position(|x| x.contains("restart ozbox-dashboard.service"))
        .unwrap_or_else(|| panic!("no dashboard restart:\n{l}"));
    let install = l
        .lines()
        .position(|x| x.contains("agent-mcp install"))
        .unwrap_or_else(|| panic!("no settings step:\n{l}"));
    assert!(
        restart < install,
        "the door exists before the engines are told about it:\n{l}"
    );
    // a second run changes nothing: no second restart
    let before = rig
        .log()
        .lines()
        .filter(|x| x.contains("restart ozbox-dashboard.service"))
        .count();
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    let after = rig
        .log()
        .lines()
        .filter(|x| x.contains("restart ozbox-dashboard.service"))
        .count();
    assert_eq!(before, after, "an up-to-date unit is not restarted again");
}

/// the setup step says what it skips, and never lets a box-user process share its terminal.
#[test]
fn the_settings_step_says_what_it_skips_and_gives_the_box_user_no_terminal() {
    // no home folder for the box user
    let rig = Rig::new(Some(OLD_UNIT));
    let bin = executable(&rig, "ozbox-bin");
    std::fs::remove_dir_all(rig.dir.path().join("work/home/ozbox")).ok();
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(text(&o).contains("no home folder"), "{}", text(&o));
    // no program
    let rig = Rig::new(Some(OLD_UNIT));
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let missing = rig.dir.path().join("nope");
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &missing)]);
    assert!(text(&o).contains("is not installed"), "{}", text(&o));
    // a refused engine: the step reports it and the answer is shown
    let rig = Rig::new(Some(OLD_UNIT));
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let bin = executable(&rig, "ozbox-bin");
    tool(
        &rig.dir.path().join("bin"),
        "runuser",
        "echo '  Claude Code: left alone, it is not valid JSON.'; exit 1",
    );
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(
        o.status.success(),
        "a refused engine does not stop the rest of the setup: {}",
        text(&o)
    );
    let t = text(&o);
    assert!(
        t.contains("left alone, it is not valid JSON")
            && t.contains("not added to every coding agent"),
        "{t}"
    );
    // the box user's process is run with the setup step's terminal closed
    let code = std::fs::read_to_string(script()).unwrap();
    assert!(
        code.contains("agent-mcp install </dev/null"),
        "no input from root's terminal"
    );
}

/// what is read back from the unit is checked. A unit with an extra flag on its line is left alone (and said), where
/// it used to be rendered into one that cannot start and restarted.
#[test]
fn a_unit_with_something_extra_on_its_line_is_left_alone() {
    let rig = Rig::new(None);
    let odd =
        MOVED_UNIT_WITHOUT_THE_DOOR.replace("--tunnel cloudflare", "--tunnel cloudflare --foo bar");
    std::fs::write(rig.dir.path().join("units/ozbox-dashboard.service"), &odd).unwrap();
    std::fs::write(rig.dir.path().join("active"), "").unwrap();
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let bin = executable(&rig, "ozbox-bin");
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(rig.unit(), odd, "the unit is as it was");
    assert!(text(&o).contains("not one this step wrote"), "{}", text(&o));
    assert!(
        !rig.log().contains("restart ozbox-dashboard.service"),
        "{}",
        rig.log()
    );
}

/// the unit is written beside itself and moved into place, and if the dashboard will not start with the new one the
/// old one is put back.
#[test]
fn a_dashboard_that_will_not_start_with_the_new_unit_gets_the_old_one_back() {
    let rig = Rig::new(None);
    std::fs::write(
        rig.dir.path().join("units/ozbox-dashboard.service"),
        MOVED_UNIT_WITHOUT_THE_DOOR,
    )
    .unwrap();
    std::fs::write(rig.dir.path().join("active"), "").unwrap();
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let b = rig.dir.path().join("bin");
    let l = rig.dir.path().join("calls.log");
    tool(&b, "systemctl", &format!("echo systemctl \"$@\" >>'{}'; case \"$1\" in restart) [ \"$2\" = ozbox-dashboard.service ] && exit 1;; esac; exit 0", l.display()));
    let bin = executable(&rig, "ozbox-bin");
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        rig.unit(),
        MOVED_UNIT_WITHOUT_THE_DOOR,
        "the old unit was put back"
    );
    assert!(text(&o).contains("old unit was put back"), "{}", text(&o));
    let leftovers: Vec<_> = std::fs::read_dir(rig.dir.path().join("units"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".new.") || n.contains(".old."))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let script = std::fs::read_to_string(script()).unwrap();
    assert!(
        script.contains("mv -f \"$tmp\" \"$new_unit\""),
        "written beside the unit and moved into place"
    );
}

/// `systemctl restart` of a simple unit succeeds once the process is forked, so a dashboard that exits at once reads
/// as restarted. It is asked whether it is running, and the old unit goes back if it is not.
#[test]
fn a_dashboard_that_exits_at_once_after_a_good_restart_gets_the_old_unit_back() {
    let rig = Rig::new(None);
    std::fs::write(
        rig.dir.path().join("units/ozbox-dashboard.service"),
        MOVED_UNIT_WITHOUT_THE_DOOR,
    )
    .unwrap();
    std::fs::write(rig.dir.path().join("active"), "").unwrap();
    let b = rig.dir.path().join("bin");
    let l = rig.dir.path().join("calls.log");
    let r = rig.dir.path();
    // restart "works", then the unit is not active; a second restart (of the old unit) is fine and it stays active
    tool(&b, "systemctl", &format!("echo systemctl \"$@\" >>'{l}'; case \"$1 $2\" in \"restart ozbox-dashboard.service\") n=$(cat '{r}/n' 2>/dev/null || echo 0); echo $((n+1)) >'{r}/n'; [ \"$n\" = 0 ] && rm -f '{r}/active' || touch '{r}/active';; is-active*) [ -e '{r}/active' ] || exit 1;; esac; exit 0", l = l.display(), r = r.display()));
    let bin = executable(&rig, "ozbox-bin");
    let o = rig.run_env(
        &["--socket-only"],
        &[
            ("OZBOX_BIN", &bin),
            ("OZBOX_DASHBOARD_SETTLE_S", std::path::Path::new("0")),
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        rig.unit(),
        MOVED_UNIT_WITHOUT_THE_DOOR,
        "the old unit was put back: {}\n{}",
        text(&o),
        rig.log()
    );
    assert!(text(&o).contains("old unit was put back"), "{}", text(&o));
}

/// a crash loop that happens to read `active` at the moment of the check is still caught: systemd restarted it (its
/// restart count moved). A dashboard that stays up, with a steady count, is left alone.
#[test]
fn a_dashboard_in_a_crash_loop_is_caught_by_its_restart_count_not_by_when_it_is_looked_at() {
    for (loops, expect_back) in [(true, true), (false, false)] {
        let rig = Rig::new(None);
        std::fs::write(
            rig.dir.path().join("units/ozbox-dashboard.service"),
            MOVED_UNIT_WITHOUT_THE_DOOR,
        )
        .unwrap();
        std::fs::write(rig.dir.path().join("active"), "").unwrap();
        let b = rig.dir.path().join("bin");
        let l = rig.dir.path().join("calls.log");
        let r = rig.dir.path();
        // always active; `show NRestarts` counts up on every ask when it loops, and stays at 0 when it does not
        let count = if loops {
            format!(
                "n=$(cat '{r}/c' 2>/dev/null || echo 0); echo $((n+1)) >'{r}/c'; echo $n",
                r = r.display()
            )
        } else {
            "echo 0".to_string()
        };
        tool(&b, "systemctl", &format!("echo systemctl \"$@\" >>'{l}'; case \"$1\" in show) case \"$3\" in NRestarts) {count};; *) echo 1;; esac;; is-active*) exit 0;; esac; exit 0", l = l.display()));
        let bin = executable(&rig, "ozbox-bin");
        let o = rig.run_env(
            &["--socket-only"],
            &[
                ("OZBOX_BIN", &bin),
                ("OZBOX_DASHBOARD_SETTLE_S", std::path::Path::new("0")),
            ],
        );
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(
            text(&o).contains("old unit was put back"),
            expect_back,
            "loops={loops}: {}\n{}",
            text(&o),
            rig.log()
        );
    }
}

/// the wait is longer than the unit's `RestartSec`, so a dashboard that fails at once has been restarted by systemd
/// when it is asked. Nothing may change one without the other.
#[test]
fn the_dashboards_settle_time_is_longer_than_its_restart_delay() {
    let text = std::fs::read_to_string(script()).unwrap();
    let settle: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("settle_s=\"${OZBOX_DASHBOARD_SETTLE_S:-"))
        .and_then(|r| r.split('}').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("settle_s default"));
    let restart: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("RestartSec="))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("RestartSec"));
    assert!(
        settle > restart,
        "settle {settle}s must exceed RestartSec {restart}s"
    );
    assert!(text.contains("NRestarts") && text.contains("ActiveEnterTimestampMonotonic"));
}

/// a copy that fails (a full disk) ends that step, not the script: the unit is as it was, and the settings step runs.
#[test]
fn a_backup_copy_that_fails_does_not_abort_the_script() {
    let rig = Rig::new(None);
    std::fs::write(
        rig.dir.path().join("units/ozbox-dashboard.service"),
        MOVED_UNIT_WITHOUT_THE_DOOR,
    )
    .unwrap();
    std::fs::write(rig.dir.path().join("active"), "").unwrap();
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    let b = rig.dir.path().join("bin");
    tool(&b, "cp", "exit 1");
    let bin = executable(&rig, "ozbox-bin");
    let path = format!(
        "{}:{}",
        b.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let o = rig.run_env(
        &["--socket-only"],
        &[("OZBOX_BIN", &bin), ("PATH", std::path::Path::new(&path))],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("could not be backed up"), "{}", text(&o));
    assert_eq!(rig.unit(), MOVED_UNIT_WITHOUT_THE_DOOR);
    assert!(
        rig.log().contains("agent-mcp install"),
        "the settings step still ran:\n{}",
        rig.log()
    );
}

// ---- after an upgrade: the folder on /work outlives the unit, and so does its `.migrated` marker ----

fn sha_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn have_sha256sum() -> bool {
    Command::new("sha256sum").arg("--version").output().is_ok()
}

/// A box that was moved before an upgrade: the folder and its marker are there, the dashboard's settings are not (the
/// person then runs `ozbox dashboard install`, which stages the unit and the settings again).
fn upgraded_box_without_settings() -> Rig {
    let rig = Rig::new(Some(OLD_UNIT));
    let home = rig.dir.path().join("work/ozbox-supervisor");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join(".migrated"), "").unwrap();
    rig
}

fn home_auth(rig: &Rig) -> Option<String> {
    std::fs::read_to_string(rig.dir.path().join("work/ozbox-supervisor/auth.toml")).ok()
}

#[test]
fn a_fresh_install_after_an_upgrade_installs_the_verified_settings_and_starts_the_dashboard() {
    if !have_sha256sum() {
        return;
    }
    let rig = upgraded_box_without_settings();
    let o = rig.run(&["--expect-auth", &sha_hex(b"y = 2\n")]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(home_auth(&rig).as_deref(), Some("y = 2\n"));
    assert!(
        rig.log().contains("restart ozbox-dashboard"),
        "{}",
        rig.log()
    );
    assert!(
        text(&o).contains("runs as ozbox-supervisor"),
        "{}",
        text(&o)
    );
}

#[test]
fn after_an_upgrade_settings_that_are_not_the_ones_sent_are_refused_and_nothing_changes() {
    if !have_sha256sum() {
        return;
    }
    let rig = upgraded_box_without_settings();
    let o = rig.run(&["--expect-auth", &"0".repeat(64)]);
    assert!(!o.status.success());
    assert!(
        text(&o).contains("not the ones your computer sent"),
        "{}",
        text(&o)
    );
    assert!(home_auth(&rig).is_none());
    assert!(rig.unit().is_empty());
    assert!(!rig.log().contains("restart ozbox-dashboard"));
    assert!(!rig
        .dir
        .path()
        .join("work/ozbox-supervisor/auth.toml.verified")
        .exists());
}

#[test]
fn a_dashboard_that_has_settings_keeps_them_against_a_request_the_box_user_can_make() {
    if !have_sha256sum() {
        return;
    }
    // the box user stages a file of its own and asks with that file's own sha256: that proves nothing about the person
    let rig = Rig::new(Some(OLD_UNIT));
    assert!(rig.run(&[]).status.success());
    let before = home_auth(&rig);
    assert_eq!(before.as_deref(), Some("y = 2\n"));
    let staged = rig
        .dir
        .path()
        .join("work/home/ozbox/ozbox-dashboard/auth.toml");
    std::fs::write(&staged, "attacker = true\n").unwrap();
    std::fs::write(
        rig.dir
            .path()
            .join("work/home/ozbox/.config/systemd/user/ozbox-dashboard.service"),
        OLD_UNIT,
    )
    .unwrap();
    let n = rig.log().matches("restart ozbox-dashboard").count();
    let o = rig.run(&["--expect-auth", &sha_hex(b"attacker = true\n")]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("already has sign-in settings of its own"),
        "{}",
        text(&o)
    );
    assert_eq!(home_auth(&rig), before);
    assert_eq!(rig.log().matches("restart ozbox-dashboard").count(), n);
}

#[test]
fn a_dashboard_with_no_settings_to_read_is_not_started_and_the_setup_fails_loudly() {
    let rig = Rig::new(Some(OLD_UNIT));
    assert!(rig.run(&[]).status.success());
    std::fs::remove_file(rig.dir.path().join("work/ozbox-supervisor/auth.toml")).unwrap();
    let n = rig.log().matches("restart ozbox-dashboard").count();
    let o = rig.run(&[]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("sign-in settings are missing"),
        "{}",
        text(&o)
    );
    assert_eq!(rig.log().matches("restart ozbox-dashboard").count(), n);
}

#[test]
fn a_dashboard_that_runs_but_does_not_answer_is_reported_as_failed_not_ok() {
    let rig = Rig::new(Some(OLD_UNIT));
    let silent = rig.dir.path().join("bin/probe-silent");
    let o = rig.run_env(&[], &[("OZBOX_DASHBOARD_PROBE", &silent)]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("nothing answers on port 7878"),
        "{}",
        text(&o)
    );
    assert!(
        rig.log().contains("disable --now ozbox-dashboard"),
        "{}",
        rig.log()
    );
}

fn steps(rig: &Rig) -> String {
    std::fs::read_to_string(rig.dir.path().join("etc/ozbox/first-boot-steps")).unwrap_or_default()
}

fn agent_rig() -> (Rig, PathBuf) {
    let rig = Rig::new(Some(OLD_UNIT));
    std::fs::create_dir_all(rig.dir.path().join("work/home/ozbox")).unwrap();
    std::fs::create_dir_all(rig.dir.path().join("etc/ozbox")).unwrap();
    let bin = executable(&rig, "ozbox-bin");
    (rig, bin)
}

/// B4-12: the plain way works: one runuser call, systemd is not asked, and the step is recorded for the self-test.
#[test]
fn the_agent_settings_step_is_recorded_when_it_works() {
    let (rig, bin) = agent_rig();
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!rig.log().contains("systemd-run"), "{}", rig.log());
    assert_eq!(steps(&rig), "agent_tools ok runuser 1\n");
}

/// B4-12: after an upgrade the setup's `runuser` was refused ("cannot set user id"), so the coding agents never got the Oz
/// Box tools. Now systemd starts the step as the box user instead, in a unit of its own, with no terminal and no privileges
/// to gain, and the person's home.
#[test]
fn a_refused_runuser_hands_the_agent_settings_step_to_systemd_as_the_box_user() {
    let (rig, bin) = agent_rig();
    let b = rig.dir.path().join("bin");
    let l = rig.dir.path().join("calls.log");
    tool(
        &b,
        "runuser",
        &format!(
            "echo runuser \"$@\" >>'{}'; echo 'runuser: cannot set user id: Operation not permitted' >&2; exit 1",
            l.display()
        ),
    );
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    let call = rig
        .log()
        .lines()
        .find(|x| x.starts_with("systemd-run "))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("systemd was not asked:\n{}", rig.log()));
    for want in [
        "--wait",
        "--pipe",
        "--uid=ozbox",
        "--gid=ozbox",
        "--property=NoNewPrivileges=yes",
        "/work/home/ozbox",
        "ozbox-bin agent-mcp install",
    ] {
        assert!(call.contains(want), "{want}: {call}");
    }
    assert!(!call.contains("ozbox-supervisor"), "{call}");
    assert_eq!(steps(&rig), "agent_tools ok systemd-run 1\n");
}

/// B4-12: a systemd that is not answering yet is asked again after a pause, a bounded number of times, never forever; a
/// step that never ran is recorded as failed, naming why, and does not stop the rest of the setup.
#[test]
fn a_systemd_that_is_not_ready_is_asked_a_bounded_number_of_times() {
    let (rig, bin) = agent_rig();
    let b = rig.dir.path().join("bin");
    let l = rig.dir.path().join("calls.log");
    tool(
        &b,
        "runuser",
        "echo 'runuser: cannot set user id: Operation not permitted' >&2; exit 1",
    );
    // not ready on the first try, then it works
    let n = rig.dir.path().join("tries");
    tool(
        &b,
        "systemd-run",
        &format!(
            "echo systemd-run \"$@\" >>'{}'; echo x >>'{}'; if [ \"$(wc -l <'{}')\" -lt 2 ]; then echo 'Failed to connect to bus: No such file or directory' >&2; exit 1; fi; exit 0",
            l.display(),
            n.display(),
            n.display()
        ),
    );
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(steps(&rig), "agent_tools ok systemd-run 2\n");

    // never ready: the first try and one per pause (two), then it stops and says what to run
    let (rig, bin) = agent_rig();
    let b = rig.dir.path().join("bin");
    let l = rig.dir.path().join("calls.log");
    tool(
        &b,
        "runuser",
        "echo 'runuser: cannot set user id: Operation not permitted' >&2; exit 1",
    );
    tool(
        &b,
        "systemd-run",
        &format!(
            "echo systemd-run \"$@\" >>'{}'; echo 'Failed to start transient service unit: Connection timed out' >&2; exit 1",
            l.display()
        ),
    );
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "the rest of the setup still runs: {}", text(&o));
    assert_eq!(
        rig.log().lines().filter(|x| x.starts_with("systemd-run ")).count(),
        3
    );
    assert_eq!(steps(&rig), "agent_tools failed switch-user-refused 3\n");
    assert!(text(&o).contains("ozbox admin <box> -- ensure-supervisor"), "{}", text(&o));
}

/// B4-12: a coding agent's settings the program refused (the person's own file) are said, recorded, and never retried or
/// handed to systemd: switching user worked.
#[test]
fn a_refused_agent_setting_is_recorded_and_not_retried() {
    let (rig, bin) = agent_rig();
    let b = rig.dir.path().join("bin");
    tool(
        &b,
        "runuser",
        "echo '  Claude Code: left alone, it is not valid JSON.'; exit 1",
    );
    let o = rig.run_env(&["--socket-only"], &[("OZBOX_BIN", &bin)]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!rig.log().contains("systemd-run"), "{}", rig.log());
    assert_eq!(steps(&rig), "agent_tools failed agent-settings-refused 1\n");
}
