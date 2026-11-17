//! The box's web IDE (code-server) and desktop (KasmVNC) as services of the box user, and every way to reach them:
//! on `localhost` through the box's own SSH route, on the person's own domain behind the Oz Box sign-in, and from a
//! desktop editor over SSH.
//!
//! Both services run as `systemd --user` units of the box user (the box user has no sudo, ADR 0011), bound to
//! `127.0.0.1` only. Nothing here opens a port on the box (ADR 0005): the program on this computer reaches them through
//! the same outbound SSH forward everything else uses. Their own sign-in stays on: the password is generated here, kept
//! in the secret store (write-only: no answer, no log and no argument ever carries it), and sent to the box on the
//! standard input of the setup command.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod editors;
pub mod local;
pub mod procs;
pub mod proxy;
pub mod settings;

use serde::{Deserialize, Serialize};

pub use settings::CodeSettings;

/// The two services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Service {
    /// code-server: VS Code in the browser.
    Ide,
    /// KasmVNC: a desktop with Firefox in the browser.
    Desktop,
}

pub const ALL: [Service; 2] = [Service::Ide, Service::Desktop];

/// `code.toml`, beside the main configuration.
pub fn settings_path() -> Option<std::path::PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("code.toml"))
}

/// The folder the IDE opens on.
pub const REPOS_DIR: &str = "/work/repos";
/// The workspace file the IDE opens: one folder per repository under [`REPOS_DIR`].
pub const WORKSPACE_FILE: &str = "/work/repos/oz.code-workspace";
/// How long code-server keeps a disconnected session (a week).
pub const GRACE_S: u64 = 604_800;

/// Reattaches to the first unattached `term-N` tmux session, or makes `term-N`. Where tmux is missing it opens a plain
/// login shell, which ends with its tab (the box page says so).
pub const OZ_TERM: &str = "\
#!/bin/sh
command -v tmux >/dev/null 2>&1 || exec \"${SHELL:-/bin/bash}\" -l
first=$(tmux list-sessions -F '#{session_name} #{session_attached}' 2>/dev/null | awk '$1 ~ /^term-[0-9]+$/ && $2 == 0 { print $1; exit }')
if [ -n \"$first\" ]; then exec tmux attach-session -t \"$first\"; fi
n=1
while tmux has-session -t \"term-$n\" 2>/dev/null; do n=$((n + 1)); done
exec tmux new-session -s \"term-$n\"
";

/// Writes the workspace file: each directory under `/work/repos` whose name is plain becomes a folder.
pub const OZ_WORKSPACE: &str = "\
#!/bin/sh
d=${OZ_REPOS:-/work/repos}
out=\"$d/oz.code-workspace\"
[ -d \"$d\" ] || exit 0
{
  printf '{\\n  \"folders\": [\\n'
  sep=''
  for p in \"$d\"/*/; do
    [ -d \"$p\" ] || continue
    b=$(basename \"$p\")
    case \"$b\" in *[!A-Za-z0-9._-]*) continue;; esac
    printf '%b    {\"path\": \"%s\"}' \"$sep\" \"$b\"
    sep=',\\n'
  done
  printf '\\n  ]\\n}\\n'
} > \"$out.tmp\" && mv \"$out.tmp\" \"$out\"
";

/// Lines every box's `~/.tmux.conf` should have; each is appended only when it is not there yet, so running setup again
/// changes nothing and a person's own file is never rewritten.
///
/// Copying out of tmux: `set-clipboard on` makes tmux send what it copies (a mouse drag, or copy mode's Enter) to the
/// terminal around it as an OSC 52 sequence, which the browser IDE's terminal and the dashboard's terminal turn into a
/// write to the person's clipboard. tmux already does that for `xterm*` outer terminals; the `terminal-features` line adds
/// the same for an outer tmux or screen (tmux on a laptop, then `ssh` to the box, then tmux here). A program inside tmux that
/// asks to READ the clipboard (`OSC 52 ;?`) gets tmux's own copy buffer back, never the person's clipboard: tmux answers that
/// itself. `allow-passthrough` is deliberately not set: OSC 52 does not need it, and it would let any program inside reach
/// the outer terminal unfiltered.
pub const TMUX_LINES: [&str; 5] = [
    "set -g mouse on",
    "set -g history-limit 100000",
    "set -g default-terminal \"tmux-256color\"",
    "set -g set-clipboard on",
    "set -as terminal-features \",screen*:clipboard,tmux*:clipboard\"",
];

/// Editor settings that make terminals survive: the default profile is the tmux one, with a plain one beside it, and the
/// editor restores windows and terminals after a disconnect. `home` is the box user's home (the profile needs a full path).
/// The last two make selecting and pasting in a browser terminal behave.
pub fn editor_settings(home: &str) -> String {
    format!(
        "{{\n  \"terminal.integrated.profiles.linux\": {{\n    \"oz-term\": {{ \"path\": \"{home}/.local/bin/oz-term\" }},\n    \"bash (ends with the tab)\": {{ \"path\": \"bash\", \"args\": [\"-l\"] }}\n  }},\n  \"terminal.integrated.defaultProfile.linux\": \"oz-term\",\n  \"terminal.integrated.enablePersistentSessions\": true,\n  \"terminal.integrated.persistentSessionReviveProcess\": \"onExitAndWindowClose\",\n  \"window.restoreWindows\": \"all\",\n  \"files.hotExit\": \"onExitAndWindowClose\",\n  \"terminal.integrated.macOptionClickForcesSelection\": true,\n  \"terminal.integrated.rightClickBehavior\": \"copyPaste\"\n}}\n"
    )
}

/// One keymap per operating system for the browser IDE's terminal (the editor's own keys are the browser's and need
/// nothing). The editor picks the binding for the computer the browser runs on, so one file serves every visitor:
///
/// | | macOS | Windows | Linux |
/// |---|---|---|---|
/// | copy | Cmd+C (editor default) | Ctrl+C with a selection, Ctrl+Shift+C (editor default) | Ctrl+C with a selection (added here), Ctrl+Shift+C |
/// | interrupt | Ctrl+C | Ctrl+C with nothing selected | Ctrl+C with nothing selected |
/// | paste | Cmd+V (the browser's own paste) | Ctrl+V (editor), Ctrl+Shift+V and Shift+Insert (browser's own) | Ctrl+V (added here), Ctrl+Shift+V and Shift+Insert (browser's own) |
///
/// Why the paste keys differ: the editor's paste command reads the clipboard from code, which Chromium allows once the person
/// says yes, and Firefox and Safari allow only after a click on a small Paste button. The browser's own paste (a `paste` event)
/// needs no permission in any browser, so wherever the terminal lets the key through (Cmd+V, Ctrl+Shift+V, Shift+Insert) the
/// editor's command is removed and the browser pastes. Ctrl+V cannot be let through: the terminal turns a plain Ctrl+V into the
/// shell's literal-next key whenever the browser can read the clipboard from code, so Ctrl+V stays on the editor's command.
/// (A leading `-` on a command removes a default binding; `isLinux` and `isMac` are the visitor's computer.)
pub const KEYBINDINGS: &str = r#"[
  { "key": "cmd+v", "command": "-workbench.action.terminal.paste", "when": "terminalFocus" },
  { "key": "ctrl+shift+v", "command": "-workbench.action.terminal.paste", "when": "terminalFocus" },
  { "key": "shift+insert", "command": "-workbench.action.terminal.pasteSelection", "when": "terminalFocus" },
  { "key": "ctrl+v", "command": "workbench.action.terminal.paste", "when": "isLinux && terminalFocus" },
  { "key": "ctrl+c", "command": "workbench.action.terminal.copyAndClearSelection", "when": "isLinux && terminalFocus && terminalTextSelected" }
]
"#;

/// Entries an earlier Oz Box wrote that turned out wrong; setup takes them out of a person's file again. Removing the
/// editor's Ctrl+V paste made Ctrl+V type the shell's literal-next key (`^V`) on Windows and Linux in every browser that can
/// read the clipboard from code, so Ctrl+V pasted nothing. Only an exact copy of what Oz Box wrote is removed.
pub const RETIRED_KEYBINDINGS: &str = r#"[
  { "key": "ctrl+v", "command": "-workbench.action.terminal.paste", "when": "terminalFocus" }
]
"#;

/// Merges defaults into a person's JSON file on the box: a key they have is never changed or removed (for a list, their
/// entries stay and only missing ones are added), a file that is absent is created, and a file that is not plain JSON
/// (damage, or comments anywhere but a header) is left exactly as it is. Writes nothing when nothing is missing, so it is safe
/// to run again. A header of whole-line `//` comments (the editor writes one at the top of a new keybindings file) is kept
/// as it is. An optional third file lists entries an earlier Oz Box wrote and now takes back (see [`RETIRED_KEYBINDINGS`]):
/// only exact copies are removed from a list.
pub const OZ_MERGE_JSON: &str = r#"#!/usr/bin/env python3
import json, os, sys
dest, defaults = sys.argv[1], sys.argv[2]
retired = []
if len(sys.argv) > 3:
    with open(sys.argv[3]) as f:
        retired = json.load(f)
with open(defaults) as f:
    want = json.load(f)
if not os.path.exists(dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w") as f:
        f.write(json.dumps(want, indent=2) + "\n")
    sys.exit(0)
try:
    with open(dest) as f:
        text = f.read()
    lines = text.split("\n")
    n = 0
    while n < len(lines) and (lines[n].strip() == "" or lines[n].lstrip().startswith("//")):
        n += 1
    header = "\n".join(lines[:n])
    have = json.loads("\n".join(lines[n:]))
except Exception:
    sys.exit(0)
if isinstance(want, dict) and isinstance(have, dict):
    new = {**want, **have}
elif isinstance(want, list) and isinstance(have, list):
    kept = [e for e in have if e not in retired]
    new = kept + [e for e in want if e not in kept]
else:
    sys.exit(0)
if new != have:
    tmp = dest + ".oz-tmp"
    with open(tmp, "w") as f:
        f.write((header + "\n" if header else "") + json.dumps(new, indent=2) + "\n")
    os.replace(tmp, dest)
"#;

/// The part of a setup script that puts the terminal helpers and settings on the box. What a person already has is kept:
/// their settings and keybindings are merged (never overwritten) and tmux lines are only added when missing.
pub fn terminal_fragment() -> String {
    let tmux = TMUX_LINES
        .iter()
        .map(|l| format!("grep -qxF '{l}' \"$HOME/.tmux.conf\" 2>/dev/null || printf '%s\\n' '{l}' >> \"$HOME/.tmux.conf\"\n"))
        .collect::<String>();
    format!(
        "mkdir -p \"$HOME/.local/bin\" \"$HOME/.config/ozbox/defaults\" \"$HOME/.local/share/code-server/User\" \"$HOME/.vscode-server/data/Machine\"\n\
         cat > \"$HOME/.local/bin/oz-term\" <<'__OZBOX_EOF__'\n{OZ_TERM}__OZBOX_EOF__\n\
         cat > \"$HOME/.local/bin/oz-workspace\" <<'__OZBOX_EOF__'\n{OZ_WORKSPACE}__OZBOX_EOF__\n\
         cat > \"$HOME/.local/bin/oz-merge-json\" <<'__OZBOX_EOF__'\n{OZ_MERGE_JSON}__OZBOX_EOF__\n\
         chmod 0755 \"$HOME/.local/bin/oz-term\" \"$HOME/.local/bin/oz-workspace\" \"$HOME/.local/bin/oz-merge-json\"\n\
         touch \"$HOME/.tmux.conf\"\n\
         {tmux}\
         cat > \"$HOME/.config/ozbox/defaults/settings.json\" <<__OZBOX_EOF__\n{settings}__OZBOX_EOF__\n\
         cat > \"$HOME/.config/ozbox/defaults/keybindings.json\" <<'__OZBOX_EOF__'\n{KEYBINDINGS}__OZBOX_EOF__\n\
         cat > \"$HOME/.config/ozbox/defaults/keybindings-retired.json\" <<'__OZBOX_EOF__'\n{RETIRED_KEYBINDINGS}__OZBOX_EOF__\n\
         merge() {{ if command -v python3 >/dev/null 2>&1; then python3 \"$HOME/.local/bin/oz-merge-json\" \"$@\" || true; else [ -e \"$1\" ] || cp \"$2\" \"$1\"; fi; }}\n\
         merge \"$HOME/.local/share/code-server/User/settings.json\" \"$HOME/.config/ozbox/defaults/settings.json\"\n\
         merge \"$HOME/.vscode-server/data/Machine/settings.json\" \"$HOME/.config/ozbox/defaults/settings.json\"\n\
         merge \"$HOME/.local/share/code-server/User/keybindings.json\" \"$HOME/.config/ozbox/defaults/keybindings.json\" \"$HOME/.config/ozbox/defaults/keybindings-retired.json\"\n\
         \"$HOME/.local/bin/oz-workspace\" || true\n",
        settings = editor_settings("$HOME")
    )
}

impl Service {
    pub fn id(self) -> &'static str {
        match self {
            Service::Ide => "ide",
            Service::Desktop => "desktop",
        }
    }

    /// The loopback port the service listens on, on the box.
    pub fn box_port(self) -> u16 {
        match self {
            Service::Ide => 8443,
            Service::Desktop => 8444,
        }
    }

    /// The program the image installs for it.
    pub fn program(self) -> &'static str {
        match self {
            Service::Ide => "code-server",
            Service::Desktop => "vncserver",
        }
    }

    pub fn unit_name(self) -> &'static str {
        match self {
            Service::Ide => "ozbox-ide.service",
            Service::Desktop => "ozbox-desktop.service",
        }
    }

    /// The user name KasmVNC's own sign-in uses.
    pub const DESKTOP_USER: &'static str = "ozbox";

    /// The write-only secret on this computer that holds the web IDE's tunnel token for one box, so an upgrade (which replaces
    /// the system disk the box's own secrets service lives on) can put the connector back. Never shown, logged or sent anywhere
    /// but the box's own admin helper.
    pub fn connector_secret_name(box_name: &str) -> String {
        format!("ide-tunnel-token-{box_name}")
    }

    /// The write-only secret that holds the service's password for one box.
    pub fn secret_name(self, box_name: &str) -> String {
        format!("{}-password-{box_name}", self.id())
    }
}

// Commands and settings below were checked against the programs' own sources and documentation (2026-11):
// * code-server: `--bind-addr host:port`, `--auth password`, `--reconnection-grace-time <seconds>`, `--disable-telemetry` and
//   `--disable-update-check` are options in https://github.com/coder/code-server/blob/main/src/node/cli.ts ; the sign-in
//   password is read only from the `PASSWORD` environment variable or the config file (never `--password`), which is why it
//   comes from an EnvironmentFile. Grace time: https://coder.com/docs/code-server/faq (default 3 hours).
// * KasmVNC: `vncserver [:N] [-geometry WxH] [-depth 8..32] [-fg]` and `vncserver -kill :N`
//   (https://github.com/kasmtech/KasmVNC/blob/master/unix/vncserver); `vncpasswd -u USER [-r read] [-w write]` reads the
//   password and its confirmation from standard input when it is not a terminal
//   (https://github.com/kasmtech/KasmVNC/blob/master/unix/kasmvncpasswd/kasmvncpasswd.c); the settings file is
//   `~/.vnc/kasmvnc.yaml` with `network.interface`, `network.websocket_port`, `network.ssl.require_ssl` and
//   `data_loss_prevention.clipboard.{server_to_client,client_to_server}.{enabled,size}` (size: `unlimited` or a byte
//   count; checked with `vncserver -dry-run`, which turns them into `-DLP_ClipSendMax` / `-DLP_ClipAcceptMax`)
//   (https://docs.kasmvnc.com/docs/latest/configuration/).
// * VS Code keybindings are read by the editor on the person's own computer, never from the box: over SSH a desktop editor
//   gets only the terminal side (tmux and its settings) from here; the Code panel says so.

/// The text of the service's unit file (a `systemd --user` unit). Pure: nothing is written. Loopback only, and the
/// service's own sign-in on, are pinned by tests.
pub fn unit_text(service: Service) -> String {
    let port = service.box_port();
    match service {
        Service::Ide => format!(
            "\
[Unit]
Description=Oz Box web IDE (code-server, loopback only)
After=network-online.target

[Service]
Type=simple
# The sign-in password lives in a file only the box user can read; it is never in this unit or in a command line.
EnvironmentFile=%h/.config/ozbox/ide.env
# Lists each repository under /work/repos as its own folder of one workspace, so nested and git-ignored repositories are searchable.
ExecStartPre=%h/.local/bin/oz-workspace
# A browser that was closed or lost its connection finds the editor as it left it for a week.
ExecStart=/usr/bin/env code-server --bind-addr 127.0.0.1:{port} --auth password --reconnection-grace-time {GRACE_S} --disable-telemetry --disable-update-check {WORKSPACE_FILE}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"
        ),
        Service::Desktop => String::from(
            "\
[Unit]
Description=Oz Box desktop (KasmVNC, loopback only)
After=network-online.target

[Service]
Type=simple
# Foreground, so the service manager owns the process. The listening address and the sign-in are in ~/.vnc/kasmvnc.yaml
# and ~/.kasmpasswd, written by the setup command.
ExecStart=/usr/bin/env vncserver :1 -fg -geometry 1920x1080 -depth 24
ExecStop=/usr/bin/env vncserver -kill :1
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"
        ),
    }
}

/// The system unit that runs the web IDE's Cloudflare connector as the secrets user, with the token opened from the
/// secrets store (never a file the box user can read, never an argument). The box's first-boot setup installs it with
/// exactly this text, and the admin action that stores the token starts it; a test holds the two together.
pub fn connector_unit_text() -> String {
    String::from(
        "\
[Unit]
Description=Oz Box web IDE tunnel connector (cloudflared as the secrets user)
After=network-online.target ozbox-secrets.service
Wants=network-online.target
ConditionPathExists=/usr/local/bin/ozbox

[Service]
Type=simple
User=ozbox-secrets
Group=ozbox-secrets
Environment=OZBOX_SECRET_STORE=file
Environment=OZBOX_SECRET_FILE=/var/lib/ozbox-secrets/secrets.json
EnvironmentFile=/etc/ozbox/secrets.env
ExecStart=/usr/local/bin/ozbox secrets exec --env TUNNEL_TOKEN=tunnel-token-ide -- /usr/bin/cloudflared tunnel --no-autoupdate run
Restart=on-failure
RestartSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/ozbox-secrets
LimitCORE=0
LockPersonality=true

# Without this `systemctl enable` has nothing to enable, and the connector would not come back after a reboot or an upgrade.
[Install]
WantedBy=multi-user.target
",
    )
}

/// The unit's file name, and where the token is kept (under the box user's home on /work).
pub const CONNECTOR_UNIT: &str = "ozbox-code-connector.service";

/// The user unit and token file an older version made; removed whenever the connector is set up or turned off.
const OLD_CONNECTOR_UNIT: &str = "ozbox-cloudflared.service";

/// A Cloudflare tunnel token is a long base64 text (letters, digits, `+ / = _ -`). Anything else is refused here, so it can
/// never need quoting where it is written.
pub fn token_ok(t: &str) -> bool {
    (20..=2048).contains(&t.len())
        && t.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-' | b'.')
        })
}

/// Most text the desktop's clipboard carries in one copy, each way (KasmVNC cuts anything longer at this size).
pub const DESKTOP_CLIPBOARD_BYTES: u32 = 1_048_576;

/// KasmVNC's settings: plain HTTP on loopback (the SSH forward is the encryption), its own sign-in required. The clipboard
/// goes both ways (the person's computer to the desktop and back), capped at [`DESKTOP_CLIPBOARD_BYTES`] per copy instead of
/// KasmVNC's unlimited default; the X "primary" selection (select-to-copy) is not sent out, so merely selecting text on the
/// desktop never changes the person's clipboard.
pub fn kasmvnc_yaml() -> String {
    format!(
        "\
network:
  interface: 127.0.0.1
  websocket_port: {port}
  ssl:
    require_ssl: false
data_loss_prevention:
  clipboard:
    server_to_client:
      enabled: true
      size: {cap}
      primary_clipboard_enabled: false
    client_to_server:
      enabled: true
      size: {cap}
",
        port = Service::Desktop.box_port(),
        cap = DESKTOP_CLIPBOARD_BYTES,
    )
}

/// The session KasmVNC starts when none is set up: the first desktop the image has.
pub const XSTARTUP: &str = "\
#!/bin/sh
unset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS
if command -v startxfce4 >/dev/null 2>&1; then exec startxfce4; fi
exec x-session-manager
";

/// What the box says about itself, parsed from [`STATUS_SCRIPT`]'s answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct BoxCode {
    /// The box user's services keep running without anyone logged in (`loginctl enable-linger`).
    pub linger: bool,
    /// tmux is on the box, so terminals can outlive their tab.
    pub tmux: bool,
    /// The terminal helpers are written (`oz-term`).
    pub terminals: bool,
    pub ide: ServiceState,
    pub desktop: ServiceState,
    /// The Cloudflare tunnel's connector running on the box as the box user's own service (`ozbox tunnel setup --on-box`).
    pub connector: ServiceState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ServiceState {
    /// The program is on the image.
    pub program: bool,
    /// The unit file is there and is the one this version writes.
    pub unit_current: bool,
    pub active: bool,
}

impl ServiceState {
    /// `running`, `stopped` (set up but not running), `not_set_up` or `unavailable` (the image has no program).
    pub fn label(&self) -> &'static str {
        match (self.program, self.unit_current, self.active) {
            (false, _, _) => "unavailable",
            (true, _, true) => "running",
            (true, true, false) => "stopped",
            (true, false, _) => "not_set_up",
        }
    }
}

impl BoxCode {
    pub fn of(&self, s: Service) -> ServiceState {
        match s {
            Service::Ide => self.ide,
            Service::Desktop => self.desktop,
        }
    }
}

/// Fixed text run on the box (no input from anywhere): what is installed and running. Writes nothing.
pub fn status_script() -> String {
    let mut s = String::from(
        "uid=$(id -u); export XDG_RUNTIME_DIR=/run/user/$uid\n\
         echo linger=$(loginctl show-user \"$(id -un)\" -p Linger --value 2>/dev/null || echo no)\n\
         if command -v tmux >/dev/null 2>&1; then echo tmux=yes; else echo tmux=no; fi\n\
         k=\"$HOME/.config/ozbox/defaults/keybindings.json\"\n",
    );
    // "yes" only when the helpers are there AND the key bindings set up are this version's, so a box set up by an older
    // Oz Box (whose Ctrl+V binding did not paste) is brought up to date the next time its IDE is opened.
    s.push_str(&format!(
        "if [ -x \"$HOME/.local/bin/oz-term\" ] && [ -f \"$k\" ] && [ \"$(sha256sum \"$k\" | cut -d' ' -f1)\" = {want} ]; then echo terminals=yes; else echo terminals=no; fi\n",
        want = sha256_hex(KEYBINDINGS.as_bytes()),
    ));
    for svc in ALL {
        let id = svc.id();
        let want = sha256_hex(unit_text(svc).as_bytes());
        s.push_str(&format!(
            "if command -v {prog} >/dev/null 2>&1; then echo {id}_program=yes; else echo {id}_program=no; fi\n\
             f=\"$HOME/.config/systemd/user/{unit}\"\n\
             if [ -f \"$f\" ] && [ \"$(sha256sum \"$f\" | cut -d' ' -f1)\" = {want} ]; then echo {id}_unit=current; else echo {id}_unit=other; fi\n\
             echo {id}_active=$(systemctl --user is-active {unit} 2>/dev/null || echo inactive)\n",
            prog = svc.program(),
            unit = svc.unit_name(),
        ));
    }
    s.push_str(&format!(
        "if command -v cloudflared >/dev/null 2>&1; then echo connector_program=yes; else echo connector_program=no; fi\n\
         f=/etc/systemd/system/{unit}\n\
         if [ -f \"$f\" ] && [ \"$(sha256sum \"$f\" | cut -d' ' -f1)\" = {want} ]; then echo connector_unit=current; else echo connector_unit=other; fi\n\
         echo connector_active=$(systemctl is-active {unit} 2>/dev/null || echo inactive)\n",
        unit = CONNECTOR_UNIT,
        want = sha256_hex(connector_unit_text().as_bytes()),
    ));
    s
}

pub fn parse_status(out: &str) -> Option<BoxCode> {
    let mut b = BoxCode::default();
    let mut seen = 0;
    for line in out.lines() {
        let Some((k, v)) = line.trim().split_once('=') else {
            continue;
        };
        let v = v.trim();
        let slot = |s: &mut ServiceState, field: &str| match field {
            "program" => s.program = v == "yes",
            "unit" => s.unit_current = v == "current",
            "active" => s.active = v == "active",
            _ => {}
        };
        match k {
            "linger" => {
                b.linger = v == "yes";
                seen += 1;
            }
            "tmux" => {
                b.tmux = v == "yes";
                seen += 1;
            }
            "terminals" => {
                b.terminals = v == "yes";
                seen += 1;
            }
            _ => {
                if let Some(f) = k.strip_prefix("ide_") {
                    slot(&mut b.ide, f);
                    seen += 1;
                } else if let Some(f) = k.strip_prefix("desktop_") {
                    slot(&mut b.desktop, f);
                    seen += 1;
                } else if let Some(f) = k.strip_prefix("connector_") {
                    // additive: a box asked by an older program prints none of these, and is still understood
                    slot(&mut b.connector, f);
                }
            }
        }
    }
    (seen >= 9).then_some(b)
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A password for a service: 32 hex digits from the system's secure random source. Hex, so it needs no quoting
/// anywhere it is written.
pub fn new_password() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| format!("no secure random source: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn password_ok(p: &str) -> bool {
    p.len() >= 16 && p.len() <= 128 && p.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// What to change on the box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Set the service up and start it. The password is written (new, or the stored one).
    Enable { service: Service, password: String },
    /// Stop it and take its unit and password file away.
    Disable { service: Service },
    /// Put the persistent-terminal helpers and editor settings on the box (no service), for editors over SSH.
    Terminals,
    /// Run the Cloudflare tunnel's connector on the box as the box user's own service. The token goes in the file
    /// `~/.config/ozbox/cloudflared.env` (0600), sent on standard input.
    Connector { token: String },
    /// Stop the connector and remove its unit and token file.
    ConnectorOff,
}

impl Change {
    /// The service a change is about (the IDE for the terminal helpers, which it shares).
    pub fn service(&self) -> Service {
        match self {
            Change::Enable { service, .. } | Change::Disable { service } => *service,
            Change::Terminals | Change::Connector { .. } | Change::ConnectorOff => Service::Ide,
        }
    }
}

/// The program text run on the box for a change, given on standard input to `bash -s`. It carries the password (only
/// for an enable); it is the one place a password leaves this computer, and it travels on standard input, never in an
/// argument. Exit codes: 20 the image lacks the program, 21 the box user's services would stop at logout (no linger),
/// 22 the user's service manager did not come up, 23 the service did not start.
pub fn change_script(c: &Change) -> Result<String, String> {
    let mut s = String::from(
        "set -eu\n\
         uid=$(id -u); user=$(id -un)\n\
         export XDG_RUNTIME_DIR=/run/user/$uid\n\
         export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus\n",
    );
    if matches!(c, Change::Terminals) {
        s.push_str(&terminal_fragment());
        s.push_str("echo ok\n");
        return Ok(s);
    }
    if matches!(c, Change::Connector { .. } | Change::ConnectorOff) {
        return connector_script(s, c);
    }
    let svc = c.service();
    s.push_str(&format!(
        "command -v {prog} >/dev/null 2>&1 || {{ echo 'the image has no {prog}' >&2; exit 20; }}\n",
        prog = svc.program()
    ));
    s.push_str(
        "loginctl enable-linger \"$user\" >/dev/null 2>&1 || true\n\
         [ \"$(loginctl show-user \"$user\" -p Linger --value 2>/dev/null)\" = yes ] || { echo 'the box user is not set to keep its services running (loginctl enable-linger)' >&2; exit 21; }\n\
         n=0; while [ ! -S \"$XDG_RUNTIME_DIR/bus\" ] && [ $n -lt 20 ]; do sleep 1; n=$((n+1)); done\n\
         [ -S \"$XDG_RUNTIME_DIR/bus\" ] || { echo 'the box user service manager did not come up' >&2; exit 22; }\n\
         mkdir -p \"$HOME/.config/systemd/user\" \"$HOME/.config/ozbox\"\n",
    );
    let unit = svc.unit_name();
    match c {
        Change::Enable { password, .. } => {
            if !password_ok(password) {
                return Err("the password has an unexpected shape".into());
            }
            s.push_str("umask 077\n");
            match svc {
                Service::Ide => {
                    s.push_str(&format!(
                        "printf 'PASSWORD=%s\\n' '{password}' > \"$HOME/.config/ozbox/ide.env\"\n"
                    ));
                    s.push_str(&terminal_fragment());
                }
                Service::Desktop => s.push_str(&format!(
                    "mkdir -p \"$HOME/.vnc\"\n\
                     cat > \"$HOME/.vnc/kasmvnc.yaml\" <<'__OZBOX_EOF__'\n{yaml}__OZBOX_EOF__\n\
                     if [ ! -f \"$HOME/.vnc/xstartup\" ]; then cat > \"$HOME/.vnc/xstartup\" <<'__OZBOX_EOF__'\n{xs}__OZBOX_EOF__\nchmod 0755 \"$HOME/.vnc/xstartup\"; fi\n\
                     printf '%s\\n%s\\n' '{password}' '{password}' | vncpasswd -u {user} -w -r >/dev/null\n",
                    yaml = kasmvnc_yaml(),
                    xs = XSTARTUP,
                    user = Service::DESKTOP_USER,
                )),
            }
            s.push_str(&format!(
                "cat > \"$HOME/.config/systemd/user/{unit}\" <<'__OZBOX_EOF__'\n{}__OZBOX_EOF__\n\
                 systemctl --user daemon-reload\n\
                 systemctl --user enable {unit} >/dev/null 2>&1\n\
                 systemctl --user restart {unit}\n\
                 n=0; until systemctl --user is-active --quiet {unit}; do n=$((n+1)); [ $n -lt 15 ] || {{ echo 'the service did not start' >&2; exit 23; }}; sleep 1; done\n\
                 echo ok\n",
                unit_text(svc)
            ));
        }
        Change::Terminals | Change::Connector { .. } | Change::ConnectorOff => {}
        Change::Disable { .. } => {
            s.push_str(&format!(
                "systemctl --user disable --now {unit} >/dev/null 2>&1 || true\n\
                 rm -f \"$HOME/.config/systemd/user/{unit}\"\n\
                 systemctl --user daemon-reload\n"
            ));
            match svc {
                Service::Ide => s.push_str("rm -f \"$HOME/.config/ozbox/ide.env\"\n"),
                Service::Desktop => s.push_str("rm -f \"$HOME/.kasmpasswd\"\n"),
            }
            s.push_str("echo ok\n");
        }
    }
    Ok(s)
}

/// The connector's part of [`change_script`]: same preamble. The token is handed to the box's root helper, which stores it
/// in the secrets store and starts the connector as the secrets user; this script never leaves it in a file.
fn connector_script(mut s: String, c: &Change) -> Result<String, String> {
    let old = OLD_CONNECTOR_UNIT;
    if let Change::Connector { token } = c {
        if !token_ok(token) {
            return Err("the tunnel token has an unexpected shape".into());
        }
        s.push_str(
            "command -v cloudflared >/dev/null 2>&1 || { echo 'the image has no cloudflared' >&2; exit 20; }\n\
             [ -x /usr/local/bin/ozbox-admin-request ] || { echo 'this box has no admin helper' >&2; exit 20; }\n",
        );
        s.push_str(&format!(
            "umask 077\n\
             tid=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \\n')\n\
             printf '%s\\n' '{token}' > \"/run/ozbox-admin/requests/$tid.tok\"\n\
             /usr/local/bin/ozbox-admin-request replace-tunnel-token ide \"$tid\" >/dev/null || {{ rm -f \"/run/ozbox-admin/requests/$tid.tok\"; echo 'the service did not start' >&2; exit 23; }}\n\
             rm -f \"/run/ozbox-admin/requests/$tid.tok\"\n\
             export XDG_RUNTIME_DIR=/run/user/$uid\n\
             systemctl --user disable --now {old} >/dev/null 2>&1 || true\n\
             rm -f \"$HOME/.config/systemd/user/{old}\" \"$HOME/.config/ozbox/cloudflared.env\"\n\
             n=0; until systemctl is-active --quiet {unit}; do n=$((n+1)); [ $n -lt 15 ] || {{ echo 'the service did not start' >&2; exit 23; }}; sleep 1; done\n\
             echo ok\n",
            unit = CONNECTOR_UNIT,
        ));
    } else {
        s.push_str(&format!(
            "[ -x /usr/local/bin/ozbox-admin-request ] && /usr/local/bin/ozbox-admin-request clear-tunnel-token ide >/dev/null || true\n\
             systemctl --user disable --now {old} >/dev/null 2>&1 || true\n\
             rm -f \"$HOME/.config/systemd/user/{old}\" \"$HOME/.config/ozbox/cloudflared.env\"\n\
             echo ok\n"
        ));
    }
    Ok(s)
}

/// Why a change failed, from the setup command's exit status.
pub fn failure_key(status: Option<i32>) -> &'static str {
    match status {
        Some(20) => "code.err_no_program",
        Some(21) => "code.err_no_linger",
        Some(22) => "code.err_no_user_manager",
        Some(23) => "code.err_not_started",
        _ => "code.err_setup_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_listen_on_loopback_only_and_keep_the_services_own_sign_in_on() {
        let ide = unit_text(Service::Ide);
        assert!(ide.contains("--bind-addr 127.0.0.1:8443"));
        assert!(ide.contains("--auth password"));
        assert!(!ide.contains("--auth none"));
        assert!(!ide.contains("0.0.0.0"));
        assert!(
            !ide.contains("PASSWORD="),
            "the password is in a file, not here"
        );
        assert!(ide.contains("EnvironmentFile=%h/.config/ozbox/ide.env"));
        assert!(ide.contains(REPOS_DIR));
        let desk = unit_text(Service::Desktop);
        assert!(!desk.contains("0.0.0.0") && !desk.contains("-disableBasicAuth"));
        let yaml = kasmvnc_yaml();
        assert!(yaml.contains("interface: 127.0.0.1") && yaml.contains("websocket_port: 8444"));
        assert!(!yaml.contains("0.0.0.0"));
        // the clipboard goes both ways, capped, and selecting text on the desktop alone never reaches the person's clipboard
        assert_eq!(yaml.matches("enabled: true").count(), 2, "{yaml}");
        assert_eq!(yaml.matches("size: 1048576").count(), 2, "{yaml}");
        assert!(yaml.contains("primary_clipboard_enabled: false") && !yaml.contains("unlimited"));
    }

    #[test]
    fn the_status_answer_is_read_and_a_partial_answer_is_not_trusted() {
        let out = "linger=yes\ntmux=yes\nterminals=no\nide_program=yes\nide_unit=current\nide_active=active\n\
                   desktop_program=yes\ndesktop_unit=other\ndesktop_active=inactive\n";
        let b = parse_status(out).unwrap();
        assert!(b.linger && b.tmux && !b.terminals);
        assert_eq!(b.ide.label(), "running");
        assert_eq!(b.desktop.label(), "not_set_up");
        assert!(parse_status("linger=yes\n").is_none());
        let none = parse_status(
            "linger=no\ntmux=no\nterminals=no\nide_program=no\nide_unit=other\nide_active=inactive\ndesktop_program=yes\ndesktop_unit=current\ndesktop_active=inactive\n",
        )
        .unwrap();
        assert_eq!(none.ide.label(), "unavailable");
        assert_eq!(none.desktop.label(), "stopped");
        assert!(!none.linger);
    }

    #[test]
    fn the_status_script_writes_nothing_and_names_the_units_it_expects() {
        let s = status_script();
        for bad in [" > ", "rm ", "systemctl --user start", "enable", "mkdir"] {
            assert!(!s.contains(bad), "{bad}");
        }
        assert!(s.contains(&sha256_hex(unit_text(Service::Ide).as_bytes())));
    }

    #[test]
    fn an_enable_script_carries_the_password_once_and_a_disable_script_never() {
        let pw = new_password().unwrap();
        assert_eq!(pw.len(), 32);
        for svc in ALL {
            let on = change_script(&Change::Enable {
                service: svc,
                password: pw.clone(),
            })
            .unwrap();
            assert!(on.contains(&pw));
            assert!(on.contains("enable-linger"));
            assert!(on.contains(&unit_text(svc)));
            assert!(on.contains("exit 21") && on.contains("exit 22") && on.contains("exit 23"));
            let off = change_script(&Change::Disable { service: svc }).unwrap();
            assert!(!off.contains(&pw));
            assert!(off.contains("disable --now"));
        }
    }

    #[test]
    fn a_password_that_needs_quoting_is_refused() {
        for bad in [
            "short",
            "has space has space has space",
            "quote'quote'quote'quote",
            "semi;colon;semi;colon;",
        ] {
            assert!(change_script(&Change::Enable {
                service: Service::Ide,
                password: bad.into()
            })
            .is_err());
        }
    }

    fn sh(script: &str, dir: &std::path::Path, env: &[(&str, &str)]) -> (i32, String) {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(script).current_dir(dir).env("HOME", dir);
        for (k, v) in env {
            c.env(k, v);
        }
        let o = c.output().unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
        )
    }

    /// A tmux that keeps its sessions in a file, enough for what `oz-term` asks of it.
    const FAKE_TMUX: &str = "#!/bin/sh
f=\"$STATE\"; touch \"$f\"
case \"$1\" in
  list-sessions) cat \"$f\" ;;
  has-session) grep -q \"^$3 \" \"$f\" ;;
  attach-session) sed -i.bak \"s/^$3 .*/$3 1/\" \"$f\"; echo \"attached $3\" ;;
  new-session) echo \"$3 1\" >> \"$f\"; echo \"new $3\" ;;
esac
";

    #[test]
    fn a_terminal_reattaches_to_the_session_it_left_and_only_makes_a_new_one_when_all_are_in_use() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::write(bin.join("tmux"), FAKE_TMUX).unwrap();
        std::fs::write(d.path().join("oz-term"), OZ_TERM).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let state = d.path().join("state");
        let run = || {
            let (code, out) = sh(
                &format!(
                    "chmod +x {0}/tmux; sh {1}/oz-term",
                    bin.display(),
                    d.path().display()
                ),
                d.path(),
                &[("PATH", &path), ("STATE", state.to_str().unwrap())],
            );
            assert_eq!(code, 0, "{out}");
            out.trim().to_string()
        };
        let detach = |name: &str| {
            let t = std::fs::read_to_string(&state).unwrap();
            std::fs::write(
                &state,
                t.replace(&format!("{name} 1"), &format!("{name} 0")),
            )
            .unwrap();
        };
        assert_eq!(run(), "new term-1");
        // the tab or the whole client goes away: the session stays, unattached; the next terminal gets it back
        detach("term-1");
        assert_eq!(run(), "attached term-1");
        // a second terminal while the first is in use is a new one
        assert_eq!(run(), "new term-2");
        detach("term-1");
        detach("term-2");
        assert_eq!(run(), "attached term-1", "the first unattached one");
    }

    #[test]
    fn without_tmux_a_terminal_is_a_plain_login_shell_and_never_fails() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("oz-term"), OZ_TERM).unwrap();
        std::fs::write(d.path().join("fakeshell"), "#!/bin/sh\necho plain-shell\n").unwrap();
        let (code, out) = sh(
            &format!(
                "chmod +x {0}/fakeshell; SHELL={0}/fakeshell /bin/sh {0}/oz-term",
                d.path().display()
            ),
            d.path(),
            &[("PATH", "/usr/bin:/bin")],
        );
        // (a machine that has tmux in /usr/bin makes this a real attach: only a plain shell is asserted when it has none)
        if std::process::Command::new("sh")
            .args(["-c", "command -v tmux"])
            .env("PATH", "/usr/bin:/bin")
            .output()
            .is_ok_and(|o| !o.status.success())
        {
            assert_eq!((code, out.trim()), (0, "plain-shell"));
        }
    }

    #[test]
    fn the_workspace_lists_each_plain_named_repository_as_a_folder() {
        let d = tempfile::tempdir().unwrap();
        let repos = d.path().join("repos");
        for r in ["alpha", "beta-2", "has space", "ok.dir"] {
            std::fs::create_dir_all(repos.join(r).join(".git")).unwrap();
        }
        std::fs::write(repos.join("a-file"), "x").unwrap();
        std::fs::write(d.path().join("ws"), OZ_WORKSPACE).unwrap();
        let (code, _) = sh(
            &format!("sh {}/ws", d.path().display()),
            d.path(),
            &[("OZ_REPOS", repos.to_str().unwrap())],
        );
        assert_eq!(code, 0);
        let text = std::fs::read_to_string(repos.join("oz.code-workspace")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let paths: Vec<&str> = v["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["alpha", "beta-2", "ok.dir"], "{text}");
    }

    #[test]
    fn the_terminal_settings_make_tmux_the_default_and_a_persons_own_keys_are_never_dropped() {
        let v: serde_json::Value =
            serde_json::from_str(&editor_settings("/work/home/ozbox")).unwrap();
        assert_eq!(v["terminal.integrated.defaultProfile.linux"], "oz-term");
        assert_eq!(
            v["terminal.integrated.profiles.linux"]["oz-term"]["path"],
            "/work/home/ozbox/.local/bin/oz-term"
        );
        assert!(v["terminal.integrated.profiles.linux"]
            .get("bash (ends with the tab)")
            .is_some());
        for (k, want) in [
            (
                "terminal.integrated.enablePersistentSessions",
                serde_json::json!(true),
            ),
            (
                "terminal.integrated.persistentSessionReviveProcess",
                "onExitAndWindowClose".into(),
            ),
            ("window.restoreWindows", "all".into()),
            ("files.hotExit", "onExitAndWindowClose".into()),
            (
                "terminal.integrated.macOptionClickForcesSelection",
                serde_json::json!(true),
            ),
            ("terminal.integrated.rightClickBehavior", "copyPaste".into()),
        ] {
            assert_eq!(v[k], want, "{k}");
        }
        // an empty home gets everything
        let d = tempfile::tempdir().unwrap();
        let (code, out) = sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(code, 0, "{out}");
        let user = d.path().join(".local/share/code-server/User");
        let home = d.path().display().to_string();
        let written = std::fs::read_to_string(user.join("settings.json")).unwrap();
        assert!(
            written.contains(&format!("{home}/.local/bin/oz-term")),
            "{written}"
        );
        assert!(d
            .path()
            .join(".vscode-server/data/Machine/settings.json")
            .exists());
        let kb: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(user.join("keybindings.json")).unwrap())
                .unwrap();
        assert_eq!(kb.as_array().unwrap().len(), 5);
        // a person's own files: their keys and entries stay, ours are added, and a second run changes nothing
        std::fs::write(
            user.join("settings.json"),
            r#"{ "editor.fontSize": 18, "files.hotExit": "off", "terminal.integrated.rightClickBehavior": "default" }"#,
        )
        .unwrap();
        // theirs: one of their own, one that is the same as ours, and the Ctrl+V removal an earlier Oz Box wrote
        let mine_kb = r#"[ { "key": "ctrl+k", "command": "mine.command" }, { "key": "cmd+v", "command": "-workbench.action.terminal.paste", "when": "terminalFocus" }, { "key": "ctrl+v", "command": "-workbench.action.terminal.paste", "when": "terminalFocus" } ]"#;
        std::fs::write(user.join("keybindings.json"), mine_kb).unwrap();
        sh(&terminal_fragment(), d.path(), &[]);
        let s: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(user.join("settings.json")).unwrap())
                .unwrap();
        assert_eq!(s["editor.fontSize"], 18);
        assert_eq!(s["files.hotExit"], "off", "their value wins");
        assert_eq!(s["terminal.integrated.rightClickBehavior"], "default");
        assert_eq!(
            s["terminal.integrated.defaultProfile.linux"], "oz-term",
            "what they lacked was added"
        );
        let k: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(user.join("keybindings.json")).unwrap())
                .unwrap();
        let k = k.as_array().unwrap();
        assert!(k.iter().any(|e| e["command"] == "mine.command"));
        assert!(
            !k.iter().any(|e| e["key"] == "ctrl+v"
                && e["command"] == "-workbench.action.terminal.paste"),
            "the retired Ctrl+V removal is taken back"
        );
        assert_eq!(
            k.len(),
            6,
            "their own one, plus all five of ours (one of which they had), none twice"
        );
        let before = (
            std::fs::read(user.join("settings.json")).unwrap(),
            std::fs::read(user.join("keybindings.json")).unwrap(),
        );
        sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(
            before,
            (
                std::fs::read(user.join("settings.json")).unwrap(),
                std::fs::read(user.join("keybindings.json")).unwrap()
            )
        );
        // a file with comments is not plain JSON: left exactly as it is
        let commented = "{ // mine\n  \"a\": 1 }\n";
        std::fs::write(user.join("settings.json"), commented).unwrap();
        sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(
            std::fs::read_to_string(user.join("settings.json")).unwrap(),
            commented
        );
    }

    /// The keymap the IDE's terminal ends up with on each computer, worked out the way the editor does: its own defaults
    /// (as shipped in the editor this was checked against), then ours on top. `os` is "mac", "windows" or "linux".
    fn terminal_keymap(os: &str) -> Vec<(String, String, String)> {
        // (key, command, when) for the defaults that matter here
        let mut map: Vec<(String, String, String)> = match os {
            "mac" => vec![
                (
                    "cmd+c",
                    "workbench.action.terminal.copySelection",
                    "terminalTextSelected",
                ),
                ("cmd+v", "workbench.action.terminal.paste", "terminalFocus"),
            ],
            "windows" => vec![
                (
                    "ctrl+c",
                    "workbench.action.terminal.copyAndClearSelection",
                    "terminalTextSelected",
                ),
                (
                    "ctrl+shift+c",
                    "workbench.action.terminal.copySelection",
                    "terminalTextSelected",
                ),
                ("ctrl+v", "workbench.action.terminal.paste", "terminalFocus"),
                (
                    "ctrl+shift+v",
                    "workbench.action.terminal.paste",
                    "terminalFocus",
                ),
            ],
            _ => vec![
                (
                    "ctrl+shift+c",
                    "workbench.action.terminal.copySelection",
                    "terminalTextSelected",
                ),
                (
                    "ctrl+shift+v",
                    "workbench.action.terminal.paste",
                    "terminalFocus",
                ),
                (
                    "shift+insert",
                    "workbench.action.terminal.pasteSelection",
                    "terminalFocus",
                ),
            ],
        }
        .into_iter()
        .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
        .collect();
        let ours: serde_json::Value = serde_json::from_str(KEYBINDINGS).unwrap();
        for e in ours.as_array().unwrap() {
            let key = e["key"].as_str().unwrap().to_string();
            let cmd = e["command"].as_str().unwrap();
            let when = e["when"].as_str().unwrap_or("");
            // the platform guard is the visitor's computer
            let applies = (!when.contains("isLinux") || os == "linux")
                && (!when.contains("isMac") || os == "mac");
            if !applies {
                continue;
            }
            if let Some(gone) = cmd.strip_prefix('-') {
                map.retain(|(k, c, _)| !(k == &key && c == gone));
            } else {
                map.push((key, cmd.to_string(), when.to_string()));
            }
        }
        map
    }

    fn bound(map: &[(String, String, String)], key: &str) -> Option<String> {
        map.iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, c, _)| c.clone())
    }

    #[test]
    fn one_keymap_per_computer_copies_pastes_and_still_interrupts() {
        // macOS: Cmd copies and pastes (the paste is the browser's own, no permission), Ctrl+C is always the interrupt
        let mac = terminal_keymap("mac");
        assert_eq!(
            bound(&mac, "cmd+c").as_deref(),
            Some("workbench.action.terminal.copySelection")
        );
        assert_eq!(bound(&mac, "cmd+v"), None, "the browser's own paste");
        assert_eq!(bound(&mac, "ctrl+c"), None, "always reaches the shell");
        assert_eq!(bound(&mac, "ctrl+v"), None);
        for os in ["windows", "linux"] {
            let m = terminal_keymap(os);
            // Ctrl+C copies only while text is selected; otherwise it reaches the shell as the interrupt
            let (_, cmd, when) = m.iter().find(|(k, _, _)| k == "ctrl+c").unwrap();
            assert_eq!(
                cmd, "workbench.action.terminal.copyAndClearSelection",
                "{os}"
            );
            assert!(when.contains("terminalTextSelected"), "{os}: {when}");
            // Ctrl+V must stay on the editor's paste: let through, the terminal would send ^V (the regression this fixes)
            assert_eq!(
                bound(&m, "ctrl+v").as_deref(),
                Some("workbench.action.terminal.paste"),
                "{os}"
            );
            assert_eq!(
                bound(&m, "ctrl+shift+v"),
                None,
                "{os}: the browser's own paste"
            );
            assert_eq!(
                bound(&m, "ctrl+shift+c").as_deref(),
                Some("workbench.action.terminal.copySelection"),
                "{os}"
            );
        }
        assert_eq!(bound(&terminal_keymap("linux"), "shift+insert"), None);
        // what was taken back is not shipped again
        let retired: serde_json::Value = serde_json::from_str(RETIRED_KEYBINDINGS).unwrap();
        let ours: serde_json::Value = serde_json::from_str(KEYBINDINGS).unwrap();
        for r in retired.as_array().unwrap() {
            assert!(!ours.as_array().unwrap().contains(r), "{r}");
        }
    }

    #[test]
    fn the_terminals_are_current_only_with_this_versions_key_bindings() {
        let d = tempfile::tempdir().unwrap();
        let said = |d: &std::path::Path| {
            let (_, out) = sh(&status_script(), d, &[]);
            out.lines()
                .find(|l| l.starts_with("terminals="))
                .unwrap_or("")
                .to_string()
        };
        assert_eq!(said(d.path()), "terminals=no");
        let (code, out) = sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(said(d.path()), "terminals=yes");
        // what an older Oz Box left: the helpers, with the earlier key bindings
        std::fs::write(
            d.path().join(".config/ozbox/defaults/keybindings.json"),
            RETIRED_KEYBINDINGS,
        )
        .unwrap();
        assert_eq!(said(d.path()), "terminals=no");
    }

    #[test]
    fn a_comment_header_is_kept_and_comments_anywhere_else_leave_the_file_alone() {
        let d = tempfile::tempdir().unwrap();
        let user = d.path().join(".local/share/code-server/User");
        std::fs::create_dir_all(&user).unwrap();
        // what the editor writes at the top of a new keybindings file, plus the line an earlier Oz Box added
        let headed = "// Place your key bindings in this file to override the defaults\n[\n  { \"key\": \"ctrl+v\", \"command\": \"-workbench.action.terminal.paste\", \"when\": \"terminalFocus\" },\n  { \"key\": \"f5\", \"command\": \"mine\" }\n]\n";
        std::fs::write(user.join("keybindings.json"), headed).unwrap();
        let (code, out) = sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(code, 0, "{out}");
        let got = std::fs::read_to_string(user.join("keybindings.json")).unwrap();
        assert!(got.starts_with("// Place your key bindings"), "{got}");
        let body: serde_json::Value =
            serde_json::from_str(got.split_once('\n').unwrap().1).unwrap();
        let body = body.as_array().unwrap();
        assert!(body.iter().any(|e| e["command"] == "mine"));
        assert!(!body
            .iter()
            .any(|e| e["key"] == "ctrl+v" && e["command"] == "-workbench.action.terminal.paste"));
        assert_eq!(body.len(), 6);
        // a comment inside the list cannot be kept by a rewrite, so the file is left exactly as it is
        let inner = "[\n  // mine\n  { \"key\": \"f5\", \"command\": \"mine\" }\n]\n";
        std::fs::write(user.join("keybindings.json"), inner).unwrap();
        sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(
            std::fs::read_to_string(user.join("keybindings.json")).unwrap(),
            inner
        );
    }

    #[test]
    fn tmux_lines_are_added_once_to_a_persons_own_file_and_never_twice() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join(".tmux.conf"),
            "# mine\nset -g mouse on\nbind r source-file ~/.tmux.conf\n",
        )
        .unwrap();
        sh(&terminal_fragment(), d.path(), &[]);
        let once = std::fs::read_to_string(d.path().join(".tmux.conf")).unwrap();
        assert!(
            once.starts_with("# mine\nset -g mouse on\nbind r source-file"),
            "{once}"
        );
        for l in TMUX_LINES {
            assert_eq!(once.lines().filter(|x| *x == l).count(), 1, "{l}");
        }
        assert!(
            once.contains("set -g default-terminal \"tmux-256color\"")
                && once.contains("set -g set-clipboard on")
                && once.contains("history-limit 100000")
        );
        // copies leave through OSC 52 (also through an outer tmux), and nothing inside may talk to the outer terminal unfiltered
        assert!(once.contains("set -as terminal-features \",screen*:clipboard,tmux*:clipboard\""));
        assert!(!once.contains("allow-passthrough") && !once.contains("set-clipboard off"));
        sh(&terminal_fragment(), d.path(), &[]);
        assert_eq!(
            std::fs::read_to_string(d.path().join(".tmux.conf")).unwrap(),
            once,
            "a second run changes nothing"
        );
    }

    #[test]
    fn the_ide_unit_keeps_a_week_of_reconnection_and_opens_the_workspace_and_an_enable_installs_the_helpers(
    ) {
        let u = unit_text(Service::Ide);
        assert!(u.contains("--reconnection-grace-time 604800"));
        assert!(u.contains(&format!("{WORKSPACE_FILE}\n")));
        assert!(u.contains("ExecStartPre=%h/.local/bin/oz-workspace"));
        assert!(
            u.contains("WantedBy=default.target"),
            "starts again after a reboot"
        );
        let on = change_script(&Change::Enable {
            service: Service::Ide,
            password: "a".repeat(32),
        })
        .unwrap();
        assert!(on.contains("oz-term") && on.contains(".tmux.conf"));
        let t = change_script(&Change::Terminals).unwrap();
        assert!(t.contains("oz-term") && !t.contains("enable-linger") && !t.contains("systemctl"));
        assert!(!change_script(&Change::Enable {
            service: Service::Desktop,
            password: "a".repeat(32)
        })
        .unwrap()
        .contains("oz-term"));
    }

    #[test]
    fn exit_statuses_map_to_the_fix() {
        assert_eq!(failure_key(Some(21)), "code.err_no_linger");
        assert_eq!(failure_key(Some(1)), "code.err_setup_failed");
        for k in [
            "code.err_no_program",
            "code.err_no_linger",
            "code.err_no_user_manager",
            "code.err_not_started",
            "code.err_setup_failed",
        ] {
            assert!(crate::messages::keys().contains(&k), "{k}");
        }
    }

    #[test]
    fn the_connector_token_goes_to_the_root_helper_and_is_left_in_no_file_or_unit() {
        let token = "abcdabcdabcdabcdabcdabcd";
        let s = change_script(&Change::Connector {
            token: token.into(),
        })
        .unwrap();
        // the token appears once, in the line that hands it over, through a private file the helper takes and removes
        assert_eq!(s.matches(token).count(), 1);
        assert!(s.contains("umask 077") && s.contains("replace-tunnel-token ide"));
        assert!(!s.contains("cloudflared.env\" ||") && !s.contains("TUNNEL_TOKEN"));
        // the old user unit and token file are removed once the new one is in
        assert!(s.contains("rm -f \"$HOME/.config/systemd/user/ozbox-cloudflared.service\" \"$HOME/.config/ozbox/cloudflared.env\""));
        assert!(s.contains("exit 20") && s.contains("exit 23"));
        assert!(!s.contains("sudo") && !s.contains("runuser"));
        let unit = connector_unit_text();
        assert!(!unit.contains(token) && !unit.contains("--token"));
        assert!(
            unit.contains("User=ozbox-secrets")
                && unit.contains("secrets exec --env TUNNEL_TOKEN=tunnel-token-ide")
        );
        assert!(!unit.contains("%h") && !unit.contains("default.target"));
        // the box installs exactly this unit text at first boot
        let setup = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../infra/cloud-init/scripts/ozbox-secrets-setup.sh"),
        )
        .unwrap();
        let start =
            setup.find("<<'EOF_CODE_CONNECTOR'\n").unwrap() + "<<'EOF_CODE_CONNECTOR'\n".len();
        let end = setup.find("\nEOF_CODE_CONNECTOR\n").unwrap() + 1;
        assert_eq!(&setup[start..end], unit);
        // every shape of token that could need quoting is refused before a script exists
        for bad in [
            "",
            "short",
            "a'b a'b a'b a'b a'b a'b",
            "ab cd ab cd ab cd ab cd ab cd",
            "x;rm -rf ~ x;rm -rf ~ x",
            "a\nb a b a b a b a b a b",
        ] {
            assert!(
                change_script(&Change::Connector { token: bad.into() }).is_err(),
                "{bad}"
            );
        }
        let off = change_script(&Change::ConnectorOff).unwrap();
        assert!(off.contains("clear-tunnel-token ide") && off.contains("cloudflared.env"));
        assert!(!off.contains("TUNNEL_TOKEN"));
    }

    #[test]
    fn the_connector_is_part_of_the_status_and_an_older_answer_without_it_is_still_understood() {
        assert!(
            status_script().contains("connector_active=")
                && status_script().contains(CONNECTOR_UNIT)
        );
        let old = "linger=yes\ntmux=yes\nterminals=yes\nide_program=yes\nide_unit=current\nide_active=active\ndesktop_program=yes\ndesktop_unit=other\ndesktop_active=inactive\n";
        assert_eq!(
            parse_status(old).unwrap().connector,
            ServiceState::default()
        );
        let new = format!(
            "{old}connector_program=yes\nconnector_unit=current\nconnector_active=active\n"
        );
        let c = parse_status(&new).unwrap().connector;
        assert!(c.program && c.unit_current && c.active);
    }
}
