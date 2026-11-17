#!/usr/bin/env bash
# Gives the dashboard (the supervisor) a user of its own (ADR 0023). Run as root, at first boot and by the root helper's
# ensure-supervisor action. Safe to run again, and safe on a box with agent sessions running: those are the box user's tmux
# sessions and the box daemon's, and are not touched. Only the dashboard restarts (a few seconds without the web page).
#
#   (no argument)   make the user and its private home, move the dashboard to a system unit that runs as it
#   --expect-auth SHA256
#                   the same, refusing unless the staged sign-in settings are exactly the ones the person's computer sent
#                   (`ozbox dashboard install` passes their sha256): the box user could have changed the file in between.
#                   Those settings are installed when this is the first move, or when the dashboard's own folder has no
#                   sign-in settings (a box whose system disk was replaced by an upgrade keeps that folder on /work). A
#                   dashboard that already HAS settings keeps them: the sha proves the file is what the person's computer
#                   sent, not that the person asked, and this request comes from the box user, so replacing settings that
#                   decide who may approve needs an approval this step cannot take.
#   --replace-auth SHA256
#                   the same as --expect-auth, and the staged settings REPLACE the ones the dashboard already has. Only the
#                   root helper's `replace-dashboard-auth` runs this, and only after the secrets service accepted a single-use
#                   approval bound to this sha256 (a passkey, an authenticator code or the laptop's pinned key). The old
#                   settings are kept beside them (auth.toml.replaced) for one step back.
#   --socket-only   make the supervisor user and the dashboard's socket to the box daemon (below) and stop: nothing about the
#                   dashboard itself is touched (a box that upgraded its program or daemon runs this)
#   --finish        after the dashboard has been seen working as the supervisor, destroy the old copies the box user could read
#
# The old way ran `ozbox serve` as the box user from a user unit, with its program, settings and state under the box user's
# home, so every agent could read the dashboard's sign-in state and shared a uid with the process that issues run tokens.
# The new unit runs the root-owned /usr/local/bin/ozbox as ozbox-supervisor, with everything it keeps in a folder only that
# user can open. The old user unit is disabled and left (renamed) so a rollback is `--rollback`.
#
# The dashboard's address (port, host, tunnel kind) is also kept in a folder ROOT owns on /work (ozbox-supervisor-keep), because an
# upgrade replaces the system disk and with it the unit, while /work and the supervisor's folder stay. First boot and
# `ensure-supervisor` then make the unit again from that record: never from a file the box user can write, and never over
# settings the person did not approve.
#
# Environment (for tests): OZBOX_ETC, OZBOX_WORK, OZBOX_SYSTEMD_DIR, OZBOX_SYSTEMCTL, OZBOX_USERADD, OZBOX_USERMOD,
# OZBOX_PASSWD, OZBOX_ID, OZBOX_CHOWN, OZBOX_RUNUSER, OZBOX_SHRED, OZBOX_BIN, OZBOX_GPASSWD, OZBOX_DAEMON_BIN, OZBOX_JOURNALCTL,
# OZBOX_DASHBOARD_PROBE (a program that is given the port and succeeds when the dashboard answers), OZBOX_DASHBOARD_PROBE_S,
# OZBOX_SYSTEMD_RUN, OZBOX_RETRY_DELAYS (the pauses between tries of the agent settings step, in seconds).
set -euo pipefail

etc="${OZBOX_ETC:-/etc}"
work="${OZBOX_WORK:-/work}"
unitdir="${OZBOX_SYSTEMD_DIR:-/etc/systemd/system}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
# How long a restarted dashboard is given before it is asked whether it is running (seconds); the tests make it short. It
# must be LONGER than the unit's RestartSec (5): a dashboard that dies at once is then restarted by systemd before it is
# asked, and the check below sees that through the restart counter instead of relying on catching it between two starts.
# A test pins the two together.
settle_s="${OZBOX_DASHBOARD_SETTLE_S:-8}"
useradd_bin="${OZBOX_USERADD:-useradd}"
usermod_bin="${OZBOX_USERMOD:-usermod}"
id_bin="${OZBOX_ID:-id}"
chown_bin="${OZBOX_CHOWN:-chown}"
runuser_bin="${OZBOX_RUNUSER:-runuser}"
systemd_run_bin="${OZBOX_SYSTEMD_RUN:-systemd-run}"
retry_delays="${OZBOX_RETRY_DELAYS:-2 4 8}"
shred_bin="${OZBOX_SHRED:-shred}"
gpasswd_bin="${OZBOX_GPASSWD:-gpasswd}"
ozbox_bin="${OZBOX_BIN:-/usr/local/bin/ozbox}"
daemon_bin="${OZBOX_DAEMON_BIN:-/usr/local/bin/ozboxd}"
journalctl_bin="${OZBOX_JOURNALCTL:-journalctl}"
# After a start the dashboard must answer on its port within this many seconds (the tests make it short)
probe_s="${OZBOX_DASHBOARD_PROBE_S:-20}"

sup=ozbox-supervisor
home="$work/ozbox-supervisor"
# Root's own record of the dashboard's address. Not under $home: the supervisor owns that folder and could replace any file in
# it. The folder is 0711 so the box user's self-test can see that a dashboard was installed (the marker is empty); the record is 0600.
keep="$work/ozbox-supervisor-keep"
old_home="$work/home/ozbox/ozbox-dashboard"
old_unit="$work/home/ozbox/.config/systemd/user/ozbox-dashboard.service"
new_unit="$unitdir/ozbox-dashboard.service"
sock=/run/ozbox-secrets/supervisor/supervisor.sock
left_group=no
restart_dashboard=no
replace_auth=no
kept_settings=no
settings_state=unchanged

say() { printf 'ozbox-supervisor-setup: %s\n' "$*"; }
box_uid() { "$id_bin" -u ozbox 2>/dev/null || echo 0; }
user_systemctl() {
  "$runuser_bin" -u ozbox -- env "XDG_RUNTIME_DIR=/run/user/$(box_uid)" systemctl --user "$@" 2>/dev/null
}

ensure_user() {
  if ! "$id_bin" "$sup" >/dev/null 2>&1; then
    # No group of the box user's: the dashboard reaches the box daemon through a socket of its own (ensure_scoped_socket) and
    # the secrets service through the supervisor's own folder, so it shares nothing with the box user or its agents.
    "$useradd_bin" --system --user-group --home-dir "$home/home" --no-create-home \
      --shell /usr/sbin/nologin --comment "Oz Box supervisor" "$sup"
    "${OZBOX_PASSWD:-passwd}" --lock "$sup" >/dev/null 2>&1 || true
  fi
  # A box moved by an earlier version put the supervisor in the box user's group: take it out. A running dashboard keeps the
  # group it started with, so it is restarted (below) when this removed one.
  if "$id_bin" -nG "$sup" 2>/dev/null | tr ' ' '\n' | grep -qx ozbox; then
    "$gpasswd_bin" -d "$sup" ozbox >/dev/null 2>&1 || say "could not take $sup out of the box user's group; run: gpasswd -d $sup ozbox"
    left_group=yes
  fi
  # The earlier unit also named the box user's group (`SupplementaryGroups=ozbox`), which systemd grants at every start whatever
  # /etc/group says: drop that line from an existing unit too, so the restart below really takes the group away (G1 N2).
  if [ -f "$new_unit" ] && grep -q '^SupplementaryGroups=' "$new_unit"; then
    grep -v '^SupplementaryGroups=' "$new_unit" >"$new_unit.tmp" && chmod 0644 "$new_unit.tmp" && mv -f "$new_unit.tmp" "$new_unit"
    "$systemctl_bin" daemon-reload
    left_group=yes
  fi
  mkdir -p "$home/state" "$home/home"
  "$chown_bin" "$sup:$sup" "$home" "$home/state" "$home/home"
  chmod 0700 "$home" "$home/state" "$home/home"
  # A kept folder whose owner id differs from this user's (a user made again after an upgrade gets a new id) would leave the
  # dashboard unable to read or write its own files ("Permission denied" on its memory and skills). EVERYTHING under it is put back
  # under this user at every run, not only at the first move, and nothing in it is readable by anyone else. `-h` and no `-L`:
  # a link in there is changed as a link and never followed, so a link the supervisor (or anything else) left cannot point root's
  # `chown` at a file elsewhere.
  "$chown_bin" -R -h "$sup:$sup" "$home" || say "could not put everything under $home back under $sup; the dashboard may report 'Permission denied' for its files (run: chown -R -h $sup:$sup $home)"
  chmod -R go-rwx "$home" 2>/dev/null || true
  record_folder_state
  drop_box_user_ssh_config
  ensure_scoped_socket
}

# After the repair above (and after a first move): count what under the dashboard's folder is still not its user's own, or is open
# to anyone else, and keep the answer in root's folder, where the box user's self-test reads it (the dashboard's folder is closed
# to the box user, so the self-test cannot look itself). The record holds the user's id and a count, never a path or a file name.
# Portable `find` (no `-perm /mode`); a symbolic link's own mode is always open, so only its owner is looked at.
record_folder_state() {
  local uid n tmp
  uid="$("$id_bin" -u "$sup" 2>/dev/null || true)"
  if printf '%s' "$uid" | grep -Eq '^[0-9]+$'; then
    n="$(find "$home" -xdev \( ! -uid "$uid" -o \( ! -type l \( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0010 -o -perm -0020 -o -perm -0040 \) \) \) -print 2>/dev/null | wc -l | tr -d ' ')" || n=unknown
    printf '%s' "$n" | grep -Eq '^[0-9]+$' || n=unknown
  else
    uid=unknown n=unknown
  fi
  tmp="$keep/folder.state.new.$$"
  if mkdir -p "$keep" && chmod 0711 "$keep" \
    && ( umask 022; printf 'uid=%s wrong=%s\n' "$uid" "$n" >"$tmp" ) && mv -f "$tmp" "$keep/folder.state"; then
    :
  else
    rm -f "$tmp"
  fi
  case "$n" in
    0) ;;
    unknown) say "could not check that everything under $home belongs to $sup; the self-test will say so" ;;
    *) say "$n entries under $home are still not $sup's own or are open to other users, so the dashboard may report 'Permission denied' for its memory and skills (run: chown -R -h $sup:$sup $home && chmod -R go-rwx $home)" ;;
  esac
}

# The box user's `~/.ssh` was once copied into the supervisor's home. An `ssh_config` there can run a command
# (`ProxyCommand`, `LocalCommand`, `Match exec`) as whoever uses it, here the supervisor, and the box user wrote it. The
# supervisor on a box needs no SSH configuration (its daemon is a local socket), so none is kept: remove what an earlier move
# copied. Its keys and known hosts are left for the owner to decide (see the cleanup in the changelog).
drop_box_user_ssh_config() {
  local d="$home/home/.ssh"
  [ -d "$d" ] || return 0
  # Removed AS the supervisor, never as root: the supervisor owns this folder, so a link it swapped in between a check and the
  # removal could only point root's `rm -rf` somewhere root owns (G1 N6). As the supervisor it can delete only what it already
  # could. A link in the way is removed as a link.
  "$runuser_bin" -u "$sup" -- rm -rf -- "$d/config" "$d/config.d" "$d/rc" "$d/environment" 2>/dev/null \
    || say "could not remove the copied ssh configuration in $d; remove it by hand"
}

# The dashboard's own socket to the box daemon (ADR 0040, decision 3) is made by systemd, as root, in a folder root owns, and
# handed to the daemon as an open descriptor (socket activation, the way `ozbox-runner.socket` works). Nothing root runs
# here touches a path under /run/ozboxd, which the box user owns and could fill with links. The daemon never binds or
# changes the mode of it; the box user, not being in `ozbox-supervisor`, cannot connect to it, and the daemon also checks
# the peer's uid. Written here, in the program's own script, so a first boot, `ensure-supervisor` and an upgrade of the
# program or the daemon all bring it. A daemon already running has no descriptor until it restarts, so a unit that was
# just written or changed restarts an active daemon (its runs are in their own scopes and its agent sessions are tmux's).
socket_unit() {
  cat <<'EOF_SOCKET'
[Unit]
Description=Oz Box: the dashboard user's socket to the box daemon
ConditionPathExists=/usr/local/bin/ozboxd
# No After= on any service, on purpose: a socket unit is ordered before sockets.target, which basic.target waits for, and a
# service is ordered after basic.target, so any `After=<service>` here is an ordering cycle at boot (G1 N1).

[Socket]
ListenStream=/run/ozbox-supervisor-api/daemon.sock
SocketUser=root
SocketGroup=ozbox-supervisor
SocketMode=0660
DirectoryMode=0755
Service=ozboxd.service

[Install]
WantedBy=sockets.target
EOF_SOCKET
}

socket_dropin() {
  cat <<'EOF_DROPIN'
[Unit]
Wants=ozboxd-supervisor.socket
After=ozboxd-supervisor.socket

[Service]
Sockets=ozboxd-supervisor.socket
EOF_DROPIN
}

# Does the installed daemon take its socket from systemd? One that does not would ignore the descriptor and leave a listening
# socket inheritable by every run it starts (G1 N4). The binary carries a marker (ozbox-listenfd's DAEMON_MARKER, in a line it
# logs); it is looked for in the file, never by running the daemon with a new argument (an older daemon ignores an unknown
# argument and starts a second daemon, as root).
daemon_takes_socket() {
  [ -f "$daemon_bin" ] && grep -aq 'ozbox-listenfd-protocol-1' "$daemon_bin"
}

ensure_scoped_socket() {
  local changed=no dropin_dir="$unitdir/ozboxd.service.d" f want need_restart=no
  if ! daemon_takes_socket; then
    # No socket for a daemon that cannot take it. A unit left by a newer daemon (a rollback) is removed so nothing hands the
    # old daemon a descriptor.
    if [ -e "$unitdir/ozboxd-supervisor.socket" ] || [ -e "$dropin_dir/10-supervisor-socket.conf" ]; then
      "$systemctl_bin" disable --now ozboxd-supervisor.socket >/dev/null 2>&1 || true
      rm -f "$unitdir/ozboxd-supervisor.socket" "$dropin_dir/10-supervisor-socket.conf"
      "$systemctl_bin" daemon-reload
    fi
    say "the installed box daemon does not take its socket from systemd; the dashboard's socket is not made until the daemon is upgraded (ozbox admin <box> -- reinstall-ozboxd)"
    return 0
  fi
  mkdir -p "$unitdir" "$dropin_dir"
  want="$(socket_unit)"
  f="$unitdir/ozboxd-supervisor.socket"
  if [ ! -f "$f" ] || [ "$(cat "$f")" != "$want" ]; then printf '%s\n' "$want" >"$f"; chmod 0644 "$f"; changed=yes; fi
  want="$(socket_dropin)"
  f="$dropin_dir/10-supervisor-socket.conf"
  if [ ! -f "$f" ] || [ "$(cat "$f")" != "$want" ]; then printf '%s\n' "$want" >"$f"; chmod 0644 "$f"; changed=yes; fi
  [ "$changed" = no ] || "$systemctl_bin" daemon-reload
  # The socket is only ever ENABLED here. A stopped daemon is left stopped: starting the socket would let the dashboard's next
  # poll start the daemon (socket activation) and undo an operator's `systemctl stop ozboxd`, and at first boot it would open
  # a window before the metadata guard and the firewall are up. The daemon's drop-in has `Wants=` the socket, so the socket
  # comes up with the daemon (G1 F5, and never a daemon restart on the spawn path, G1 N8).
  "$systemctl_bin" enable ozboxd-supervisor.socket >/dev/null 2>&1 || true
  need_restart=$changed
  if ! "$systemctl_bin" is-active --quiet ozboxd-supervisor.socket; then need_restart=yes; fi
  if [ "$need_restart" = yes ] && "$systemctl_bin" is-active --quiet ozboxd.service; then
    # A running daemon has no descriptor until it starts again, and systemd will not start a socket whose service is running.
    # So the order is explicit, not left to how a restart job orders its `Wants=` (G1 F4): stop the daemon, (re)start the
    # socket, start the daemon. Runs are in their own scopes and agent sessions are tmux's, so neither is touched.
    "$systemctl_bin" stop ozboxd.service || say "the box daemon did not stop; run: systemctl restart ozboxd"
    if [ "$changed" = yes ]; then "$systemctl_bin" stop ozboxd-supervisor.socket >/dev/null 2>&1 || true; fi
    "$systemctl_bin" start ozboxd-supervisor.socket >/dev/null 2>&1 \
      || say "the dashboard's socket to the box daemon did not start; the dashboard cannot reach the daemon until it does"
    "$systemctl_bin" start ozboxd.service || say "the box daemon did not start; run: systemctl start ozboxd"
    "$systemctl_bin" is-active --quiet ozboxd-supervisor.socket \
      || say "the dashboard's socket to the box daemon is not up after the daemon restarted; the dashboard cannot reach the daemon until it is"
  fi
}

# record STEP RESULT REASON ATTEMPTS: what a first-boot step ended as, in /etc/ozbox/first-boot-steps (one line per step,
# `<step> <ok|failed> <reason> <attempts>`), which the box's self-test reads and fails on, naming the step. Every run
# records again, so the action that repairs a step clears its failure. Best effort: no /etc/ozbox, no record.
record() {
  local f="$etc/ozbox/first-boot-steps" tmp
  [ -d "$etc/ozbox" ] && [ ! -L "$etc/ozbox" ] || return 0
  tmp="$f.tmp.$$"
  { if [ -f "$f" ] && [ ! -L "$f" ]; then awk -v s="$1" '$1 != s' "$f"; fi
    printf '%s %s %s %s\n' "$1" "$2" "$3" "$4"; } >"$tmp" 2>/dev/null \
    && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$f" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

# Coding agents the box user starts (Claude Code, Codex, Gemini CLI, OpenCode) get the Oz Box tools by a static entry in their
# own settings (ADR 0043). It holds no secret and never changes, and it is written AS the box user, on the box user's own files:
# the dashboard cannot and must not reach them. Safe to run again; the person's other servers are never touched. Best effort:
# an older program without the command, or a settings file the person made unreadable, leaves everything as it was.
#
# Two ways to become the box user, the first being the plain one. `runuser` switches user inside this process, which a
# service's sandbox can refuse ("cannot set user id": seen at an upgrade's first boot). Then systemd itself starts the
# command as the box user in a unit of its own (`systemd-run --uid`), which needs nothing of this process's privileges; a
# systemd that is not answering yet is asked again a few times, with a growing pause, and never forever. A coding agent's
# settings the program refused are not retried: that is the person's file, and the answer is shown.
runuser_refused() { printf '%s' "$1" | grep -Eq 'runuser: (cannot set (user id|group id|groups)|cannot open session|cannot initialize)'; }
systemd_not_ready() { printf '%s' "$1" | grep -Eq '^Failed to (start transient|connect to (bus|system scope bus)|create bus connection)'; }
install_agent_settings() {
  [ -x "$ozbox_bin" ] || { say "the Oz Box tools were not added to the coding agents' settings: the program $ozbox_bin is not installed"; record agent_tools failed no-program 0; return 0; }
  local h out tries pause
  h="$(getent passwd ozbox 2>/dev/null | cut -d: -f6 || true)"
  [ -n "$h" ] || h="$work/home/ozbox"
  [ -d "$h" ] || { say "the Oz Box tools were not added to the coding agents' settings: the box user has no home folder ($h)"; record agent_tools failed no-home 0; return 0; }
  # AS the box user, with no terminal and no input from this one (a box-user process must never share root's terminal), and
  # the answer kept: a refused engine is said, not swallowed
  local -a detach=()
  command -v setsid >/dev/null 2>&1 && detach=(setsid)
  if out="$(${detach[@]+"${detach[@]}"} "$runuser_bin" -u ozbox -- env "HOME=$h" "$ozbox_bin" agent-mcp install </dev/null 2>&1)"; then
    printf '%s\n' "$out" | sed 's/^/ozbox-supervisor-setup: /'
    record agent_tools ok runuser 1
    return 0
  fi
  printf '%s\n' "$out" | sed 's/^/ozbox-supervisor-setup: /'
  if ! runuser_refused "$out"; then
    say "the Oz Box tools were not added to every coding agent's settings (see above; run as the box user: ozbox agent-mcp install)"
    record agent_tools failed agent-settings-refused 1
    return 0
  fi
  if ! command -v "$systemd_run_bin" >/dev/null 2>&1; then
    say "the Oz Box tools were not added to the coding agents' settings: this process may not switch to the box user, and there is no systemd-run to ask instead; the dashboard is not affected. Run as the box user: ozbox agent-mcp install"
    record agent_tools failed switch-user-refused 1
    return 0
  fi
  say "this process may not switch to the box user, so systemd is asked to run the step as the box user instead"
  tries=0
  for pause in 0 $retry_delays; do
    [ "$pause" = 0 ] || { say "systemd did not start the step; trying again in ${pause}s"; sleep "$pause"; }
    tries=$((tries + 1))
    if out="$("$systemd_run_bin" --quiet --wait --pipe --collect --service-type=exec --uid=ozbox --gid=ozbox \
      "--setenv=HOME=$h" --property=NoNewPrivileges=yes -- "$ozbox_bin" agent-mcp install </dev/null 2>&1)"; then
      printf '%s\n' "$out" | sed 's/^/ozbox-supervisor-setup: /'
      record agent_tools ok systemd-run "$tries"
      return 0
    fi
    systemd_not_ready "$out" || break
  done
  printf '%s\n' "$out" | sed 's/^/ozbox-supervisor-setup: /'
  if systemd_not_ready "$out"; then
    # neither way could become the box user: it says nothing about the dashboard or its settings
    say "the Oz Box tools were not added to the coding agents' settings: this process may not switch to the box user and systemd did not start the step after $tries tries; the dashboard is not affected. Run: ozbox admin <box> -- ensure-supervisor, or as the box user: ozbox agent-mcp install"
    record agent_tools failed switch-user-refused "$tries"
  else
    say "the Oz Box tools were not added to every coding agent's settings (see above; run as the box user: ozbox agent-mcp install)"
    record agent_tools failed agent-settings-refused "$tries"
  fi
}

# A box whose dashboard already moved to the supervisor user has the OLD unit, which does not make the door's folder
# (RuntimeDirectory=ozbox-agent-mcp). A program upgrade (reinstall-ozboxd) runs --socket-only, so it brings the unit up to date
# here, and restarts the dashboard so the new program opens the door. Nothing else about the unit changes: the port, the public
# name and the tunnel are read back from the unit that is there. No dashboard unit, or an unreadable one, is left alone.
refresh_dashboard_unit() {
  [ -f "$new_unit" ] || return 0
  local args port host kind want tmp old
  args="$(parse_new || true)"
  # what was read back is checked the way the old unit's is: a unit with anything else on its line is left alone
  # rather than rendered into one that cannot start
  read -r port host kind extra <<<"$args"
  if [ -z "$args" ] || [ -n "${extra:-}" ] \
    || ! printf '%s' "$port" | grep -Eq '^[0-9]{4,5}$' || [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ] \
    || ! printf '%s' "$host" | grep -Eq '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])$' \
    || ! case "${kind:-}" in ''|cloudflare|tailscale-funnel|tailscale-serve|caddy|ngrok) true ;; *) false ;; esac; then
    say "the dashboard's unit is not one this step wrote; its folder for coding agents was not added (run: ozbox admin <box> -- ensure-supervisor)"
    return 0
  fi
  # a unit that is here and valid is the truth about the address: keep it for the next upgrade (a box made before this record existed)
  record_unit_args "$port" "$host" "${kind:-}"
  want="$(write_unit "$port" "$host" "${kind:-}")"
  if [ "$(cat "$new_unit")" != "$want" ]; then
    # written beside the unit and moved into place, so a full disk never leaves half a unit; the old one is kept to put back
    tmp="$new_unit.new.$$"
    old="$new_unit.old.$$"
    # a copy that cannot be made (full disk) ends this step only, never the whole script, and changes nothing
    if ! cp -p "$new_unit" "$old"; then
      rm -f "$old"
      say "the dashboard's unit could not be backed up (disk full?); it was left as it was"
      return 0
    fi
    if ! { printf '%s\n' "$want" >"$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$new_unit"; }; then
      rm -f "$tmp" "$old"
      say "the dashboard's unit could not be updated (disk full?); it was left as it was"
      return 0
    fi
    "$systemctl_bin" daemon-reload
    say "the dashboard's unit was brought up to date (the folder for coding agents' socket)"
    restart_dashboard=yes
  fi
  if [ "$restart_dashboard" = yes ] && "$systemctl_bin" is-active --quiet ozbox-dashboard.service; then
    # `restart` of a simple unit succeeds once the process is forked, so a dashboard that exits at once still "restarted": it is
    # given a moment and asked whether it is running, and the old unit goes back if it is not
    # A crash loop is told by three things, not by one look: it is not active, systemd restarted it on its own (its restart count
    # moved), or it entered the active state again since the restart (its start time moved). Any one is a dashboard that is not
    # running well, whatever instant it is looked at.
    if ! "$systemctl_bin" restart ozbox-dashboard.service \
      || ! dashboard_steady; then
      if [ -f "${old:-}" ]; then
        mv -f "$old" "$new_unit" && "$systemctl_bin" daemon-reload
        "$systemctl_bin" restart ozbox-dashboard.service || true
        say "the dashboard did not start with the new unit; the old unit was put back"
      else
        say "the dashboard did not restart; run: systemctl restart ozbox-dashboard"
      fi
    fi
  fi
  rm -f "${old:-}"
}

# A unit's arguments are valid only in these shapes; used on what is read back from a unit and from root's record alike.
unit_args_ok() { # port host kind extra
  printf '%s' "${1:-}" | grep -Eq '^[0-9]{4,5}$' && [ "$1" -ge 1024 ] && [ "$1" -le 65535 ] \
    && printf '%s' "${2:-}" | grep -Eq '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])$' \
    && [ -z "${4:-}" ] \
    && case "${3:-}" in ''|cloudflare|tailscale-funnel|tailscale-serve|caddy|ngrok) true ;; *) false ;; esac
}

# Keep what is needed to make the unit again (port, host, tunnel kind: never the unit's text, which changes between images, and
# never a secret). Written beside the record and moved into place, with its sha256 so a half-written or changed one is refused.
record_unit_args() { # port host kind
  unit_args_ok "$1" "$2" "${3:-}" || return 0
  local line tmp="$keep/dashboard.args.new.$$"
  line="$(printf '%s %s %s' "$1" "$2" "${3:-}" | sed 's/ *$//')"
  if [ -f "$keep/dashboard.args" ] && [ "$(cat "$keep/dashboard.args" 2>/dev/null)" = "$line" ] && [ -f "$keep/installed" ]; then return 0; fi
  if mkdir -p "$keep" && chmod 0711 "$keep" \
    && ( umask 077; printf '%s\n' "$line" >"$tmp" ) && mv -f "$tmp" "$keep/dashboard.args" \
    && ( umask 077; printf '%s\n' "$(sha_of "$keep/dashboard.args")" >"$keep/dashboard.args.sha256" ) \
    && : >"$keep/installed" && chmod 0644 "$keep/installed"; then
    :
  else
    rm -f "$tmp"
    say "the dashboard's address could not be kept on $work (disk full?); an upgrade would not bring the dashboard back by itself"
  fi
}

# The kept address, when it is intact: prints "port host kind". Anything that does not check out is as good as none.
recorded_args() {
  local f="$keep/dashboard.args" port host kind extra
  [ -f "$f" ] && [ ! -L "$f" ] && [ -f "$f.sha256" ] && [ ! -L "$f.sha256" ] || return 1
  [ "$(sha_of "$f")" = "$(cat "$f.sha256" 2>/dev/null)" ] || return 1
  read -r port host kind extra <"$f" || true
  unit_args_ok "$port" "$host" "${kind:-}" "${extra:-}" || return 1
  printf '%s %s %s\n' "$port" "$host" "${kind:-}"
}

# Property of the dashboard's unit (empty when systemd does not say).
dash_prop() {
  "$systemctl_bin" show -p "$1" --value ozbox-dashboard.service 2>/dev/null || true
}

# After a restart: wait, then say whether the dashboard is running and has stayed up through the wait.
dashboard_steady() {
  local n0 t0 n1 t1
  n0="$(dash_prop NRestarts)"
  t0="$(dash_prop ActiveEnterTimestampMonotonic)"
  [ "$settle_s" -le 0 ] || sleep "$settle_s"
  "$systemctl_bin" is-active --quiet ozbox-dashboard.service || return 1
  n1="$(dash_prop NRestarts)"
  t1="$(dash_prop ActiveEnterTimestampMonotonic)"
  if [ -n "$n0" ] && [ -n "$n1" ] && [ "$n0" != "$n1" ]; then return 1; fi
  if [ -n "$t0" ] && [ -n "$t1" ] && [ "$t0" != "$t1" ]; then return 1; fi
  return 0
}

# The arguments of the old unit's `serve`, read strictly: only these shapes are carried over. Anything else stops the move,
# because the old unit is a file the box user can write and root does not copy a command line it has not checked.
parse_old() {
  local line port="" host="" kind="" tok prev=""
  line="$(sed -n 's/^ExecStart=//p' "$1" | head -n 1)"
  set -- $line
  [ "${2:-}" = serve ] || return 1
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --bind) [ "${2:-}" = 127.0.0.1 ] || return 1; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      --public-url) host="${2:-}"; shift 2 ;;
      --tunnel) kind="${2:-}"; shift 2 ;;
      *) return 1 ;;
    esac
  done
  printf '%s' "$port" | grep -Eq '^[0-9]{4,5}$' && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || return 1
  host="${host#https://}"
  printf '%s' "$host" | grep -Eq '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])$' || return 1
  case "$kind" in ''|cloudflare|tailscale-funnel|tailscale-serve|caddy|ngrok) ;; *) return 1 ;; esac
  printf '%s %s %s\n' "$port" "$host" "$kind"
}

# The arguments of an existing system unit, so a second run keeps what the first chose.
parse_new() {
  sed -n 's/^ExecStart=.* serve --bind 127.0.0.1 --port \([0-9]*\) --public-url https:\/\/\([a-z0-9.-]*\)\(.*\)$/\1 \2 \3/p' "$new_unit" | head -n 1 | sed 's/ --tunnel / /;s/  */ /g'
}

write_unit() { # port host kind
  local tunnel=""
  [ -z "${3:-}" ] || tunnel=" --tunnel $3"
  cat <<EOF_UNIT
[Unit]
Description=Oz Box dashboard (the supervisor, its own user)
After=network-online.target ozbox-secrets.service
Wants=network-online.target ozbox-secrets.service

# Runs the root-owned program as the supervisor user. Everything it keeps is in a folder only that user can open; it reaches
# the secrets service through the supervisor's own socket and the box daemon through its own socket (/run/ozbox-supervisor-api,
# root's, bound by systemd). It is not in the box user's group. The box user cannot connect to those sockets, replace this
# program, or read this process.
[Service]
Type=simple
User=$sup
Group=$sup
WorkingDirectory=$home
Environment=HOME=$home/home
Environment=OZBOX_CONFIG=$home/config.toml
Environment=OZBOX_STATE_DIR=$home/state
Environment=OZBOX_SECRET_STORE=socket
Environment=OZBOX_SECRET_SOCKET=$sock
Environment=OZBOX_BROKER_SOCKET=$sock
Environment=OZBOX_SUPERVISOR_SOCKET=$sock
Environment=OZBOX_TUNNEL_SYSTEM_UNIT=ozbox-cloudflared.service
EnvironmentFile=-$home/dashboard.env
ExecStart=$ozbox_bin serve --bind 127.0.0.1 --port $1 --public-url https://$2$tunnel
# The door for coding agents the box user starts (ADR 0043): a folder of this user's, in /run, that systemd makes and clears.
# The socket in it answers the box user only (the kernel names the caller) and nothing but the Oz Box tools.
RuntimeDirectory=ozbox-agent-mcp
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$home
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF_UNIT
}

# The optional dashboard.env becomes the supervisor's EnvironmentFile, and the box user can write the old one: so only
# plain OZBOX_ settings are carried, never one the unit sets itself or one that names a program, a path, a socket or a store
# (LD_PRELOAD in that file would run the box user's code as the supervisor).
safe_env() {
  grep -E '^OZBOX_[A-Z0-9_]{1,64}=[A-Za-z0-9._:@+,-]{0,200}$' "$1" 2>/dev/null \
    | grep -Ev '^OZBOX_[A-Z0-9_]*(SOCKET|PATH|DIR|FILE|BIN|CONFIG|STORE|UNIT|HOME|KEY|TOKEN|SECRET)[A-Z0-9_]*=' || true
}

copy_state() {
  [ ! -e "$home/.migrated" ] || return 0
  local f
  for f in config.toml auth.toml; do
    [ -f "$old_home/$f" ] && [ ! -L "$old_home/$f" ] && install -m 0600 "$old_home/$f" "$home/$f"
  done
  if [ -f "$old_home/dashboard.env" ] && [ ! -L "$old_home/dashboard.env" ]; then
    ( umask 077; safe_env "$old_home/dashboard.env" >"$home/dashboard.env" )
  fi
  if [ -d "$old_home/state" ] && [ ! -L "$old_home/state" ]; then
    cp -a "$old_home/state/." "$home/state/"
  fi
  # its own settings. Never the box user's `~/.ssh`: its configuration can run a command as whoever uses it, the box user
  # wrote it, and the supervisor on a box needs no SSH configuration or keys (its daemon is a local socket).
  local src="$work/home/ozbox"
  if [ -d "$src/.config/ozbox" ] && [ ! -L "$src/.config/ozbox" ]; then
    mkdir -p "$home/home/.config"
    cp -a "$src/.config/ozbox" "$home/home/.config/ozbox"
  fi
  "$chown_bin" -R -h "$sup:$sup" "$home"
  chmod -R go-rwx "$home"
  : >"$home/.migrated"
  "$chown_bin" -h "$sup:$sup" "$home/.migrated"
  chmod 0600 "$home/.migrated"
  record_folder_state
}

# Is there a sign-in settings file in the dashboard's own folder that the dashboard could read? Without one it exits at once
# ("the sign-in settings file could not be read") and systemd restarts it for ever.
settings_usable() {
  [ -f "$home/auth.toml" ] && [ ! -L "$home/auth.toml" ] && [ -s "$home/auth.toml" ]
}

sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# The staged sign-in settings, proven to be the ones the person's computer sent. The bytes that are hashed are the bytes that
# are kept: the file is copied FIRST (into the dashboard's folder, which only root and the supervisor can open) and the COPY
# is hashed, so the box user swapping the staged file after the check changes nothing. Prints nothing; on success the verified
# copy is $home/auth.toml.verified.
stage_verified_auth() {
  rm -f "$home/auth.toml.verified"
  if [ -L "$old_home/auth.toml" ] || [ ! -f "$old_home/auth.toml" ] \
    || ! install -m 0600 "$old_home/auth.toml" "$home/auth.toml.verified" 2>/dev/null \
    || [ "$(sha_of "$home/auth.toml.verified")" != "$expect_auth" ]; then
    rm -f "$home/auth.toml.verified"
    say "the staged sign-in settings are not the ones your computer sent (a process on the box changed them, or none were staged); nothing was moved or started"
    exit 1
  fi
}

# The last error the dashboard printed, for a person to read: printable characters only, anything shaped like a credential
# blanked, and short.
last_dashboard_error() {
  "$journalctl_bin" -u ozbox-dashboard.service -n 30 --no-pager -o cat 2>/dev/null \
    | grep -i 'error' | tail -n 1 | tr -cd '[:print:]' \
    | sed -E -e 's#([Bb]earer[[:space:]]+)[A-Za-z0-9_.~+/=-]+#\1[redacted]#g' \
      -e 's#(([Tt]oken|[Ss]ecret|[Pp]assword|[Kk]ey)[=: ]+)[A-Za-z0-9_.+/=-]+#\1[redacted]#g' \
    | cut -c1-200 || true
}

port_answers() {
  if [ -n "${OZBOX_DASHBOARD_PROBE:-}" ]; then "$OZBOX_DASHBOARD_PROBE" "$1"; else (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; fi
}

# Started AND staying up AND answering: a simple unit is "active" the instant it forks, so a dashboard that exits straight
# away (its settings missing) looked started. Returns non-zero with the reason in $why.
why=""
dashboard_up() {
  local n=0 t=0
  until "$systemctl_bin" is-active --quiet ozbox-dashboard.service; do
    n=$((n + 1))
    if [ "$n" -ge 15 ]; then why="it did not start"; return 1; fi
    sleep 1
  done
  if ! dashboard_steady; then why="it started and stopped again"; return 1; fi
  until port_answers "$1"; do
    t=$((t + 1))
    if [ "$t" -gt "$probe_s" ]; then why="it is running but nothing answers on port $1"; return 1; fi
    sleep 1
  done
  return 0
}

case "${1:-}" in
  --finish)
    [ -e "$home/.migrated" ] || { say "nothing was moved yet; run without --finish first"; exit 1; }
    "$systemctl_bin" is-active --quiet ozbox-dashboard.service || { say "the supervisor's dashboard is not running; the old copies are kept"; exit 1; }
    for f in config.toml auth.toml dashboard.env secrets.json; do
      [ -e "$old_home/$f" ] && { "$shred_bin" -u "$old_home/$f" 2>/dev/null || rm -f "$old_home/$f"; }
    done
    [ -d "$old_home/state" ] && { find "$old_home/state" -type f -exec "$shred_bin" -u {} \; 2>/dev/null || true; rm -rf "$old_home/state"; }
    rm -f "$old_unit.migrated"
    say "the old dashboard state is destroyed; the box user's own ssh keys are left alone"
    exit 0 ;;
  --rollback)
    # only before --finish: afterwards there is no old unit to put back, and nothing is started as the box user
    [ -e "$old_unit.migrated" ] || { say "there is no old dashboard to put back (the move was finished, or never made); nothing was changed"; exit 0; }
    "$systemctl_bin" disable --now ozbox-dashboard.service 2>/dev/null || true
    mv -f "$old_unit.migrated" "$old_unit"
    user_systemctl daemon-reload || true
    user_systemctl enable --now ozbox-dashboard.service || true
    say "the dashboard runs as the box user again"
    exit 0 ;;
  --socket-only)
    ensure_user
    if [ "$left_group" = yes ]; then restart_dashboard=yes; fi
    refresh_dashboard_unit
    install_agent_settings
    say "the dashboard user and its socket to the box daemon are ready"
    exit 0 ;;
  --expect-auth)
    printf '%s' "${2:-}" | grep -Eq '^[0-9a-f]{64}$' || { say "--expect-auth takes a sha256"; exit 2; }
    expect_auth="$2" ;;
  --replace-auth)
    printf '%s' "${2:-}" | grep -Eq '^[0-9a-f]{64}$' || { say "--replace-auth takes a sha256"; exit 2; }
    expect_auth="$2"; replace_auth=yes ;;
  '') ;;
  *) say "unknown argument"; exit 2 ;;
esac

ensure_user
# The browser's launcher socket belongs to this user's group (ADR 0037, amendment 4): now that the group exists it can start.
# A failure must not stop this step.
[ ! -x "$ozbox_bin" ] || "$ozbox_bin" browser-setup >/dev/null 2>&1 || true

args=""
from_record=no
# Where the dashboard's address comes from, most trusted first. A dashboard that was moved before and whose unit is gone (an
# upgrade replaced the system disk) takes root's own record. A unit the box user staged is read only for a first move (nothing has
# been moved yet), on the person's own install (the request carries their sha256) when there is no record, and never otherwise: a
# staged unit with no sha would repoint the dashboard.
if [ -e "$home/.migrated" ] && [ ! -f "$new_unit" ] && args="$(recorded_args)"; then
  from_record=yes
elif [ -f "$old_unit" ] && [ ! -L "$old_unit" ] && { [ ! -e "$home/.migrated" ] || [ -n "${expect_auth:-}" ]; }; then
  args="$(parse_old "$old_unit")" || { say "the old dashboard unit has arguments this step does not carry over; nothing was moved"; exit 1; }
elif [ -f "$new_unit" ]; then
  args="$(parse_new)"
fi
if [ -z "$args" ]; then
  if [ -e "$home/.migrated" ] && settings_usable; then
    say "the dashboard's sign-in settings are kept on this box but nothing records its address, so no dashboard was started; run 'ozbox dashboard install' from your computer to start it again"
  else
    say "no dashboard is installed on this box; the supervisor user is ready"
  fi
  exit 0
fi
read -r port host kind <<<"$args"

# The sign-in settings decide who may approve on this box, and the box user could have rewritten the staged file after the
# person's computer wrote it: it is proven to be what that computer sent before anything is installed.
if [ -n "${expect_auth:-}" ]; then stage_verified_auth; fi

if [ ! -e "$home/.migrated" ]; then
  # the one-time move of the box user's old dashboard (its settings, state and own configuration)
  copy_state
  if [ -n "${expect_auth:-}" ]; then
    # what was proven is what is kept, even if the staged file changed while the rest was copied
    install -m 0600 "$home/auth.toml.verified" "$home/auth.toml"
    "$chown_bin" "$sup:$sup" "$home/auth.toml"
  fi
elif [ -n "${expect_auth:-}" ]; then
  # Moved long ago (an upgrade replaces the system disk and keeps /work, so this folder, and its marker, outlive the unit).
  # The move is over; this is the person's own install. Their verified settings go in when the dashboard has none to read; a
  # dashboard that already has some keeps them unless the root helper ran this as --replace-auth, which it does only after the
  # secrets service accepted an approval bound to exactly these settings (see the head of this file).
  if ! settings_usable; then
    install -m 0600 "$home/auth.toml.verified" "$home/auth.toml"
    "$chown_bin" "$sup:$sup" "$home/auth.toml"
    say "the sign-in settings you sent were installed"
    settings_state=installed
  elif [ "$(sha_of "$home/auth.toml")" = "$expect_auth" ]; then
    settings_state=unchanged
  elif [ "$replace_auth" = yes ]; then
    install -m 0600 "$home/auth.toml" "$home/auth.toml.replaced"
    install -m 0600 "$home/auth.toml.verified" "$home/auth.toml"
    "$chown_bin" "$sup:$sup" "$home/auth.toml" "$home/auth.toml.replaced"
    say "the dashboard's sign-in settings were replaced by the ones you sent and approved (the old ones are kept as auth.toml.replaced)"
    settings_state=replaced
    restart_dashboard=yes
  else
    kept_settings=yes
    settings_state=kept
    say "the dashboard on this box already has sign-in settings of its own, so the ones sent from your computer were not applied (replacing them needs your approval, which this step cannot take; ask for one and run the install again with --replace-sign-in)"
  fi
  # the address is the one the dashboard has, never one a staged unit names (an approval of sign-in settings does not cover it)
  if [ -f "$new_unit" ] && [ -n "$(parse_new)" ]; then
    read -r port host kind <<<"$(parse_new)"
  fi
fi
rm -f "$home/auth.toml.verified"
if ! settings_usable; then
  say "the dashboard's sign-in settings are missing ($home/auth.toml), so it was not started (it would fail and restart for ever). Run 'ozbox dashboard install' again from your computer"
  exit 1
fi
want="$(write_unit "$port" "$host" "$kind")"
# Settings kept and a dashboard that is already running as it should: nothing to do, and nothing restarted.
if [ "$kept_settings" = yes ] && [ -f "$new_unit" ] && [ "$(cat "$new_unit")" = "$want" ] \
  && "$systemctl_bin" is-active --quiet ozbox-dashboard.service; then
  record_unit_args "$port" "$host" "$kind"
  say "state dashboard=running settings=kept"
  exit 0
fi
if [ ! -f "$new_unit" ] || [ "$(cat "$new_unit")" != "$want" ]; then
  printf '%s\n' "$want" >"$new_unit"
  chmod 0644 "$new_unit"
  "$systemctl_bin" daemon-reload
fi

# Stop the old dashboard first (it holds the port), then start the new one; put the old one back if the new one does not
# come up, but only if it was running before: a dashboard staged by `ozbox dashboard install` never ran as the box user,
# and is never started as the box user here either.
was_running=no
if [ -f "$old_unit" ]; then
  if user_systemctl is-active --quiet ozbox-dashboard.service; then was_running=yes; fi
  user_systemctl disable --now ozbox-dashboard.service || true
  mv -f "$old_unit" "$old_unit.migrated"
  user_systemctl daemon-reload || true
fi
"$systemctl_bin" enable ozbox-dashboard.service >/dev/null 2>&1 || true
"$systemctl_bin" restart ozbox-dashboard.service || true
if ! dashboard_up "$port"; then
  reason="$(last_dashboard_error)"
  "$systemctl_bin" disable --now ozbox-dashboard.service 2>/dev/null || true
  [ ! -e "$old_unit.migrated" ] || mv -f "$old_unit.migrated" "$old_unit"
  user_systemctl daemon-reload || true
  say "the dashboard did not run as the supervisor: $why${reason:+ ($reason)}"
  # settings that were just replaced and did not start the dashboard go back
  if [ "$settings_state" = replaced ] && [ -f "$home/auth.toml.replaced" ]; then
    install -m 0600 "$home/auth.toml.replaced" "$home/auth.toml" && "$chown_bin" "$sup:$sup" "$home/auth.toml"
    say "the new sign-in settings did not start the dashboard, so the old ones were put back"
  fi
  if [ "$was_running" = yes ]; then
    say "putting the old one back"
    user_systemctl enable --now ozbox-dashboard.service || true
  else
    say "it was not started as the box user either (nothing runs)"
  fi
  exit 1
fi
install_agent_settings
# what makes the unit again after an upgrade (see the head of this file)
record_unit_args "$port" "$host" "$kind"
[ "$from_record" != yes ] || say "the dashboard's unit was made again from the address kept on this box (an upgrade had removed it)"
say "state dashboard=running settings=$settings_state"
say "the dashboard runs as $sup (port $port); run with --finish once you have signed in to it"
