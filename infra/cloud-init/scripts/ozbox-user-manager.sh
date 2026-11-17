#!/usr/bin/env bash
# Start the box user's own service manager (`systemd --user`) once, at first boot, after /work is mounted and the box
# user's home on it is owned, so the units the box user enabled (`~/.config/systemd/user/default.target.wants`, on /work)
# start with it. Run as root by first-boot configuration, after ozbox-work-setup.sh; safe to run again.
#
# Why it is a step of its own: the box user's home is on /work, and on a new system disk (a new box, or an upgrade) /work
# is not in /etc/fstab until first boot adds it, so `RequiresMountsFor=/work` has no mount to wait for at boot. Linger,
# which the image turns on, then let the login manager start the user manager right after boot with no home: it reached
# default.target having started nothing, and restarting it from the middle of first boot raced the rest of first boot.
# Now a drop-in for the box user's manager holds it back until /work is a mount point (the image carries the same one,
# which is what holds it back on the very first boot), and this step starts it when everything it needs is ready.
#
#   - writes that drop-in for the box user's uid (the controllers runs need are delegated by the memory guard's own drop-in,
#     `ozbox host-guard memory install`, which first boot runs before this step: one file, one writer);
#   - turns linger on (on a stock machine that alone starts the manager);
#   - starts the manager if it is not running; one already running that started before /work was mounted (an image
#     without the drop-in) is restarted once, so its units start; one that started after is left alone.
#
# Each step that can wait on another part of the system is bounded, retried a few times with a growing pause, and never
# loops forever: the login manager can be slow to answer at first boot (an upgrade's first boot saw `enable-linger` time
# out), and a manager start can wait on the units it starts. Linger that the image already turned on (its file exists) is
# not asked for again. What each step ended as is recorded in /etc/ozbox/first-boot-steps (one line per step:
# `<step> <ok|failed> <reason> <attempts>`), which the box's self-test reads and fails on, naming the step.
#
# Environment (for tests; the defaults are the real paths): OZBOX_USER, OZBOX_WORK, OZBOX_SYSTEMD_DIR, OZBOX_SYSTEMCTL,
# OZBOX_LOGINCTL, OZBOX_ID, OZBOX_MOUNTPOINT, OZBOX_ETC, OZBOX_LINGER_DIR, OZBOX_RETRY_DELAYS (the pauses between tries,
# in seconds), OZBOX_LOGINCTL_TIMEOUT_S, OZBOX_START_TIMEOUT_S.
set -euo pipefail

user="${OZBOX_USER:-ozbox}"
work="${OZBOX_WORK:-/work}"
unitdir="${OZBOX_SYSTEMD_DIR:-/etc/systemd/system}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
loginctl_bin="${OZBOX_LOGINCTL:-loginctl}"
id_bin="${OZBOX_ID:-id}"
mountpoint_bin="${OZBOX_MOUNTPOINT:-mountpoint}"
etc="${OZBOX_ETC:-/etc}"
linger_dir="${OZBOX_LINGER_DIR:-/var/lib/systemd/linger}"
retry_delays="${OZBOX_RETRY_DELAYS:-2 4 8 16}"
loginctl_timeout_s="${OZBOX_LOGINCTL_TIMEOUT_S:-30}"
start_timeout_s="${OZBOX_START_TIMEOUT_S:-120}"

say() { echo "ozbox-user-manager: $*"; }

# record STEP RESULT REASON ATTEMPTS: what a first-boot step ended as, for the self-test. Best effort: a box without
# /etc/ozbox (it is made before this step) records nothing, and a record that cannot be written never stops the boot.
record() {
  local f="$etc/ozbox/first-boot-steps" tmp
  [ -d "$etc/ozbox" ] && [ ! -L "$etc/ozbox" ] || return 0
  tmp="$f.tmp.$$"
  { if [ -f "$f" ] && [ ! -L "$f" ]; then awk -v s="$1" '$1 != s' "$f"; fi
    printf '%s %s %s %s\n' "$1" "$2" "$3" "$4"; } >"$tmp" 2>/dev/null \
    && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$f" 2>/dev/null || rm -f "$tmp" 2>/dev/null || true
}

uid="$("$id_bin" -u "$user")"
case "$uid" in ''|*[!0-9]*|0) say "the box user has no usable id" >&2; exit 1 ;; esac
unit="user@$uid.service"

if ! "$mountpoint_bin" -q "$work"; then
  say "$work is not mounted, so the box user's services were not started (they start with it at the next boot)" >&2
  exit 1
fi

mkdir -p "$unitdir/$unit.d"
printf '[Unit]\nRequiresMountsFor=%s\nAfter=work.mount\nConditionPathIsMountPoint=%s\n' "$work" "$work" \
  >"$unitdir/$unit.d/10-ozbox-work.conf"
chmod 0644 "$unitdir/$unit.d/10-ozbox-work.conf"
"$systemctl_bin" daemon-reload

# Linger. The image turns it on by writing the file `loginctl enable-linger` writes, and the login manager reads that file
# when it starts, so a file that is there needs no question to a login manager that may still be busy at first boot.
if [ -e "$linger_dir/$user" ]; then
  say "linger is already on for the box user"
  record enable_linger ok already-on 0
else
  tries=0 lingered=no
  for pause in 0 $retry_delays; do
    [ "$pause" = 0 ] || { say "the login manager did not answer; trying again in ${pause}s"; sleep "$pause"; }
    tries=$((tries + 1))
    if timeout "$loginctl_timeout_s" "$loginctl_bin" enable-linger "$user"; then lingered=yes; break; fi
  done
  if [ "$lingered" = yes ]; then
    record enable_linger ok enabled "$tries"
  else
    # the same file the image writes: the login manager honours it from its next start, and this step starts the
    # manager below in any case, so the box user's services still start now
    if install -d -m 0755 "$linger_dir" 2>/dev/null && : >"$linger_dir/$user" 2>/dev/null; then
      say "the login manager did not answer after $tries tries; linger was written to its file, which it reads at the next boot. To turn it on now, run: ozbox admin <box> -- enable-linger" >&2
    else
      say "could not enable linger for the box user after $tries tries; run: ozbox admin <box> -- enable-linger" >&2
    fi
    record enable_linger failed login-manager-no-answer "$tries"
  fi
fi

# start_manager VERB: start (or restart) the box user's manager, waiting a bounded time. A wait that runs out does not
# cancel systemd's job, so the manager is then asked again, a few times with a growing pause, whether it came up.
start_manager() {
  if timeout "$start_timeout_s" "$systemctl_bin" "$1" "$unit"; then return 0; fi
  local pause
  for pause in $retry_delays; do
    sleep "$pause"
    "$systemctl_bin" is-active --quiet "$unit" && return 0
  done
  return 1
}
manager_failed() {
  record user_manager failed "$1" 1
  say "the box user's manager did not come up; run: ozbox admin <box> -- enable-linger" >&2
  exit 1
}

# When did the manager and /work come up (monotonic microseconds; 0 when never)?
since() { "$systemctl_bin" show -p ActiveEnterTimestampMonotonic --value "$1" 2>/dev/null || echo 0; }
if "$systemctl_bin" is-active --quiet "$unit"; then
  started="$(since "$unit")"
  mounted="$(since work.mount)"
  case "$started$mounted" in *[!0-9]*) started=0 mounted=1 ;; esac
  if [ "${started:-0}" -lt "${mounted:-0}" ]; then
    say "the box user's manager started before $work was mounted; restarting it once"
    start_manager restart || manager_failed restart-failed
    record user_manager ok restarted 1
  else
    say "the box user's manager is running, with its home"
    record user_manager ok running 1
  fi
else
  start_manager start || manager_failed start-failed
  say "the box user's manager started, with its home"
  record user_manager ok started 1
fi
