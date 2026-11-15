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
# Environment (for tests; the defaults are the real paths): OZBOX_USER, OZBOX_WORK, OZBOX_SYSTEMD_DIR, OZBOX_SYSTEMCTL,
# OZBOX_LOGINCTL, OZBOX_ID, OZBOX_MOUNTPOINT.
set -euo pipefail

user="${OZBOX_USER:-ozbox}"
work="${OZBOX_WORK:-/work}"
unitdir="${OZBOX_SYSTEMD_DIR:-/etc/systemd/system}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
loginctl_bin="${OZBOX_LOGINCTL:-loginctl}"
id_bin="${OZBOX_ID:-id}"
mountpoint_bin="${OZBOX_MOUNTPOINT:-mountpoint}"

say() { echo "ozbox-user-manager: $*"; }

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

"$loginctl_bin" enable-linger "$user" ||
  say "could not enable linger for the box user; run: ozbox admin <box> -- enable-linger" >&2

# When did the manager and /work come up (monotonic microseconds; 0 when never)?
since() { "$systemctl_bin" show -p ActiveEnterTimestampMonotonic --value "$1" 2>/dev/null || echo 0; }
if "$systemctl_bin" is-active --quiet "$unit"; then
  started="$(since "$unit")"
  mounted="$(since work.mount)"
  case "$started$mounted" in *[!0-9]*) started=0 mounted=1 ;; esac
  if [ "${started:-0}" -lt "${mounted:-0}" ]; then
    say "the box user's manager started before $work was mounted; restarting it once"
    "$systemctl_bin" restart "$unit"
  else
    say "the box user's manager is running, with its home"
  fi
else
  "$systemctl_bin" start "$unit"
  say "the box user's manager started, with its home"
fi
