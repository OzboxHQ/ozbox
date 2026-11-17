#!/bin/sh
# Clears what only the BUILD instance should hold, at the end of an image build (AWS): the SSM agent's registration and logs
# of the build machine, and the temporary key Packer logged in with. It is run by a transient systemd unit at the build
# instance's shutdown, AFTER the SSM agent has stopped (see image-wipe-install.sh), never while the session that carries
# Packer is still open. OZBOX_WIPE_ROOT is a test's stand-in for /.
set -u
r="${OZBOX_WIPE_ROOT:-}"
for d in "$r/var/lib/amazon/ssm" "$r/var/log/amazon/ssm"; do
  [ -d "$d" ] && find "$d" -mindepth 1 -delete
done
for home in "$r/home/ubuntu" "$r/root"; do
  rm -f "$home/.ssh/authorized_keys"
done
# the build instance's journal (its Session Manager and login lines). journald is still running at this point, so flush
# what it holds in memory, rotate and drop what it has, and then make it RELINQUISH /var: it keeps writing only to /run
# (memory) from here on, so nothing it logs while the instance stops lands in /var/log/journal after the wipe below
# (that is how a second boot, the build's, leaked into the image's journal). Only then remove what is left on disk.
# Skipped under a test root.
if [ -z "$r" ] && command -v journalctl >/dev/null 2>&1; then
  journalctl --flush >/dev/null 2>&1
  journalctl --rotate >/dev/null 2>&1
  journalctl --vacuum-time=1s >/dev/null 2>&1
  journalctl --relinquish-var >/dev/null 2>&1
fi
[ -d "$r/var/log/journal" ] && find "$r/var/log/journal" -mindepth 1 -delete
exit 0
