#!/usr/bin/env bash
# The browser's own Unix user, its folders and its launcher (ADR 0037, amendment 4). Run as root, by first-boot
# configuration (`ozbox browser-setup`, the script is carried in the program so first boot stays small) and again when the
# dashboard's own user is made. Idempotent: a second run changes nothing that is already right.
#
# The browser worker, its Chromium and its profiles run as `ozbox-browser`, never as the box user an agent's shell runs as.
# What this script puts in place:
#   - the user and group, with a fixed id (the folders are on /work, which outlives the system disk, so the id must be the
#     same on every image; on a machine where that id is taken the next free system id is used and the folders are
#     re-owned to it);
#   - /work/ozbox-browser           0751 root: the browser's user cannot rename what is in it, so root never follows a link it plants;
#   - /work/ozbox-browser/private   0700 to that user: profiles (cookies), held-back downloads, a paused session's place;
#   - /work/ozbox-browser/shared    0750, group `ozbox`, setgid: recordings and released documents, which the box's group
#                                   (the agent's user) reads and the browser's user alone writes. The dashboard's own user is NOT
#                                   in that group (ADR 0040, decision 3: it shares nothing with the box user), so it reads them
#                                   through a POSIX ACL entry of its own, `u:ozbox-supervisor:rX`, as an access entry and a
#                                   default entry (new files inherit it), set by the browser's user (G1 F1);
#   - /work/uploads                 made readable by others when it does not exist, because the worker reads an upload from
#                                   there and is not the box user;
#   - a launcher socket the DASHBOARD'S user alone may open (never the box group: an agent that could open it could start a
#     worker of its own), and the per-connection unit that starts `ozbox browser-launch` as root.
# Nothing here is a secret and nothing listens on the network.
#
# Environment (for tests; the defaults are the real paths): OZBOX_BROWSER_ROOT, OZBOX_UNIT_DIR, OZBOX_ID, OZBOX_GETENT,
# OZBOX_USERADD, OZBOX_GROUPADD, OZBOX_PASSWD, OZBOX_INSTALL, OZBOX_CHOWN, OZBOX_STAT, OZBOX_SYSTEMCTL, OZBOX_TMPFILES_DIR,
# OZBOX_UPLOADS, OZBOX_SETFACL, OZBOX_OLD_PROFILES, OZBOX_RUNUSER, OZBOX_MV, OZBOX_CHMOD, OZBOX_TMPFILES, OZBOX_CHGRP, OZBOX_RUN_DIR.
set -euo pipefail

root="${OZBOX_BROWSER_ROOT:-/work/ozbox-browser}"
unitdir="${OZBOX_UNIT_DIR:-/etc/systemd/system}"
tmpfilesdir="${OZBOX_TMPFILES_DIR:-/etc/tmpfiles.d}"
uploads="${OZBOX_UPLOADS:-/work/uploads}"
old_profiles="${OZBOX_OLD_PROFILES:-/work/.ozbox/browser/profiles}"
id_bin="${OZBOX_ID:-id}"
getent_bin="${OZBOX_GETENT:-getent}"
useradd_bin="${OZBOX_USERADD:-useradd}"
groupadd_bin="${OZBOX_GROUPADD:-groupadd}"
passwd_bin="${OZBOX_PASSWD:-passwd}"
install_bin="${OZBOX_INSTALL:-install}"
chown_bin="${OZBOX_CHOWN:-chown}"
stat_bin="${OZBOX_STAT:-stat}"
systemctl_bin="${OZBOX_SYSTEMCTL:-systemctl}"
runuser_bin="${OZBOX_RUNUSER:-runuser}"
mv_bin="${OZBOX_MV:-mv}"
chmod_bin="${OZBOX_CHMOD:-chmod}"
tmpfiles_bin="${OZBOX_TMPFILES:-systemd-tmpfiles}"
chgrp_bin="${OZBOX_CHGRP:-chgrp}"
setfacl_bin="${OZBOX_SETFACL:-setfacl}"
run_dir="${OZBOX_RUN_DIR:-/run/ozbox-browser}"

user=ozbox-browser
pin=1501
dash=ozbox-supervisor

say() { printf 'ozbox-browser-setup: %s\n' "$*"; }

ensure_user() {
  if "$id_bin" "$user" >/dev/null 2>&1; then return 0; fi
  # the fixed id, unless something else holds it on this machine
  if ! "$getent_bin" passwd "$pin" >/dev/null 2>&1 && ! "$getent_bin" group "$pin" >/dev/null 2>&1; then
    "$groupadd_bin" --system --gid "$pin" "$user"
    "$useradd_bin" --system --gid "$user" --uid "$pin" --home-dir "$root/private/home" --no-create-home \
      --shell /usr/sbin/nologin --comment "Oz Box browser" "$user"
  else
    "$useradd_bin" --system --user-group --home-dir "$root/private/home" --no-create-home \
      --shell /usr/sbin/nologin --comment "Oz Box browser" "$user"
  fi
  "$passwd_bin" --lock "$user" >/dev/null 2>&1 || true
}

# A folder inside a tree the browser's user owns must never be followed by root: that user can swap any entry of its own for a
# symlink. So root touches only what it owns ($root, and the two folders directly in it, which the browser's user cannot
# rename because $root is root's), and everything deeper is made by the browser's user itself.
refuse_link() {
  if [ -L "$1" ]; then
    say "$1 is a symbolic link, which is not something this setup makes; it was left alone (remove it and run this again)"
    exit 1
  fi
}

as_browser() { "$runuser_bin" -u "$user" -- "$@"; }

ensure_folders() {
  local uid
  uid="$("$id_bin" -u "$user")"
  refuse_link "$root"
  # $root is root's, so the browser's user can enter it but cannot rename what is in it (not `private`, not `shared`)
  "$install_bin" -d -m 0751 -o root -g ozbox "$root"
  refuse_link "$root/shared"
  refuse_link "$root/private"
  "$install_bin" -d -m 2750 -o "$user" -g ozbox "$root/shared"
  "$install_bin" -d -m 0700 -o "$user" -g "$user" "$root/private"
  # A re-made system disk can give the user a different id than the one the folders on /work carry: follow it. (`-h`: a
  # link is re-owned, never what it points at; `-R` never follows one.)
  if [ "$("$stat_bin" -c %u "$root/private")" != "$uid" ] || [ "$("$stat_bin" -c %u "$root/shared")" != "$uid" ]; then
    "$chown_bin" -R -h "$user" "$root/private" "$root/shared"
    "$chown_bin" -R -h :"$user" "$root/private"
    say "the folders were re-owned to the browser's user"
  fi
  # what is inside is made by the browser's user, as that user
  as_browser mkdir -p -m 0700 "$root/private/home" "$root/private/profiles" "$root/private/held" "$root/private/resume" 2>/dev/null || true
  # an upload comes from a folder the box user fills and the browser's user reads
  if [ ! -e "$uploads" ]; then
    "$install_bin" -d -m 0755 -o ozbox -g ozbox "$uploads"
  fi
}

# The dashboard's user reads recordings and released documents in $root/shared without being in the box user's group: by an ACL
# entry for it alone (G1 F1). It is set AS the browser's user, who owns every entry in the tree, so root never walks a tree that
# user can fill with links; `-P` never follows a link. The default entry makes what the worker writes from now on carry it, and
# the access entry covers what is already there. The entry is read-only (`rX`): the dashboard never writes there. Needs a /work
# that supports ACLs (the default on ext4 and xfs, and the `acl` package the image installs); when it fails the dashboard cannot
# show recordings, which is said loudly here and in the self-test of a box, never worked around by putting the dashboard's user
# back in the box user's group. Runs again whenever this script does, so a dashboard user made later gets it.
ensure_dashboard_read() {
  "$getent_bin" group "$dash" >/dev/null 2>&1 || return 0
  if as_browser "$setfacl_bin" -P -R -m "u:$dash:rX" "$root/shared" \
    && as_browser "$setfacl_bin" -P -R -d -m "u:$dash:rX" "$root/shared"; then
    return 0
  fi
  say "$dash could not be given read access to $root/shared (is /work mounted with ACLs, and is the acl package installed?); the dashboard cannot show recordings or released documents until it can"
}

# Profiles made before the browser had its own user are in a folder the box user (an agent) can read and write. Their
# sign-ins are carried over into the browser's private folder, and the old copy goes.
#
# Everything under /work/.ozbox is the agent's, and the agent can start this at any time (`ensure-supervisor`) and watch it run.
# So root never resolves a path in that tree twice:
#   1. it walks in with `cd -P`, one part at a time, and requires each part to be where it should be (a link, or a part the agent
#      has moved, makes the real place differ), then HOLDS that folder: a later swap of its path changes nothing, because every
#      later step uses a name relative to the folder it is standing in;
#   2. it MOVES the old folder (a rename on the same disk, so it costs nothing and nothing is written twice) into $stage, a
#      folder only root can enter, and from then on works only there;
#   3. it freezes what it moved (re-owned to root, mode 0700, links deleted), and checks that nothing in it still belongs to
#      anyone else, so the agent cannot change it while root works, even through a folder it already had open;
#   4. it re-owns each profile to the browser's user and hands the folder to that user, who moves the profiles into its own private
#      folder and deletes what is left. Root never writes into the browser's folders, and never names an agent-controlled path to
#      a recursive chmod or chown (GNU `chmod -R` follows a link NAMED on its command line; here every operand is a folder
#      found in a root-only place, and nothing below it is followed).
# It runs once on a box: the marker is written whatever the outcome, so an agent cannot plant a profile later and have it
# carried in. The one state that is tried again is a move that was frozen but could not be handed over: `.profiles-migrated`
# then says `pending`, and the next run finishes only what is in the staging folder.
stage="$root/.migrate"

# Freeze a folder that is in $stage (root's own place): $1 is a real folder there, never a link.
freeze() {
  local o="$1"
  [ -d "$o" ] && [ ! -L "$o" ] || return 1
  "$chmod_bin" 0700 "$o" || return 1
  "$chown_bin" -R -h root:root "$o" || return 1
  "$chmod_bin" -R go-rwx "$o" || return 1
  # a link is removed, never followed
  find -P "$o" -type l -delete || return 1
  # anything still not root's was written by the agent while this ran: not carried over, and not trusted
  [ -z "$(find -P "$o" ! -user "$EUID" -print 2>/dev/null | head -n 1)" ] || return 1
}

# Re-own each frozen profile to the browser's user, hand the folder to that user, and let it move the profiles in.
carry_over() {
  local o="$stage/old" p moved
  freeze "$o" || { say "the old profiles could not be secured; they stay in $stage and this will be tried again"; return 1; }
  for p in "$o"/*; do
    [ -e "$p" ] || [ -L "$p" ] || continue
    if [ -L "$p" ] || [ ! -d "$p" ]; then
      rm -f -- "$p"
      continue
    fi
    "$chown_bin" -R -h "$user:$user" "$p" || return 1
  done
  "$chown_bin" -h "$user:$user" "$o" || return 1
  "$chmod_bin" 0711 "$stage" || return 1
  # a name that is already in the private folder stays as it is (what the person signed in to there wins)
  moved="$(as_browser sh -c 'n=0; for p in "$1"/*; do [ -e "$p" ] || [ -L "$p" ] || continue; d="$2/${p##*/}"; if [ -e "$d" ] || [ -L "$d" ]; then continue; fi; mv -- "$p" "$d" || exit 1; n=$((n + 1)); done; echo "$n"' _ "$o" "$root/private/profiles")" || return 1
  as_browser rm -rf -- "$o" || true
  rmdir "$stage" 2>/dev/null || true
  say "profiles made before the browser had its own user were moved into its private folder (${moved:-0}), and the copies the box user could read are removed"
}

# Move the old folder into $stage while holding it. Returns 0 staged, 10 nothing there, 11 refused.
take_old_folder() {
  local top base1 base2 base3 want rc
  [ -e "$old_profiles" ] || [ -L "$old_profiles" ] || return 10
  base3="$(basename "$old_profiles")"
  base2="$(basename "$(dirname "$old_profiles")")"
  base1="$(basename "$(dirname "$(dirname "$old_profiles")")")"
  top="$(dirname "$(dirname "$(dirname "$old_profiles")")")"
  rm -rf -- "$stage"
  "$install_bin" -d -m 0700 -o root -g root "$stage"
  (
    cd -P -- "$top" || exit 11
    want="$(pwd -P)"
    # the parts the box user can rename: each must really be where it is said to be, and must not be a link to somewhere else
    cd -P -- "$base1" 2>/dev/null || exit 11
    [ "$(pwd -P)" = "$want/$base1" ] || exit 11
    cd -P -- "$base2" 2>/dev/null || exit 11
    [ "$(pwd -P)" = "$want/$base1/$base2" ] || exit 11
    # the folder we stand in is the box user's or root's
    owner="$("$stat_bin" -c %u .)"
    boxuid="$("$id_bin" -u ozbox 2>/dev/null || echo 0)"
    if [ "$owner" != "$boxuid" ] && [ "$owner" != 0 ]; then exit 12; fi
    [ -e "$base3" ] || [ -L "$base3" ] || exit 10
    # a rename of the entry in the folder we hold: a link that replaced it is moved as a link, never followed
    "$mv_bin" -- "$base3" "$stage/old" || exit 11
  ) && rc=0 || rc=$?
  case "$rc" in
    0) ;;
    10) return 10 ;;
    12) say "$(dirname "$old_profiles") is owned by neither the box user nor root; the old profiles were left alone"; return 11 ;;
    *) say "$(dirname "$old_profiles") is not where it should be (a symbolic link, or moved while this ran); the old profiles were left alone"; return 11 ;;
  esac
  if [ -L "$stage/old" ] || [ ! -d "$stage/old" ]; then
    rm -rf -- "$stage/old"
    say "the old profiles folder was replaced by a symbolic link, which is not something this setup makes; it was removed, not followed"
    return 11
  fi
  return 0
}

migrate_profiles() {
  local marker="$root/.profiles-migrated" state="" rc=0
  [ -e "$marker" ] && state="$(cat "$marker" 2>/dev/null || true)"
  if [ -e "$marker" ] && [ "$state" != pending ]; then
    # done on this box. Profiles that are back in the old folder (a release without the browser user ran in between) are not
    # carried in, because the agent can plant them; they are still readable by the box user.
    if [ -n "$(ls -A "$old_profiles" 2>/dev/null | head -n 1)" ]; then
      say "there are profiles in $old_profiles, readable by the box user; they are not moved again (this runs once per box). Sign in again in an isolated session and remove that folder"
    fi
    return 0
  fi
  [ -e "$marker" ] || printf pending >"$marker"
  if [ -d "$stage/old" ] && [ ! -L "$stage/old" ]; then
    carry_over || rc=$?
  else
    take_old_folder && rc=0 || rc=$?
    case "$rc" in
      0) carry_over && rc=0 || rc=$? ;;
      10 | 11) rc=0 ;;
    esac
  fi
  if [ "$rc" = 0 ]; then
    : >"$marker"
  else
    say "the old profiles were frozen but not all moved; this is tried again"
    return 1
  fi
}

write_units() {
  mkdir -p "$unitdir" "$tmpfilesdir"
  # the launcher's folder: only the dashboard's user may enter it
  printf 'd /run/ozbox-browser 0750 root %s -\n' "$dash" >"$tmpfilesdir/ozbox-browser.conf"
  cat >"$unitdir/ozbox-browser.socket" <<EOF_SOCKET
[Unit]
Description=Oz Box browser launcher
ConditionPathExists=/usr/local/bin/ozbox
[Socket]
ListenStream=/run/ozbox-browser/launch.sock
SocketMode=0660
SocketUser=root
SocketGroup=$dash
DirectoryMode=0750
Accept=yes
MaxConnections=16
[Install]
WantedBy=sockets.target
EOF_SOCKET
  cat >"$unitdir/ozbox-browser@.service" <<'EOF_SERVICE'
[Unit]
Description=Oz Box browser launcher
[Service]
ExecStart=/usr/local/bin/ozbox browser-launch
StandardInput=socket
StandardOutput=socket
StandardError=journal
LimitCORE=0
PrivateTmp=true
# The launcher is root and reads a line a less trusted party wrote: keep it small. It talks to systemd over its socket
# (AF_UNIX) and writes nothing.
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
MemoryMax=128M
RuntimeMaxSec=300000
EOF_SERVICE
  # every session's unit is in this slice, so the browsers together have a ceiling: a box under memory pressure then stops the
  # browser, not the agent's build or the box's own program
  cat >"$unitdir/ozbox-browser.slice" <<'EOF_SLICE'
[Unit]
Description=Oz Box browser sessions
[Slice]
MemoryMax=60%
MemorySwapMax=0
EOF_SLICE
}

ensure_user
ensure_folders
ensure_dashboard_read
write_units
"$systemctl_bin" daemon-reload || true
# The folder the socket is in must be the dashboard's before the socket starts. Writing the tmpfiles entry only applies it at
# the next boot, and a socket started first makes the folder root's own, which the dashboard cannot enter (it would then
# quietly use the box user's browser). So apply the entry now, and set an already existing folder right.
if "$getent_bin" group "$dash" >/dev/null 2>&1; then
  "$tmpfiles_bin" --create "$tmpfilesdir/ozbox-browser.conf" || say "the launcher's folder could not be made"
  if [ -d "$run_dir" ] && [ ! -L "$run_dir" ]; then
    "$chgrp_bin" -h "$dash" "$run_dir" && "$chmod_bin" 0750 "$run_dir"
  fi
fi
# The socket belongs to the dashboard's group, which exists once the dashboard has its own user. Until then nothing starts
# (and the browser keeps working through the box daemon, as the box user); the dashboard's setup runs this again.
if "$getent_bin" group "$dash" >/dev/null 2>&1; then
  "$systemctl_bin" enable --now ozbox-browser.socket || say "the launcher socket could not be started"
  say "the browser runs as $user; its launcher is open to $dash only"
else
  say "the dashboard has no user of its own yet, so the launcher is not started; it starts when the dashboard is installed"
fi
# Last, and never fatal: it works on a tree the agent owns, and a failure there must not be able to stop the launcher's units
# above from existing (a box without them quietly falls back to the box user's browser).
migrate_profiles || say "the old profiles were not moved"
