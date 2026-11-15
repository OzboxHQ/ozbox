#!/usr/bin/env bash
# Re-own, on the box user, the files an older box user left on /work.
#
# /work outlives the system disk. A box made before the box user's id was fixed (or on another image) wrote its files
# under a different numeric id, and on the new system disk that id may belong to somebody else (on stock Ubuntu, 1000
# is the `ubuntu` account), so the box user cannot read its own files. The first-boot adoption of an old id only works
# when nothing holds it; this script covers the rest.
#
# Rules, each of which exists because the opposite is a way to hand somebody's files to the wrong person:
#   - only the box user's own trees are touched (home, repos, the daemon's state), never /work as a whole;
#   - only files that carry the old numeric id move; root's files, system accounts' files (id below 1000), and the box
#     user's own files are never selected, and symlinks are changed, never followed;
#   - an old id given by a person (or by an agent filing the request as the box user) obeys the same floor, and is never
#     the id of the box's own service accounts: the secrets user, the supervisor, the browser's user, the metadata user or a project runner.
#     Their files (a restored secrets store, say) must never become the box user's;
#   - when more than one old id is present the script stops and says so: a person gives it the one to move with
#     --from-uid / --from-gid (through `ozbox admin <box> -- reown`);
#   - it runs once per disk: /work/.ozbox-box-ids records the ids the trees are known to carry, and the script does
#     nothing while that record matches the box user. --force ignores the record (the admin action uses it);
#   - it logs counts, never names.
# Environment (for tests; the defaults are the real paths): OZBOX_USER, OZBOX_BOX_UID, OZBOX_BOX_GID,
# OZBOX_REOWN_MARKER, OZBOX_REOWN_ROOTS (space separated), OZBOX_MIN_ID, OZBOX_CHOWN, OZBOX_CHGRP, OZBOX_GETENT.
set -euo pipefail

user="${OZBOX_USER:-ozbox}"
marker="${OZBOX_REOWN_MARKER:-/work/.ozbox-box-ids}"
min_id="${OZBOX_MIN_ID:-1000}"
do_chown="${OZBOX_CHOWN:-chown}"
do_chgrp="${OZBOX_CHGRP:-chgrp}"
getent_bin="${OZBOX_GETENT:-getent}"

force=0
from_uid=""
from_gid=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=1 ;;
    --from-uid) shift; from_uid="${1:-}" ;;
    --from-gid) shift; from_gid="${1:-}" ;;
    *) echo "ozbox-reown: unknown option" >&2; exit 2 ;;
  esac
  shift
done

is_number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
say() { echo "ozbox-reown: $*"; }

box_uid="${OZBOX_BOX_UID:-$(id -u "$user")}"
box_gid="${OZBOX_BOX_GID:-$(id -g "$user")}"
if ! is_number "$box_uid" || ! is_number "$box_gid"; then say "the box user has no numeric id" >&2; exit 1; fi
[ "$box_uid" != 0 ] && [ "$box_gid" != 0 ] || { say "refusing: the box user would be root" >&2; exit 1; }
# protected KIND: the ids (uid or gid) of the box's own service accounts, which are never "an old box user".
protected() {
  local db=passwd
  [ "$1" = uid ] || db=group
  "$getent_bin" "$db" 2>/dev/null | awk -F: '$1=="ozbox-secrets"||$1=="ozbox-supervisor"||$1=="ozbox-browser"||$1=="ozbox-meta"||$1~/^ozbox-run-/{print $3}' || true
}
prot_uids="$(protected uid | tr '\n' ' ')"
prot_gids="$(protected gid | tr '\n' ' ')"
check_given() {
  local kind="$1" given="$2" p
  [ -n "$given" ] || return 0
  is_number "$given" && [ "$given" != 0 ] || { say "an old id must be a number other than 0" >&2; exit 2; }
  if [ "$given" -lt "$min_id" ] || [ "$given" = 65534 ]; then
    say "refusing: $given is a system $kind (below $min_id, or nobody), never an old box user" >&2; exit 2
  fi
  if [ "$kind" = uid ]; then p="$prot_uids"; else p="$prot_gids"; fi
  case " $p " in *" $given "*) say "refusing: $given is one of the box's own service accounts, never an old box user" >&2; exit 2 ;; esac
}
check_given uid "$from_uid"
check_given gid "$from_gid"

if [ "$force" = 0 ] && [ -f "$marker" ]; then
  read -r seen_uid seen_gid _ <"$marker" || true
  if [ "${seen_uid:-}" = "$box_uid" ] && [ "${seen_gid:-}" = "$box_gid" ]; then
    say "already done for this disk (ids $box_uid:$box_gid)"
    exit 0
  fi
fi

roots=()
if [ -n "${OZBOX_REOWN_ROOTS:-}" ]; then
  # shellcheck disable=SC2206
  roots=($OZBOX_REOWN_ROOTS)
else
  for r in /work/home/ozbox /work/repos /work/.ozbox /work/restore /work/restored-*; do
    roots+=("$r")
  done
fi
existing=()
for r in "${roots[@]}"; do
  if [ -d "$r" ] && [ ! -L "$r" ]; then existing+=("$r"); fi
done
if [ "${#existing[@]}" = 0 ]; then
  say "no box user trees on this disk yet"
  exit 0
fi

# The id a file carries, on GNU and BSD stat.
owner_of() { stat -c "%$2" "$1" 2>/dev/null || stat -f "%$2" "$1"; }

# find_foreign KIND KNOWN [EXCLUDE]: files of the box user's trees whose owner (u) or group (g) is an old id.
foreign_args() {
  local kind="$1" box="$2" excl="${3:-}"
  local -a a=("-$kind" "+$((min_id - 1))" "!" "-$kind" 65534 "!" "-$kind" "$box")
  [ -z "$excl" ] || a+=("!" "-$kind" "$excl")
  local p i
  if [ "$kind" = uid ]; then p="$prot_uids"; else p="$prot_gids"; fi
  for i in $p; do a+=("!" "-$kind" "$i"); done
  printf '%s\n' "${a[@]}"
}

# pick KIND BOX GIVEN: the one old id to move, or nothing; exits 3 when there is more than one.
pick() {
  local kind="$1" box="$2" given="$3" first second
  if [ -n "$given" ]; then printf '%s' "$given"; return 0; fi
  local -a args=()
  while IFS= read -r line; do args+=("$line"); done < <(foreign_args "$kind" "$box")
  first="$(find "${existing[@]}" -xdev "${args[@]}" -print 2>/dev/null | head -n 1 || true)"
  [ -n "$first" ] || return 0
  local id
  if [ "$kind" = uid ]; then id="$(owner_of "$first" u)"; else id="$(owner_of "$first" g)"; fi
  args=()
  while IFS= read -r line; do args+=("$line"); done < <(foreign_args "$kind" "$box" "$id")
  second="$(find "${existing[@]}" -xdev "${args[@]}" -print 2>/dev/null | head -n 1 || true)"
  if [ -n "$second" ]; then
    say "more than one old $kind is present on /work; nothing was changed. Run: ozbox admin <box> -- reown --from-$kind <id>" >&2
    return 3
  fi
  printf '%s' "$id"
}

old_uid="$(pick uid "$box_uid" "$from_uid")" || exit 3
old_gid="$(pick gid "$box_gid" "$from_gid")" || exit 3

moved_u=0
moved_g=0
if [ -n "$old_uid" ] && [ "$old_uid" != "$box_uid" ]; then
  moved_u="$(find "${existing[@]}" -xdev -uid "$old_uid" -print 2>/dev/null | wc -l | tr -d ' ')"
  find "${existing[@]}" -xdev -uid "$old_uid" -exec "$do_chown" -h "$box_uid" {} +
fi
if [ -n "$old_gid" ] && [ "$old_gid" != "$box_gid" ]; then
  moved_g="$(find "${existing[@]}" -xdev -gid "$old_gid" -print 2>/dev/null | wc -l | tr -d ' ')"
  find "${existing[@]}" -xdev -gid "$old_gid" -exec "$do_chgrp" -h "$box_gid" {} +
fi

printf '%s %s migrated uid=%s gid=%s files_uid=%s files_gid=%s\n' \
  "$box_uid" "$box_gid" "${old_uid:-none}" "${old_gid:-none}" "$moved_u" "$moved_g" >"$marker"
say "re-owned $moved_u file(s) by owner and $moved_g by group onto the box user (old owner ${old_uid:-none}, old group ${old_gid:-none})"
