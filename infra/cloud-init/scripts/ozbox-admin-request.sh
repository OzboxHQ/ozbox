#!/usr/bin/env bash
# Ask the box's root helper for one allow-listed action and print its answer (see ozbox-admin.sh for the list).
# Runs as the box user. It only writes one small request file and reads the answer root writes back.
# Environment (for tests): OZBOX_ADMIN_DIR, OZBOX_ADMIN_WAIT (seconds).
set -euo pipefail
dir="${OZBOX_ADMIN_DIR:-/run/ozbox-admin}"
wait_s="${OZBOX_ADMIN_WAIT:-120}"
[ $# -gt 0 ] || { echo "usage: ozbox-admin-request [--approval-stdin] <action> [arguments]" >&2; exit 2; }
# --approval-stdin: the approval code is read from the first line of standard input and becomes the request's last word, so
# it is never in this program's arguments (which every process of the box user can list while it waits)
words="$*"
if [ "$1" = "--approval-stdin" ]; then
  shift
  [ $# -gt 0 ] || { echo "usage: ozbox-admin-request [--approval-stdin] <action> [arguments]" >&2; exit 2; }
  IFS= read -r code || code=""
  code="$(printf '%s' "$code" | tr -d '[:space:]')"
  if printf '%s' "$code" | grep -Eq '[^A-Za-z0-9-]'; then echo "ozbox-admin-request: that is not an approval code" >&2; exit 2; fi
  words="$*${code:+ $code}"
fi
if printf '%s' "$words" | grep -Eq '[^A-Za-z0-9 ._-]'; then echo "ozbox-admin-request: only letters, digits, space, dash, dot and underscore" >&2; exit 2; fi
id="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
umask 077
printf '%s\n' "$words" >"$dir/requests/$id.req.tmp"
mv "$dir/requests/$id.req.tmp" "$dir/requests/$id.req"
i=0
while [ ! -f "$dir/results/$id.out" ]; do
  i=$((i + 1))
  if [ "$i" -gt "$((wait_s * 2))" ]; then echo "ozbox-admin-request: no answer within $wait_s seconds" >&2; exit 1; fi
  sleep 0.5
done
cat "$dir/results/$id.out"
head -n 1 "$dir/results/$id.out" | grep -q '^status=ok$'
