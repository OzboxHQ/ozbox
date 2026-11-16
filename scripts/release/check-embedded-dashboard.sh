#!/bin/sh
# Ask a built ozbox program which dashboard it embedded, and fail unless it is the one this build made.
#
#   check-embedded-dashboard.sh <expected-sha256> <command...>
#
# <command...> is how to run the program: the program alone, or with a runner in front (`arch -x86_64 ./ozbox`,
# `qemu-aarch64-static ./ozbox`). The script appends `build-info --json` and reads the program's own answer:
#
#   {"version": "...", "dashboard": {"embedded": true, "sha256": "<64 hex>"}, "placeholder_page": false}
#
# It fails when the program says it has no dashboard, carries the placeholder page, or embedded a different hash.
#
# Why it runs the program instead of searching the file: the content hash is a constant the compiler is free to split into
# pieces, so no byte search can be relied on to find a 64-character string (an optimized x86_64 macOS build kept only 8
# characters of it contiguous). The program's own report is stable, and it is also what proves the file runs.
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: check-embedded-dashboard.sh <expected-sha256> <command...>" >&2
  exit 2
fi
expected="$1"
shift

case "$expected" in
  *[!0-9a-f]* | '') bad=1 ;;
  *) bad=0 ;;
esac
if [ "$bad" = 1 ] || [ "${#expected}" -ne 64 ]; then
  echo "::error title=No dashboard hash::the dashboard build did not give a 64-character content hash (got '$expected')"
  exit 1
fi

# nothing of the machine's own configuration or state is read, and nothing is written
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if ! report="$(OZBOX_CONFIG="$tmp/none.toml" OZBOX_STATE_DIR="$tmp/state" HOME="$tmp" "$@" build-info --json)"; then
  echo "::error title=Program did not answer::'$* build-info --json' failed, so what the program embedded is unknown"
  exit 1
fi

got="$(printf '%s' "$report" | jq -r '.dashboard.sha256 // "missing"')"
embedded="$(printf '%s' "$report" | jq -r '.dashboard.embedded // false')"
placeholder="$(printf '%s' "$report" | jq -r '.placeholder_page | tostring')"

if [ "$placeholder" != "false" ]; then
  echo "::error title=Placeholder dashboard::the program reports the placeholder page is compiled in (placeholder_page=$placeholder). The dashboard was not embedded."
  exit 1
fi
if [ "$embedded" != "true" ]; then
  echo "::error title=No dashboard::the program reports no dashboard is embedded"
  exit 1
fi
if [ "$got" != "$expected" ]; then
  echo "::error title=Wrong dashboard::the program embedded dashboard $got, not this build's $expected"
  exit 1
fi
echo "ok: the program embeds dashboard $got"
