#!/usr/bin/env bash
# Tests for npm-packages.sh: the empty list is a no-op, a listed package is packed and its tarball smoke-tested in a clean
# directory, and a broken package fails. Needs node and npm; no network (the package has no dependencies).
# Run: bash scripts/release/test-npm-packages.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/npm-packages.sh"
root="$(cd "$here/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/ozbox-npm-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT
n=0
ok() { n=$((n + 1)); echo "ok   $1"; }

# the real list is empty, and a dry run says so
out="$("$script" dry-run)"
[ -z "$("$script" list)" ] && grep -q "nothing to do" <<<"$out"
ok "the shipped list is empty and a dry run is a no-op"

# a fake package inside the repository tree (the script only accepts paths under it)
pkg="packaging/.test-npm-pkg-$$"
mkdir -p "$root/$pkg"
trap 'rm -rf "$work" "$root/$pkg"' EXIT
cat >"$root/$pkg/package.json" <<'JSON'
{ "name": "ozbox-test-pkg", "version": "1.2.3", "main": "index.js" }
JSON
echo 'module.exports = { hello: () => "hi" };' >"$root/$pkg/index.js"

printf '# comment\n\n%s :: node -e "if (require(\x27ozbox-test-pkg\x27).hello() !== \x27hi\x27) process.exit(1)"\n' "$pkg" >"$work/list.txt"
export OZBOX_NPM_LIST="$work/list.txt"
[ "$("$script" list)" = "$pkg" ]
ok "list prints the package directory, skipping comments"
"$script" smoke "$pkg" >/dev/null
ok "a packed tarball installs in a clean directory and its smoke command passes"
"$script" dry-run >/dev/null
ok "dry-run smoke-tests every listed package"
"$script" check-version "$pkg" 1.2.3
ok "check-version accepts the matching version"
if "$script" check-version "$pkg" 9.9.9 2>/dev/null; then exit 1; fi
ok "check-version refuses a different version"

printf '%s :: node -e "process.exit(1)"\n' "$pkg" >"$work/list.txt"
if "$script" smoke "$pkg" >/dev/null 2>&1; then exit 1; fi
ok "a failing smoke command fails the run"

printf '%s\n' "$pkg" >"$work/list.txt"
if "$script" smoke "$pkg" >/dev/null 2>&1; then exit 1; fi
ok "a package with no smoke command is refused"

printf '../escape :: true\n' >"$work/list.txt"
if "$script" list >/dev/null 2>&1; then exit 1; fi
ok "a path that leaves the repository is refused"

echo "$n passed"
