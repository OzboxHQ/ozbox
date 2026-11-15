#!/usr/bin/env bash
# shellcheck disable=SC2030,SC2031 # the pretend-host variables are set in subshells on purpose
# Tests for scripts/install.sh. No network: a fake release lives in a temporary directory and is reached through file://.
# cosign is faked (a stub that records its arguments) or hidden, so the signature paths are tested without Sigstore.
# Run: bash scripts/release/test-install.sh
set -uo pipefail
# the cases below assume a Linux x86_64 host unless a case says otherwise (the script reads these only for tests)
export OZBOX_UNAME_S=Linux OZBOX_UNAME_M=x86_64
here="$(cd "$(dirname "$0")" && pwd)"
installer="$here/../install.sh"
work="$(mktemp -d "${TMPDIR:-/tmp}/ozbox-install-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0
ok() {
  pass=$((pass + 1))
  printf 'ok   %s\n' "$1"
}
bad() {
  fail=$((fail + 1))
  printf 'FAIL %s\n' "$1"
}
check() { # check NAME CONDITION-EXIT-STATUS
  if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi
}

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1; else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}

# ---- a PATH with the tools the installer needs and no cosign -------------------------------------------------------------
nocosign="$work/path-nocosign"
mkdir -p "$nocosign"
for t in sh uname curl grep sed tr cut head mktemp chmod cp mv rm mkdir cat sha256sum shasum openssl dirname printf; do
  p="$(command -v "$t" 2>/dev/null || true)"
  if [ -n "$p" ] && [ -x "$p" ]; then
    # a wrapper, not a symlink: some tools (macOS shasum, a perl script) misbehave when run under another path
    printf '#!/bin/sh\nexec "%s" "$@"\n' "$p" >"$nocosign/$t"
    chmod +x "$nocosign/$t"
  fi
done
# a stub cosign: records its arguments; passes or fails as STUB_COSIGN says
withcosign="$work/path-cosign"
cp -R "$nocosign" "$withcosign"
cat >"$withcosign/cosign" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" >>"${STUB_COSIGN_LOG:-/dev/null}"
[ "${STUB_COSIGN:-pass}" = "pass" ]
STUB
chmod +x "$withcosign/cosign"

# ---- a fake release tree: <base>/download/v<version>/<files> ---------------------------------------------------------
make_release() { # make_release VERSION [pretty|compact]
  local version="$1" style="${2:-pretty}" dir="$work/releases/download/v$1"
  mkdir -p "$dir"
  local entries="" os arch asset sum first=1
  for os in linux darwin; do
    for arch in x86_64 aarch64; do
      asset="ozbox-$os-$arch"
      printf '#!/bin/sh\necho "ozbox %s %s-%s"\n' "$version" "$os" "$arch" >"$dir/$asset"
      chmod +x "$dir/$asset"
      sum="$(sha "$dir/$asset")"
      if [ "$style" = pretty ]; then
        [ $first -eq 1 ] || entries="$entries,"
        entries="$entries
    {
      \"os\": \"$os\",
      \"arch\": \"$arch\",
      \"asset\": \"$asset\",
      \"sha256\": \"$sum\"
    }"
      else
        [ $first -eq 1 ] || entries="$entries,"
        entries="$entries{\"os\":\"$os\",\"arch\":\"$arch\",\"asset\":\"$asset\",\"sha256\":\"$sum\"}"
      fi
      first=0
    done
  done
  printf '{\n  "version": "%s",\n  "source_commit": "0000000000000000000000000000000000000000",\n  "built_at": "2026-01-01T00:00:00Z",\n  "dashboard": "%s",\n  "binaries": [%s\n  ]\n}\n' \
    "$version" "$(printf '%064d' 0)" "$entries" >"$dir/ozbox-cli-manifest.json"
  printf 'sig' >"$dir/ozbox-cli-manifest.json.sig"
  printf 'cert' >"$dir/ozbox-cli-manifest.json.pem"
}

make_release 0.1.0 pretty
make_release 0.2.0 compact
base="file://$work/releases"
cat >"$work/releases.json" <<'JSON'
[
  {"tag_name": "image-v2026.11.10-1", "prerelease": false},
  {"tag_name": "v0.3.0-rc.1", "prerelease": true},
  {"tag_name": "v0.2.0", "prerelease": false, "author": {"login": "x"}},
  {"tag_name": "v0.1.0", "prerelease": false}
]
JSON
api="file://$work/releases.json"

# run NAME-OF-PATH-DIR args... : sets OUT and STATUS. PREFIX is a fresh directory each time.
run() {
  local pathdir="$1"
  shift
  PFX="$work/prefix-$((++counter))"
  set +e
  OUT="$(PATH="$pathdir" OZBOX_UNAME_S="${OZBOX_UNAME_S:-Linux}" OZBOX_UNAME_M="${OZBOX_UNAME_M:-x86_64}" \
    OZBOX_RELEASE_BASE_URL="$base" OZBOX_RELEASE_API_URL="$api" PREFIX="$PFX" HOME="$work/home" \
    "$nocosign/sh" "$installer" "$@" 2>&1)"
  STATUS=$?
  set -e
}
counter=0
installed() { [ -e "$PFX/bin/ozbox" ]; }
contains() { printf '%s' "$OUT" | grep -qF -- "$1"; }

# 1. no cosign: refuses, installs nothing, says how to get cosign
run "$nocosign" --version 0.1.0
{ [ "$STATUS" -ne 0 ] && ! installed && contains "cosign is not installed"; }
check "refuses without cosign and installs nothing" $?

# 2. --skip-signature: installs on the sha256 check alone, with a loud warning; mode 0755; the right program
run "$nocosign" --version 0.1.0 --skip-signature
{ [ "$STATUS" -eq 0 ] && installed && contains "WARNING" && contains "ozbox 0.1.0 linux-x86_64"; }
check "--skip-signature installs, warns, runs the installed program" $?
# shellcheck disable=SC2012
mode="$(ls -l "$PFX/bin/ozbox" 2>/dev/null | cut -c1-10 || true)"
rc=1
[ "$mode" = "-rwxr-xr-x" ] && rc=0
check "installed mode is 0755 ($mode)" "$rc"

# 3. with a cosign that accepts: the identity is this repository's cli-release workflow and the GitHub issuer
log="$work/cosign.log"
: >"$log"
export STUB_COSIGN_LOG="$log"
STUB_COSIGN=pass run "$withcosign" --version 0.2.0
{ [ "$STATUS" -eq 0 ] && installed && grep -q 'verify-blob' "$log" &&
  grep -qF 'cli-release\.yml' "$log" && grep -qF 'OzboxHQ/ozbox' "$log"; }
check "signature verified through cosign with the workflow identity" $?
grep -q 'https://token.actions.githubusercontent.com' "$log"
check "the GitHub Actions issuer is required" $?
contains "ozbox 0.2.0"
check "compact manifest format is read" $?

# 4. a cosign that rejects: nothing installed
STUB_COSIGN=fail run "$withcosign" --version 0.1.0
{ [ "$STATUS" -ne 0 ] && ! installed && contains "did NOT verify"; }
check "a failed signature check installs nothing" $?

# 5. a tampered program: sha256 mismatch fails, leaves nothing, and the program was never run
mkdir -p "$work/tampered/download/v0.1.0"
cp "$work/releases/download/v0.1.0/"* "$work/tampered/download/v0.1.0/"
marker="$work/ran-marker"
printf '#!/bin/sh\ntouch "%s"\necho evil\n' "$marker" >"$work/tampered/download/v0.1.0/ozbox-linux-x86_64"
base_saved="$base"
base="file://$work/tampered"
run "$nocosign" --version 0.1.0 --skip-signature
{ [ "$STATUS" -ne 0 ] && ! installed && contains "sha256" && [ ! -e "$marker" ]; }
check "bad sha256 fails, installs nothing, never runs the download" $?
rc=1
{ [ ! -d "$PFX/bin" ] || [ -z "$(ls -A "$PFX/bin")" ]; } && rc=0
check "bad sha256 leaves no stray files" "$rc"
base="$base_saved"

# 6. systems that are refused
( export OZBOX_UNAME_M=armv7l; run "$nocosign" --version 0.1.0 --skip-signature; printf "%s\n%s\n" "$STATUS" "$OUT" >"$work/sub" )
STATUS="$(head -n1 "$work/sub")"; OUT="$(tail -n +2 "$work/sub")"
{ [ "$STATUS" -ne 0 ] && ! installed && contains "unsupported processor"; }
check "an unsupported processor is refused" $?
( export OZBOX_UNAME_S=MINGW64_NT-10.0; run "$nocosign" --version 0.1.0 --skip-signature; printf "%s\n%s\n" "$STATUS" "$OUT" >"$work/sub" )
STATUS="$(head -n1 "$work/sub")"; OUT="$(tail -n +2 "$work/sub")"
{ [ "$STATUS" -ne 0 ] && contains "WSL"; }
check "Windows is refused and points at WSL" $?
( export OZBOX_UNAME_S=FreeBSD; run "$nocosign" --version 0.1.0 --skip-signature; printf "%s\n%s\n" "$STATUS" "$OUT" >"$work/sub" )
STATUS="$(head -n1 "$work/sub")"; OUT="$(tail -n +2 "$work/sub")"
{ [ "$STATUS" -ne 0 ] && contains "unsupported operating system"; }
check "another operating system is refused" $?

# 7. macOS picks the darwin program; arm64 spelling is accepted
( export OZBOX_UNAME_S=Darwin OZBOX_UNAME_M=arm64; run "$nocosign" --version 0.1.0 --skip-signature; printf "%s\n%s\n" "$STATUS" "$OUT" >"$work/sub" )
STATUS="$(head -n1 "$work/sub")"; OUT="$(tail -n +2 "$work/sub")"
{ [ "$STATUS" -eq 0 ] && contains "ozbox 0.1.0 darwin-aarch64"; }
check "macOS arm64 installs the darwin-aarch64 program" $?

# 8. pinning: --version, OZBOX_VERSION, and the v prefix (and the old cli-v one)
run "$nocosign" --version 0.1.0 --skip-signature
contains "linux-x86_64" && contains "ozbox 0.1.0"
check "--version 0.1.0 installs 0.1.0" $?
OZBOX_VERSION=v0.2.0 run "$nocosign" --skip-signature
contains "ozbox 0.2.0"
check "OZBOX_VERSION=v0.2.0 installs 0.2.0" $?

# 9. latest: the newest program release that is not a pre-release and not an image release
run "$nocosign" --skip-signature
{ [ "$STATUS" -eq 0 ] && contains "ozbox 0.2.0 linux"; }
check "latest picks v0.2.0 (skips the image release and the pre-release)" $?

# 10. dry run writes nothing and does not need the release to exist
run "$nocosign" --version 9.9.9 --dry-run
{ [ "$STATUS" -eq 0 ] && ! installed && [ ! -d "$PFX" ] && contains "dry run"; }
check "--dry-run downloads and writes nothing" $?

# 11. a manifest for another release is refused
mkdir -p "$work/mismatch/download/v0.1.0"
cp "$work/releases/download/v0.2.0/"* "$work/mismatch/download/v0.1.0/"
base="file://$work/mismatch"
run "$nocosign" --version 0.1.0 --skip-signature
{ [ "$STATUS" -ne 0 ] && ! installed && contains "not 0.1.0"; }
check "a manifest naming another release is refused" $?
base="$base_saved"

# 12. a release with no program for this system
mkdir -p "$work/noarch/download/v0.1.0"
cp "$work/releases/download/v0.1.0/"* "$work/noarch/download/v0.1.0/"
sed 's/ozbox-darwin-aarch64/ozbox-darwin-other/' "$work/releases/download/v0.1.0/ozbox-cli-manifest.json" \
  >"$work/noarch/download/v0.1.0/ozbox-cli-manifest.json"
base="file://$work/noarch"
( export OZBOX_UNAME_S=Darwin OZBOX_UNAME_M=arm64; run "$nocosign" --version 0.1.0 --skip-signature; printf "%s\n%s\n" "$STATUS" "$OUT" >"$work/sub" )
STATUS="$(head -n1 "$work/sub")"; OUT="$(tail -n +2 "$work/sub")"
{ [ "$STATUS" -ne 0 ] && ! installed && contains "no program for darwin/aarch64"; }
check "a release without this system's program is refused" $?
base="$base_saved"

# 13. the test-only overrides must be https or file
set +e
OUT="$(PATH="$nocosign" OZBOX_RELEASE_BASE_URL="http://example.invalid/x" "$nocosign/sh" "$installer" --version 0.1.0 --dry-run 2>&1)"
STATUS=$?
set -e
{ [ "$STATUS" -ne 0 ] && contains "https:// or file://"; }
check "a plain http release location is refused" $?

# 14. file:// is not usable without the override (the real default is https only)
set +e
OUT="$(PATH="$nocosign" OZBOX_REPO="bad repo" "$nocosign/sh" "$installer" --dry-run 2>&1)"
STATUS=$?
set -e
{ [ "$STATUS" -ne 0 ] && contains "owner/name"; }
check "a malformed OZBOX_REPO is refused" $?

# 15. --help works and names the safe way
set +e
OUT="$("$nocosign/sh" "$installer" --help 2>&1)"
STATUS=$?
set -e
{ [ "$STATUS" -eq 0 ] && contains "--skip-signature"; }
check "--help prints usage" $?

# 16. a download that stops part way runs nothing: every cut of the file before its last line is only definitions
set +e
cuts_ok=0
size="$(wc -c <"$installer" | tr -d ' ')"
last="$(tail -n 1 "$installer")"
for cut in 200 1000 3000 6000 9000 $((size - ${#last} - 2)); do
  OUT="$(head -c "$cut" "$installer" | PATH="$nocosign" PREFIX="$work/cut-$cut" "$nocosign/sh" -s -- --help 2>&1)"
  # sh may complain about the unfinished function; what must not happen is the body running (usage printed, a folder made)
  case "$OUT" in *"Install the ozbox"* | *"ozbox install:"*) cuts_ok=1 ;; esac
  if [ -e "$work/cut-$cut" ]; then cuts_ok=1; fi
done
set -e
[ "$last" = 'main "$@"' ] && [ "$cuts_ok" -eq 0 ]
check "a truncated download runs nothing" $?

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
