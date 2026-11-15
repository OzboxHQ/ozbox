#!/bin/sh
# Install the `ozbox` program (the command line) on Linux or macOS, from a signed release of this repository.
#
#   Recommended:   download this file, read it, then run it
#                    curl -fsSLO https://raw.githubusercontent.com/OzboxHQ/ozbox/main/scripts/install.sh
#                    less install.sh && sh install.sh
#   It also works piped (curl -fsSL ... | sh), because nothing it downloads is trusted or run before it is verified:
#   the verification happens inside this script, not in the pipe. Reading it first is still the better habit.
#
# What it does, in order:
#   1. works out your system (Linux or macOS; x86_64 or arm64) and the release (the latest, or the one you pin);
#   2. downloads the program, the release manifest `ozbox-cli-manifest.json` and its signature files to a private temporary
#      directory;
#   3. checks the manifest's signature with `cosign verify-blob`: the certificate must name this repository's
#      cli-release workflow (a keyless Sigstore signature; the issuer must be GitHub Actions);
#   4. checks the program's sha256 against the entry in that verified manifest, ALWAYS;
#   5. only then copies it to <prefix>/bin/ozbox (mode 0755, default prefix ~/.local). It never uses sudo and never runs
#      the downloaded program before it has been verified.
#
# Without `cosign` it refuses, and tells you how to install it. `--skip-signature` goes ahead on the sha256 check alone,
# which only catches a damaged download: the manifest comes from the same place as the program, so it proves nothing about
# WHO built it. Use it only if you accept that.
#
# Usage: sh install.sh [--version X.Y.Z] [--prefix DIR] [--dry-run] [--skip-signature] [--help]
# Environment: OZBOX_VERSION (same as --version), PREFIX (same as --prefix), OZBOX_REPO (owner/name, a fork's releases).
# Test only: OZBOX_RELEASE_BASE_URL, OZBOX_RELEASE_API_URL (https:// or file://), OZBOX_UNAME_S, OZBOX_UNAME_M.
# Windows: not supported natively. Use WSL (https://learn.microsoft.com/windows/wsl/install) and run this inside it.

set -eu

REPO="${OZBOX_REPO:-OzboxHQ/ozbox}"
ISSUER="https://token.actions.githubusercontent.com"
VERSION="${OZBOX_VERSION:-}"
PREFIX="${PREFIX:-${HOME:-}/.local}"
DRY_RUN=0
SKIP_SIG=0
TMP=""

say() { printf '%s\n' "$*"; }
warn() { printf 'ozbox install: %s\n' "$*" >&2; }
die() {
  printf 'ozbox install: %s\n' "$*" >&2
  exit 1
}

# shellcheck disable=SC2329 # run by the EXIT trap below
cleanup() {
  if [ -n "$TMP" ] && [ -d "$TMP" ]; then
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

usage() {
  cat <<'USAGE'
Install the ozbox command line from a signed release.

Usage: sh install.sh [options]

  --version X.Y.Z      install this release instead of the latest (also OZBOX_VERSION)
  --prefix DIR         install to DIR/bin (default: $HOME/.local; also PREFIX)
  --dry-run            say what would be downloaded and installed; download and write nothing
  --skip-signature     do not check the Sigstore signature (sha256 against the manifest only). Not recommended.
  --help               this text

The signature check needs cosign: https://docs.sigstore.dev/cosign/system_config/installation/
Windows is not supported natively; use WSL.
USAGE
}

# Everything that does something is inside main, and main is called on the last line: when this file is piped into sh and
# the download stops part way, sh reads an unfinished function and runs nothing, instead of running the part that arrived.
main() {
while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version needs a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --prefix)
      [ $# -ge 2 ] || die "--prefix needs a value"
      PREFIX="$2"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#--prefix=}"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --skip-signature)
      SKIP_SIG=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1 (try --help)"
      ;;
  esac
done

[ -n "$PREFIX" ] || die "no install location: set --prefix or HOME"

# ---- the repository and the (test-only) overrides ---------------------------------------------------------------------
case "$REPO" in
  */*/* | */ | /* | "" | *[!A-Za-z0-9._/-]*) die "OZBOX_REPO must look like owner/name" ;;
  */*) ;;
  *) die "OZBOX_REPO must look like owner/name" ;;
esac

BASE="https://github.com/$REPO/releases"
API="https://api.github.com/repos/$REPO/releases?per_page=50"
if [ -n "${OZBOX_RELEASE_BASE_URL:-}" ]; then
  case "$OZBOX_RELEASE_BASE_URL" in
    https://* | file://*) BASE="${OZBOX_RELEASE_BASE_URL%/}" ;;
    *) die "OZBOX_RELEASE_BASE_URL must be https:// or file://" ;;
  esac
  warn "WARNING: the release location is overridden to $BASE (this is for tests; the signature identity is unchanged)"
fi
if [ -n "${OZBOX_RELEASE_API_URL:-}" ]; then
  case "$OZBOX_RELEASE_API_URL" in
    https://* | file://*) API="$OZBOX_RELEASE_API_URL" ;;
    *) die "OZBOX_RELEASE_API_URL must be https:// or file://" ;;
  esac
fi

# ---- the system ---------------------------------------------------------------------------------------------------------
uname_s="${OZBOX_UNAME_S:-$(uname -s 2>/dev/null || echo unknown)}"
uname_m="${OZBOX_UNAME_M:-$(uname -m 2>/dev/null || echo unknown)}"
case "$uname_s" in
  Linux) OS=linux ;;
  Darwin) OS=darwin ;;
  MINGW* | MSYS* | CYGWIN* | Windows*)
    die "Windows is not supported natively. Install WSL (https://learn.microsoft.com/windows/wsl/install) and run this inside it."
    ;;
  *) die "unsupported operating system: $uname_s. ozbox runs on Linux and macOS (on Windows, use WSL)." ;;
esac
case "$uname_m" in
  x86_64 | amd64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) die "unsupported processor: $uname_m. ozbox is built for x86_64 and arm64 (aarch64)." ;;
esac
ASSET="ozbox-$OS-$ARCH"

# ---- tools --------------------------------------------------------------------------------------------------------------
command -v curl >/dev/null 2>&1 || die "curl is needed and was not found"

# fetch URL DEST MAXBYTES : https only (file:// only when a test override asked for it); never follows a redirect to http.
fetch() {
  _url="$1"
  _dest="$2"
  _max="$3"
  case "$_url" in
    https://*)
      curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 20 --max-time 600 --max-filesize "$_max" --output "$_dest" "$_url"
      ;;
    file://*)
      [ -n "${OZBOX_RELEASE_BASE_URL:-}${OZBOX_RELEASE_API_URL:-}" ] || return 1
      curl --fail --silent --show-error --proto '=file' --output "$_dest" "$_url"
      ;;
    *) return 1 ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d ' ' -f 1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
  else
    die "no sha256 tool found (sha256sum, shasum or openssl)"
  fi
}

make_tmp() {
  if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
    TMP="$(mktemp -d "${TMPDIR:-/tmp}/ozbox-install.XXXXXX")" || die "could not make a temporary directory"
    chmod 700 "$TMP"
  fi
}

# ---- which release ------------------------------------------------------------------------------------------------------
if [ -z "$VERSION" ]; then
  make_tmp
  fetch "$API" "$TMP/releases.json" 5000000 ||
    die "could not list the releases of $REPO (network, or GitHub's rate limit). Pin one with --version X.Y.Z."
  # The same repository publishes machine images (image-v...) and the program (v...): take the newest program release
  # that is not a pre-release (a version with a '-' suffix).
  tag="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$TMP/releases.json" |
    sed 's/.*"\([^"]*\)"$/\1/' |
    grep -E '^v[0-9]+\.[0-9]+(\.[0-9]+)?$' | head -n 1 || true)"
  [ -n "$tag" ] || die "no ozbox program release was found in $REPO yet. Pin one with --version X.Y.Z if you know it."
  VERSION="${tag#v}"
else
  VERSION="${VERSION#cli-v}" # the tag this project used before the single version scheme
  VERSION="${VERSION#v}"
fi
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?(-[0-9a-z.]+)?$' ||
  die "not a release version: $VERSION (expected like 0.1.0 or 0.1.0-rc.1)"
TAG="v$VERSION"
REL="$BASE/download/$TAG"
DEST="$PREFIX/bin/ozbox"

say "ozbox $VERSION for $OS/$ARCH"
say "  from:  $REL/$ASSET"
say "  to:    $DEST"
if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$SKIP_SIG" -eq 1 ]; then
    say "  check: sha256 against the manifest ONLY (--skip-signature)"
  else
    say "  check: Sigstore signature of the manifest (cosign), then sha256 against it"
  fi
  say "dry run: nothing was downloaded or written."
  exit 0
fi

# ---- the signature tool, decided BEFORE downloading anything big --------------------------------------------------------
if [ "$SKIP_SIG" -eq 0 ] && ! command -v cosign >/dev/null 2>&1; then
  die "cosign is not installed, so the release signature cannot be checked, and this installer will not run a program it
cannot authenticate. Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/; on macOS: brew install cosign)
and run this again. If you accept that only the download's integrity is checked, not who built it, add --skip-signature."
fi
if [ "$SKIP_SIG" -eq 1 ]; then
  warn "WARNING: --skip-signature: the Sigstore signature is NOT checked. Only the sha256 from the release's own manifest is,"
  warn "WARNING: which detects a damaged download but not a tampered release. You are trusting the server."
fi

# ---- download everything to a private directory -------------------------------------------------------------------------
make_tmp
MANIFEST="ozbox-cli-manifest.json"
fetch "$REL/$MANIFEST" "$TMP/$MANIFEST" 5000000 || die "could not download $REL/$MANIFEST (does release $TAG exist?)"
if [ "$SKIP_SIG" -eq 0 ]; then
  fetch "$REL/$MANIFEST.sig" "$TMP/$MANIFEST.sig" 5000000 || die "could not download the manifest signature"
  fetch "$REL/$MANIFEST.pem" "$TMP/$MANIFEST.pem" 5000000 || die "could not download the manifest certificate"
  # the bundle is optional (cosign 3 prefers it); the .sig/.pem pair is the form that works on cosign 2 and 3. A failed
  # download leaves no file or an unusable one, and then the pair is used.
  fetch "$REL/$MANIFEST.sigstore.json" "$TMP/$MANIFEST.sigstore.json" 5000000 2>/dev/null || true
fi

# ---- verify the manifest's signature ------------------------------------------------------------------------------------
if [ "$SKIP_SIG" -eq 0 ]; then
  repo_re="$(printf '%s' "$REPO" | sed 's/\./\\./g')"
  identity="^https://github\\.com/$repo_re/\\.github/workflows/cli-release\\.yml@refs/(heads/main|tags/v[0-9a-z.-]+)\$"
  verified=0
  if [ -s "$TMP/$MANIFEST.sigstore.json" ] &&
    cosign verify-blob --bundle "$TMP/$MANIFEST.sigstore.json" \
      --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$ISSUER" "$TMP/$MANIFEST" >/dev/null 2>&1; then
    verified=1
  fi
  if [ "$verified" -eq 0 ] &&
    cosign verify-blob --certificate "$TMP/$MANIFEST.pem" --signature "$TMP/$MANIFEST.sig" \
      --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$ISSUER" "$TMP/$MANIFEST" >/dev/null 2>&1; then
    verified=1
  fi
  [ "$verified" -eq 1 ] ||
    die "the signature on the manifest of $TAG did NOT verify against $REPO's cli-release workflow. Nothing was installed."
  say "signature: verified (signed by $REPO's cli-release workflow)"
fi

# ---- read the manifest: version, and this system's program ---------------------------------------------------------------
flat="$(tr -d ' \t\r\n' <"$TMP/$MANIFEST")"
m_version="$(printf '%s' "$flat" | grep -o '"version":"[^"]*"' | head -n 1 | cut -d '"' -f 4 || true)"
[ "$m_version" = "$VERSION" ] || die "the manifest is for release '${m_version:-?}', not $VERSION. Nothing was installed."
entry="$(printf '%s' "$flat" | grep -o '{[^{}]*"asset":"'"$ASSET"'"[^{}]*}' | head -n 1 || true)"
[ -n "$entry" ] || die "release $TAG has no program for $OS/$ARCH ($ASSET). Nothing was installed."
case "$entry" in
  *'"arch":"'"$ARCH"'"'*) ;;
  *) die "the manifest entry for $ASSET names a different processor. Nothing was installed." ;;
esac
want="$(printf '%s' "$entry" | sed -n 's/.*"sha256":"\([0-9a-fA-F]\{64\}\)".*/\1/p' | tr 'A-F' 'a-f')"
[ -n "$want" ] || die "the manifest has no valid sha256 for $ASSET. Nothing was installed."

# ---- the program, and its hash -------------------------------------------------------------------------------------------
fetch "$REL/$ASSET" "$TMP/$ASSET" 300000000 || die "could not download $REL/$ASSET"
got="$(sha256_of "$TMP/$ASSET" | tr 'A-F' 'a-f')"
[ "$got" = "$want" ] || die "the sha256 of the download ($got) is not the one in the manifest ($want). Nothing was installed."
say "sha256:    $got (matches the manifest)"

# ---- install: only now, atomically, never sudo ---------------------------------------------------------------------------
mkdir -p "$PREFIX/bin" || die "could not create $PREFIX/bin (choose another place with --prefix; this installer never uses sudo)"
STAGE="$PREFIX/bin/.ozbox.install.$$"
cp "$TMP/$ASSET" "$STAGE" || die "could not write to $PREFIX/bin"
chmod 0755 "$STAGE" || die "could not set the program's mode (a partial file $STAGE may remain; delete it)"
mv -f "$STAGE" "$DEST" || die "could not move the program into place (a partial file $STAGE may remain; delete it)"
say "installed: $DEST"
case ":${PATH:-}:" in
  *":$PREFIX/bin:"*) ;;
  *) say "note: $PREFIX/bin is not on your PATH. Add it, for example:  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
# The program has been verified, so it may be run now.
"$DEST" --version 2>/dev/null || warn "installed, but '$DEST --version' did not run on this system"
exit 0
}

main "$@"
