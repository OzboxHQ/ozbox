#!/usr/bin/env bash
# Put the box daemon (ozboxd) on a machine that does not carry it, from the signed release of the Oz Box image.
#
# The Oz image carries ozboxd (it is built, tested and signed in the same workflow run as the image, and its SHA-256 is
# in the signed image manifest). A machine made from stock Ubuntu does not, so first boot calls this script, which:
#   - does nothing on an Oz image (/etc/ozbox/image-release exists) or when ozboxd is already installed, unless
#     --force is given (the admin action `reinstall-ozboxd` gives it);
#   - downloads the manifest of the release, checks its Sigstore signature when cosign is installed, reads the SHA-256
#     it lists for this machine's architecture, downloads ozboxd, and installs it only if the SHA-256 matches. A
#     mismatch removes the download and installs nothing. Without cosign the check is the SHA-256 only, and it says so.
#   - --sha256 <hex> uses a hash someone already verified (the `ozbox` program checks the signature on the operator's
#     computer and passes the hash); the download must still match it.
#   - also installs the `ozbox` program at /usr/local/bin/ozbox (root:root 0755) when the manifest lists one for this
#     architecture (key `ozbox`): the secrets units run it as the secrets user, so the box user must not be able to
#     replace it. A manifest without that key installs only ozboxd. A hash given with --sha256 covers ozboxd only, so
#     with it the program is left alone unless --ozbox-sha256 <hex> is given too.
# Settings come from /etc/ozbox/agent-release.env (OZBOX_RELEASE_REPO=owner/repo, OZBOX_RELEASE_TAG=image-v<version>, or
# empty for the newest image release). Nothing here is a secret.
# Environment (for tests): OZBOX_CLI_DEST, OZBOX_AGENT_DEST, OZBOX_AGENT_CONF, OZBOX_IMAGE_MARKER, OZBOX_CURL, OZBOX_RELEASE_BASE.
set -euo pipefail

dest="${OZBOX_AGENT_DEST:-/usr/local/bin/ozboxd}"
conf="${OZBOX_AGENT_CONF:-/etc/ozbox/agent-release.env}"
marker="${OZBOX_IMAGE_MARKER:-/etc/ozbox/image-release}"
curl_bin="${OZBOX_CURL:-curl}"
cli_dest="${OZBOX_CLI_DEST:-$(dirname "$dest")/ozbox}"

force=0
want_sha=""
want_cli_sha=""
tag_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=1 ;;
    --sha256) shift; want_sha="${1:-}" ;;
    --ozbox-sha256) shift; want_cli_sha="${1:-}" ;;
    --tag) shift; tag_arg="${1:-}" ;;
    *) echo "ozbox-install-agent: unknown option" >&2; exit 2 ;;
  esac
  shift
done

say() { echo "ozbox-install-agent: $*"; }
die() { echo "ozbox-install-agent: $*" >&2; exit 1; }

if [ "$force" = 0 ]; then
  if [ -f "$marker" ]; then say "this is an Oz image: its ozboxd is part of the image; nothing to install"; exit 0; fi
  if [ -x "$dest" ] && [ -x "$cli_dest" ]; then say "ozboxd and ozbox are already installed"; exit 0; fi
fi

OZBOX_RELEASE_REPO=""
OZBOX_RELEASE_TAG=""
if [ -f "$conf" ]; then
  # shellcheck disable=SC1090
  . "$conf"
fi
repo="$OZBOX_RELEASE_REPO"
tag="${tag_arg:-$OZBOX_RELEASE_TAG}"
[ -n "$repo" ] || { say "no release repository is configured; ozboxd was not installed"; exit 0; }
printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || die "the release repository is not owner/name"
[ -z "$want_sha" ] || printf '%s' "$want_sha" | grep -Eq '^[0-9a-f]{64}$' || die "the given SHA-256 is not 64 hex digits"
[ -z "$want_cli_sha" ] || printf '%s' "$want_cli_sha" | grep -Eq '^[0-9a-f]{64}$' || die "the given SHA-256 is not 64 hex digits"

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported machine type $(uname -m)" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fetch() { "$curl_bin" --fail --silent --show-error --location --retry 3 --proto '=https' --tlsv1.2 --output "$2" "$1"; }

if [ -z "$tag" ]; then
  fetch "https://api.github.com/repos/$repo/releases?per_page=30" "$work/releases.json" || die "could not list the releases of $repo"
  tag="$(grep -o '"tag_name": *"image-v[0-9a-z.-]*"' "$work/releases.json" | head -n 1 | sed 's/.*"\(image-v[^"]*\)"/\1/')"
  [ -n "$tag" ] || die "$repo has no image release"
fi
printf '%s' "$tag" | grep -Eq '^image-v[0-9a-z.-]+$' || die "the release tag is not image-v<version>"
base="${OZBOX_RELEASE_BASE:-https://github.com/$repo/releases/download/$tag}"

sha_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

expected="$want_sha"
cli_expected="$want_cli_sha"
if [ -z "$expected" ]; then
  fetch "$base/ozbox-image-manifest.json" "$work/manifest.json" || die "could not download the manifest of $tag"
  if command -v cosign >/dev/null 2>&1; then
    fetch "$base/ozbox-image-manifest.json.sig" "$work/manifest.sig" || die "could not download the manifest signature"
    fetch "$base/ozbox-image-manifest.json.pem" "$work/manifest.pem" || die "could not download the manifest certificate"
    escaped="$(printf '%s' "$repo" | sed 's/[.-]/\\&/g')"
    cosign verify-blob \
      --certificate-identity-regexp "^https://github\\.com/$escaped/\\.github/workflows/image\\.yml@refs/(heads/main|tags/image-v[0-9a-z.-]+)\$" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --signature "$work/manifest.sig" --certificate "$work/manifest.pem" "$work/manifest.json" >/dev/null 2>&1 \
      || die "the signature on the manifest of $tag did not verify; ozboxd was not installed"
    say "the manifest signature verified"
  else
    say "cosign is not installed: checking the SHA-256 only"
  fi
  flat="$(tr -d ' \n\r\t' <"$work/manifest.json")"
  block="$(printf '%s' "$flat" | grep -o '"ozboxd":{[^}]*}' | head -n 1 || true)"
  expected="$(printf '%s' "$block" | grep -o "\"$arch\":\"[0-9a-f]\{64\}\"" | grep -o '[0-9a-f]\{64\}' || true)"
  [ -n "$expected" ] || die "the manifest of $tag lists no ozboxd for $arch; nothing was installed"
  cli_block="$(printf '%s' "$flat" | grep -o '"ozbox":{[^}]*}' | head -n 1 || true)"
  cli_expected="$(printf '%s' "$cli_block" | grep -o "\"$arch\":\"[0-9a-f]\{64\}\"" | grep -o '[0-9a-f]\{64\}' || true)"
fi

# Both downloads are checked before either is installed, so a bad program leaves the machine as it was.
if [ -n "$cli_expected" ]; then
  fetch "$base/ozbox-linux-$arch" "$work/ozbox" || die "could not download ozbox for $arch"
  if [ "$(sha_of "$work/ozbox")" != "$cli_expected" ]; then
    die "the downloaded ozbox does not match the SHA-256 in the release; nothing was installed"
  fi
fi

fetch "$base/ozboxd-linux-$arch" "$work/ozboxd" || die "could not download ozboxd for $arch"
actual="$(sha_of "$work/ozboxd")"
if [ "$actual" != "$expected" ]; then
  rm -f "$work/ozboxd"
  die "the downloaded ozboxd does not match the SHA-256 in the release; nothing was installed"
fi

install -d "$(dirname "$dest")"
install -m 0755 "$work/ozboxd" "$dest.new"
if [ "$(id -u)" = 0 ]; then chown root:root "$dest.new"; fi
mv -f "$dest.new" "$dest"
if [ -n "$cli_expected" ]; then
  install -d "$(dirname "$cli_dest")"
  install -m 0755 "$work/ozbox" "$cli_dest.new"
  if [ "$(id -u)" = 0 ]; then chown root:root "$cli_dest.new"; fi
  mv -f "$cli_dest.new" "$cli_dest"
  say "installed ozbox from $tag for $arch (sha256 $cli_expected)"
else
  say "no ozbox was installed (the release lists none, or only an ozboxd hash was given)"
fi
say "installed ozboxd from $tag for $arch (sha256 $expected)"
