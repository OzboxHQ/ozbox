#!/usr/bin/env bash
# Checks that the cosign this pipeline installed accepts the flags cli-release.yml signs with, without Sigstore and without
# a network identity: it signs a file with a throwaway key, writes the signature and the bundle exactly as the release
# does, and verifies them. A pin that names a cosign version that does not exist, or flags that version dropped (cosign 3
# no longer writes --output-signature), fails here, in the dry run, instead of at the first real release.
#
# Usage: scripts/release/cosign-smoke.sh   (cosign must be on PATH)
set -euo pipefail

command -v cosign >/dev/null || {
  echo "cosign-smoke: cosign is not on PATH" >&2
  exit 1
}
version="$(cosign version 2>&1 | sed -n 's/^GitVersion: *v\{0,1\}\([0-9][0-9.]*\).*/\1/p' | head -n 1)"
major="${version%%.*}"
echo "cosign-smoke: cosign $version"
[ -n "$major" ] || {
  echo "cosign-smoke: could not read the cosign version" >&2
  exit 1
}

dir="$(mktemp -d "${TMPDIR:-/tmp}/ozbox-cosign-smoke.XXXXXX")"
trap 'rm -rf "$dir"' EXIT
cd "$dir"
printf 'smoke\n' >artefact
export COSIGN_PASSWORD=""
cosign generate-key-pair >/dev/null

# the release signs keyless with these flags; here a key replaces the identity and the transparency log is not used
cosign sign-blob --yes artefact --key cosign.key --tlog-upload=false \
  --output-signature artefact.sig --bundle artefact.sigstore.json >/dev/null

if [ "$major" -lt 3 ]; then
  # cosign 2 writes the signature file the release (and `ozbox dashboard install`) rely on
  test -s artefact.sig || {
    echo "cosign-smoke: no .sig was written" >&2
    exit 1
  }
  cosign verify-blob --key cosign.pub --signature artefact.sig --insecure-ignore-tlog artefact >/dev/null
else
  echo "cosign-smoke: cosign $major does not write .sig files; the release pins cosign 2 for that reason" >&2
  exit 1
fi
test -s artefact.sigstore.json
echo "cosign-smoke: ok"
