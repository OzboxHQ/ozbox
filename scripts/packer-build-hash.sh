#!/bin/sh
# Prints the build hash of the image recipe (default: this checkout's infra/packer/ozbox-image): the SHA-256 of the
# sha256sum listing of every tracked file of the Packer template folder (the template, provision.sh, the helper scripts),
# sorted by path. It is one part of the disk generation (ADR 0038): a change to how the image is built moves it, even when
# the change leaves no trace in the package map. Left out, because they are not the recipe: the folder's build outputs
# (`agent/`, the Packer manifest and the lists downloaded after a build) and the two files only the release workflow
# reads (`upgrade-policy.json`, `upgrade-record.jq`), which describe the record and never reach a disk.
set -eu
root="${1:-$(dirname "$0")/../infra/packer/ozbox-image}"
if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$@"; }
else
  sum() { shasum -a 256 "$@"; }
fi
cd "$root"
find . -type f ! -path './agent/*' ! -path '*/.*' \
  ! -name 'packer-manifest-*' ! -name 'packages-*' ! -name 'dpkg-status-*' ! -name 'disk-parts-*' \
  ! -name 'upgrade-policy.json' ! -name 'upgrade-record.jq' \
  | LC_ALL=C sort | while IFS= read -r f; do sum "$f"; done | sum | cut -d' ' -f1
