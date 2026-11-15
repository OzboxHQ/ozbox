#!/bin/sh
# Prints the first-boot hash of an infra folder (default: this checkout's infra/): the SHA-256 of the sha256sum listing of
# the first-boot configuration and the two box modules (their .tf, .tftpl and .sh files only), sorted by path, without
# hidden files and tests folders. The same rule as `ozbox_core::infra` and the program's build (`ozbox infra` prints the
# program's own); the image workflow records it in the signed manifest as `first_boot`. Like the build, it refuses a tree
# with OpenTofu state, variables or a saved plan in it.
set -eu
root="${1:-$(dirname "$0")/../infra}"
if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$@"; }
else
  sum() { shasum -a 256 "$@"; }
fi
cd "$root"
stray="$(find cloud-init tofu/modules ! -path '*/.*' \( -name '*.tfstate*' -o -name 'terraform.tfstate.d' -o -name '*.tfvars' \
  -o -name '*.tfvars.json' -o -name '*.tfplan' \) -print)"
if [ -n "$stray" ]; then
  echo "OpenTofu state, variables or a saved plan is lying in the box modules; move it out of infra/ first:" >&2
  echo "$stray" >&2
  exit 1
fi
find cloud-init tofu/modules/aws-box tofu/modules/hcloud-box -type f ! -path '*/.*' ! -path '*/tests/*' \
  \( -name '?*.tf' -o -name '?*.tftpl' -o -name '?*.sh' \) \
  | LC_ALL=C sort | while IFS= read -r f; do sum "$f"; done | sum | cut -d' ' -f1
