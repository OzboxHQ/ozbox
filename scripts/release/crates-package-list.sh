#!/usr/bin/env bash
# Lists what `cargo package` would put in each crate, in dependency order. This is the part of a crates.io dry run that works
# today: a full `cargo package` (which compiles the unpacked crate) cannot, because the workspace's crates depend on each
# other by path with no version, and cargo refuses to package that. So the dry run checks the file lists, and reports the
# facts the owner needs to decide on publishing (see docs/releasing.md, "crates.io"):
#   - which crates are still `publish = false`
#   - whether the dashboard the program embeds is part of the ozbox-cli package
#
# It never publishes and never needs a registry token. Run from anywhere inside the repository.
set -euo pipefail
cd "$(dirname "$0")/../.."

meta="$(cargo metadata --no-deps --offline --format-version 1)"
# dependencies first: repeatedly take the crates whose path dependencies are all placed already
order=()
remaining="$(jq -r '.packages[].name' <<<"$meta" | sort)"
while [ -n "$remaining" ]; do
  progressed=0
  candidates=()
  while IFS= read -r line; do candidates+=("$line"); done < <(printf '%s\n' "$remaining")
  for c in "${candidates[@]}"; do
    unplaced="$(jq -r --arg c "$c" '.packages[] | select(.name == $c) | .dependencies[] | select(.path != null) | .name' <<<"$meta" |
      grep -vxF -f <(printf '%s\n' "${order[@]+"${order[@]}"}") || true)"
    if [ -z "$unplaced" ]; then
      order+=("$c")
      remaining="$(printf '%s\n' "$remaining" | grep -vxF "$c" || true)"
      progressed=1
    fi
  done
  if [ "$progressed" -eq 0 ]; then
    echo "crates-package-list: the crates depend on each other in a cycle: $remaining" >&2
    exit 1
  fi
done
echo "crates-package-list: publish order: ${order[*]}"

for c in "${order[@]}"; do
  n="$(cargo package --list --allow-dirty --locked -p "$c" 2>/dev/null | wc -l | tr -d ' ')"
  echo "crates-package-list: $c: $n files"
done

echo "crates-package-list: publish = false in: $(jq -r '[.packages[] | select(.publish == []) | .name] | join(", ")' <<<"$meta")"
if cargo package --list --allow-dirty --locked -p ozbox-cli 2>/dev/null | grep -q 'dashboard.*index\.html'; then
  echo "crates-package-list: the ozbox-cli package carries the dashboard"
else
  echo "crates-package-list: NOTE the ozbox-cli package does NOT carry the dashboard, so a crates.io build would serve the placeholder page"
  echo "crates-package-list: (a release build refuses that; see docs/releasing.md)"
fi
