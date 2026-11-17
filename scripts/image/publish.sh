#!/usr/bin/env bash
# Makes a release's images public, AFTER the release manifest is built and signed (ADR 0052): the manifest, not the image's
# visibility, is what a client trusts, so an image must never be public while its release is unsigned.
#
#   scripts/image/publish.sh --manifest ozbox-image-manifest.json --version 0.3.0 --regions us-east-1,eu-west-1 [--apply]
#
# Reads the image ids from the manifest (`images[].amis`, region to id), makes sure each one is tagged as ours in its region
# (a copy is not always tagged), and then grants the `all` launch permission. DOES NOTHING unless --apply is given.
#
# All or nothing: an image that is already public is skipped (so a half-public release can be published again), and if any other
# image cannot be made public, the ones made public in THIS run are made private again and the script fails, so a release is
# never left half public by it. Run make-room.sh first: AWS limits public images per region, and a full quota is the usual reason.
set -euo pipefail
apply=0
manifest=""
version=""
regions=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) manifest="${2:?}"; shift 2 ;;
    --version) version="${2:?}"; shift 2 ;;
    --regions) regions="${2:?}"; shift 2 ;;
    --apply) apply=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$' || { echo "--version must be a version like 0.3.0" >&2; exit 2; }
[ -f "$manifest" ] || { echo "--manifest must be the signed manifest file" >&2; exit 2; }
[ -n "$regions" ] || { echo "--regions is required" >&2; exit 2; }
jq -e --arg v "$version" '.version == $v' "$manifest" >/dev/null || { echo "the manifest is not for version $version" >&2; exit 1; }
aws_cmd="${OZBOX_AWS:-aws}"

made=() # "region id" for every image this run made public
rollback() {
  local entry r i
  for ((n = ${#made[@]} - 1; n >= 0; n--)); do
    entry="${made[$n]}"; r="${entry%% *}"; i="${entry##* }"
    if "$aws_cmd" ec2 modify-image-attribute --region "$r" --image-id "$i" --launch-permission 'Remove=[{Group=all}]' >/dev/null 2>&1; then
      echo "rolled back: $i is private again in $r" >&2
    else
      echo "COULD NOT make $i private again in $r; do it by hand" >&2
    fi
  done
}
abort() {
  echo "$1" >&2
  if [ "${#made[@]}" -gt 0 ]; then echo "making the ${#made[@]} image(s) this run made public private again, so the release is not left half public" >&2; rollback; fi
  exit 1
}

for region in ${regions//,/ }; do
  printf '%s' "$region" | grep -Eq '^[a-z]{2}-[a-z]+-[0-9]$' || { echo "not a region name: $region" >&2; exit 2; }
  ids="$(jq -r --arg r "$region" '.images[].amis[$r] // empty' "$manifest")"
  [ -n "$ids" ] || { echo "the manifest lists no image for $region" >&2; exit 1; }
  for id in $ids; do
    printf '%s' "$id" | grep -Eq '^ami-[0-9a-f]{8,17}$' || { echo "not an image id: $id" >&2; exit 1; }
  done
done

for region in ${regions//,/ }; do
  for id in $(jq -r --arg r "$region" '.images[].amis[$r] // empty' "$manifest"); do
    already="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" --query 'Images[0].Public' --output text)" \
      || abort "could not read $id in $region"
    if [ "$already" = "True" ]; then echo "$region $id (already public, skipped)"; continue; fi
    echo "$region $id"
    [ "$apply" = 1 ] || continue
    snaps="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" \
      --query 'Images[0].BlockDeviceMappings[].Ebs.SnapshotId' --output text)" || abort "could not read the snapshots of $id in $region"
    "$aws_cmd" ec2 create-tags --region "$region" --resources "$id" $snaps --tags \
      "Key=ozbox-managed,Value=true" "Key=ozbox-image,Value=$version" "Key=ozbox-image-version,Value=$version" \
      || abort "could not tag $id in $region"
    if ! err="$("$aws_cmd" ec2 modify-image-attribute --region "$region" --image-id "$id" --launch-permission 'Add=[{Group=all}]' 2>&1)"; then
      echo "$err" >&2
      if printf '%s' "$err" | grep -q 'ResourceLimitExceeded'; then
        abort "$id could not be made public in $region: AWS's quota on public images is full there (5 per region unless raised). Run scripts/image/make-room.sh to make the oldest Oz Box versions private, or ask AWS Support to raise the 'Public AMIs' quota, then publish this release again; it skips what is already public."
      fi
      abort "$id could not be made public in $region"
    fi
    made+=("$region $id")
    # read it back: an account that blocks public sharing refuses quietly in some regions, and a release must not be
    # reported as published when its image is not
    pub="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" --query 'Images[0].Public' --output text)" || pub=""
    [ "$pub" = "True" ] || abort "$id is not public in $region (is public AMI sharing blocked for the account in that region?)"
  done
done
[ "$apply" = 1 ] || echo "dry run: nothing was changed (pass --apply to make these public)"
