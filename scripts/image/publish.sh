#!/usr/bin/env bash
# Makes a release's images public, AFTER the release manifest is built and signed (ADR 0052): the manifest, not the image's
# visibility, is what a client trusts, so an image must never be public while its release is unsigned.
#
#   scripts/image/publish.sh --manifest ozbox-image-manifest.json --version 0.3.0 --regions us-east-1,eu-west-1 [--apply]
#
# Reads the image ids from the manifest (`images[].amis`, region to id), makes sure each one is tagged as ours in its region
# (a copy is not always tagged), and then grants the `all` launch permission. DOES NOTHING unless --apply is given.
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
for region in ${regions//,/ }; do
  printf '%s' "$region" | grep -Eq '^[a-z]{2}-[a-z]+-[0-9]$' || { echo "not a region name: $region" >&2; exit 2; }
  ids="$(jq -r --arg r "$region" '.images[].amis[$r] // empty' "$manifest")"
  [ -n "$ids" ] || { echo "the manifest lists no image for $region" >&2; exit 1; }
  for id in $ids; do
    printf '%s' "$id" | grep -Eq '^ami-[0-9a-f]{8,17}$' || { echo "not an image id: $id" >&2; exit 1; }
    echo "$region $id"
    [ "$apply" = 1 ] || continue
    snaps="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" \
      --query 'Images[0].BlockDeviceMappings[].Ebs.SnapshotId' --output text)"
    "$aws_cmd" ec2 create-tags --region "$region" --resources "$id" $snaps --tags \
      "Key=ozbox-managed,Value=true" "Key=ozbox-image,Value=$version" "Key=ozbox-image-version,Value=$version"
    "$aws_cmd" ec2 modify-image-attribute --region "$region" --image-id "$id" --launch-permission 'Add=[{Group=all}]'
    # read it back: an account that blocks public sharing refuses quietly in some regions, and a release must not be
    # reported as published when its image is not
    pub="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" --query 'Images[0].Public' --output text)"
    [ "$pub" = "True" ] || { echo "$id is not public in $region (is public AMI sharing blocked for the account in that region?)" >&2; exit 1; }
  done
done
[ "$apply" = 1 ] || echo "dry run: nothing was changed (pass --apply to make these public)"
