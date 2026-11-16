#!/usr/bin/env bash
# Makes room under AWS's per-region limit on PUBLIC images BEFORE a release is made public (ADR 0052). An account may share only a
# few images publicly per region (5 by default; the real limit is read from Service Quotas), and a release has one image per
# architecture, so older versions must stop being public before a new one can be. This makes the OLDEST public Oz Box versions
# PRIVATE (the launch permission is removed; the image and its snapshots are kept), whole versions at a time, only as many as
# the release needs. "Private" is not "retired": retiring (retention.sh) deletes an image and is a separate, explicit choice.
#
#   scripts/image/make-room.sh --manifest signed/ozbox-image-manifest.json --version 0.3.0 --regions us-east-1,eu-west-1 \
#       --owner 123456789012 [--quota N] [--apply]
#
# Never touches the version being published, a newer one, or an image that is not ours (owner, tags and name all checked; see
# public-quota.jq). Every region is planned first; if any region cannot be made to fit (the images that cannot be freed already
# fill the quota), it exits 1 having changed NOTHING. DOES NOTHING unless --apply is given (a dry run, which is also the check).
# A release that is already half public needs fewer slots: images that are public already are not counted twice.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
apply=0; manifest=""; version=""; regions=""; owner=""; quota_flag=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) manifest="${2:?}"; shift 2 ;;
    --version) version="${2:?}"; shift 2 ;;
    --regions) regions="${2:?}"; shift 2 ;;
    --owner) owner="${2:?}"; shift 2 ;;
    --quota) quota_flag="${2:?}"; shift 2 ;;
    --apply) apply=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$' || { echo "--version must be a version like 0.3.0" >&2; exit 2; }
printf '%s' "$owner" | grep -Eq '^[0-9]{12}$' || { echo "--owner must be a 12-digit account id" >&2; exit 2; }
[ -f "$manifest" ] || { echo "--manifest must be the signed manifest file" >&2; exit 2; }
[ -n "$regions" ] || { echo "--regions is required" >&2; exit 2; }
if [ -n "$quota_flag" ]; then printf '%s' "$quota_flag" | grep -Eq '^[1-9][0-9]*$' || { echo "--quota must be a positive number" >&2; exit 2; }; fi
jq -e --arg v "$version" '.version == $v' "$manifest" >/dev/null || { echo "the manifest is not for version $version" >&2; exit 1; }
for r in ${regions//,/ }; do
  printf '%s' "$r" | grep -Eq '^[a-z]{2}-[a-z]+-[0-9]$' || { echo "not a region name: $r" >&2; exit 2; }
done
aws_cmd="${OZBOX_AWS:-aws}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# the real limit, from Service Quotas; 5 (AWS's default) when it cannot be read, said out loud
region_quota() {
  if [ -n "$quota_flag" ]; then echo "$quota_flag"; return; fi
  local q
  q="$("$aws_cmd" service-quotas list-service-quotas --region "$1" --service-code ec2 \
        --query "Quotas[?contains(QuotaName, 'Public AMIs')].Value | [0]" --output text 2>/dev/null)" || q=""
  q="${q%%.*}"
  if printf '%s' "$q" | grep -Eq '^[1-9][0-9]*$'; then echo "$q"; else
    echo "$1: could not read the public-image quota from Service Quotas; assuming AWS's default of 5" >&2
    echo 5
  fi
}

# phase 1: plan every region, change nothing
bad=0
for region in ${regions//,/ }; do
  ids="$(jq -c --arg r "$region" '[.images[].amis[$r] // empty]' "$manifest")"
  [ "$ids" != "[]" ] || { echo "the manifest lists no image for $region" >&2; exit 1; }
  jq -e 'all(.[]; test("^ami-[0-9a-f]{8,17}$"))' <<<"$ids" >/dev/null || { echo "the manifest has an image id that is not one, in $region" >&2; exit 1; }
  q="$(region_quota "$region")"
  "$aws_cmd" ec2 describe-images --region "$region" --owners self \
    --filters "Name=is-public,Values=true" --output json >"$tmp/$region.images.json" \
    || { echo "could not list the public images in $region" >&2; exit 1; }
  jq -n --slurpfile images "$tmp/$region.images.json" --arg owner "$owner" --arg version "$version" \
    --argjson quota "$q" --argjson ids "$ids" -f "$here/public-quota.jq" >"$tmp/$region.plan.json" \
    || { echo "could not plan $region" >&2; exit 1; }
  echo "== $region: quota $q, $(jq .public "$tmp/$region.plan.json") public, release needs $(jq .need "$tmp/$region.plan.json") more"
  if [ "$(jq .fits "$tmp/$region.plan.json")" != true ]; then
    echo "$region: the release does not fit. AWS allows $q public images here, $(jq .public "$tmp/$region.plan.json") are public and $(jq .need "$tmp/$region.plan.json") more are needed; making every older Oz Box version private would still leave $(jq .untouchable "$tmp/$region.plan.json") public image(s) that this process never changes (other images, or this release and newer ones). Make some of those private yourself, or ask AWS Support to raise the 'Public AMIs' quota in $region (Service Quotas), then run this again. Nothing was changed." >&2
    bad=1
    continue
  fi
  jq -r '.make_private[] | "make private \(.image_id) \(.name) (\(.version))"' "$tmp/$region.plan.json"
  [ "$(jq '.make_private | length' "$tmp/$region.plan.json")" != 0 ] || echo "nothing to make private"
done
[ "$bad" = 0 ] || exit 1
if [ "$apply" != 1 ]; then echo "dry run: nothing was changed (pass --apply to make these private)"; exit 0; fi

# phase 2: every region fits, so now change them
for region in ${regions//,/ }; do
  for id in $(jq -r '.make_private[].image_id' "$tmp/$region.plan.json"); do
    "$aws_cmd" ec2 modify-image-attribute --region "$region" --image-id "$id" --launch-permission 'Remove=[{Group=all}]'
    pub="$("$aws_cmd" ec2 describe-images --region "$region" --image-ids "$id" --query 'Images[0].Public' --output text)"
    [ "$pub" != "True" ] || { echo "$id is still public in $region after its launch permission was removed" >&2; exit 1; }
    echo "$region $id is private now"
  done
done
