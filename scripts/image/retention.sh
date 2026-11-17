#!/usr/bin/env bash
# Takes old Oz Box images out of use in every region a release was published to (ADR 0052): keeps the newest KEEP versions,
# and for the older ones, by default, makes each one that is still public PRIVATE (its launch permission is removed; the image
# and its snapshots are kept, and it can be made public again by hand). Only with --delete are they RETIRED: the AMI is
# deregistered and its snapshots deleted, which cannot be undone, and breaks a box (in any account) that still names that
# image when it is rebuilt. Run by the image workflow after a release has been built, signed and made public; never by hand
# against an account you do not mean to clean.
#
#   scripts/image/retention.sh --released 0.3.0 --regions us-east-1,eu-west-1 --owner 123456789012 [--keep 3] [--delete] [--apply]
#
# It is a plan unless --apply is given: without it, it prints what it would make private (or, with --delete, retire) and
# exits 0, changing nothing. It only ever touches images the selector (retention.jq) calls ours, and never the released version
# or anything newer. A failure in one region stops that region and is reported at the end (exit 1), after the other regions
# were still processed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
keep=3
apply=0
delete=0
released=""
regions=""
owner=""
while [ $# -gt 0 ]; do
  case "$1" in
    --released) released="${2:?--released needs a version}"; shift 2 ;;
    --regions) regions="${2:?--regions needs a comma-separated list}"; shift 2 ;;
    --owner) owner="${2:?--owner needs an account id}"; shift 2 ;;
    --keep) keep="${2:?--keep needs a number}"; shift 2 ;;
    --apply) apply=1; shift ;;
    --delete) delete=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
printf '%s' "$released" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$' || { echo "--released must be a version like 0.3.0" >&2; exit 2; }
printf '%s' "$owner" | grep -Eq '^[0-9]{12}$' || { echo "--owner must be a 12-digit account id" >&2; exit 2; }
printf '%s' "$keep" | grep -Eq '^[1-9][0-9]*$' || { echo "--keep must be a positive number" >&2; exit 2; }
[ -n "$regions" ] || { echo "--regions is required" >&2; exit 2; }
for r in ${regions//,/ }; do
  printf '%s' "$r" | grep -Eq '^[a-z]{2}-[a-z]+-[0-9]$' || { echo "not a region name: $r" >&2; exit 2; }
done
now="${OZBOX_NOW:-$(date +%s)}"
printf '%s' "$now" | grep -Eq '^[0-9]+$' || { echo "OZBOX_NOW must be epoch seconds" >&2; exit 2; }
# OZBOX_AWS lets a test stand in for the aws program; it is a program path, never a shell string.
aws_cmd="${OZBOX_AWS:-aws}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failed=0

for region in ${regions//,/ }; do
  echo "== $region"
  if ! "$aws_cmd" ec2 describe-images --region "$region" --owners self \
       --filters "Name=tag:ozbox-managed,Values=true" --output json >"$tmp/images.json"; then
    echo "could not list images in $region" >&2; failed=1; continue
  fi
  if ! "$aws_cmd" ec2 describe-snapshots --region "$region" --owner-ids self \
       --filters "Name=tag:ozbox-managed,Values=true" --output json >"$tmp/snaps.json"; then
    echo "could not list snapshots in $region" >&2; failed=1; continue
  fi
  if ! jq -n --slurpfile images "$tmp/images.json" --slurpfile snaps "$tmp/snaps.json" \
       --arg owner "$owner" --arg released "$released" --argjson keep "$keep" --argjson now "$now" \
       -f "$here/retention.jq" >"$tmp/decision.json" 2>"$tmp/err.txt"; then
    echo "nothing is changed in $region: $(cat "$tmp/err.txt")" >&2; failed=1; continue
  fi
  echo "keeping versions: $(jq -r '.keep_versions | join(", ")' "$tmp/decision.json")"
  n="$(jq '.delete | length' "$tmp/decision.json")"
  if [ "$n" = 0 ]; then echo "nothing outside the window"; continue; fi
  if [ "$delete" = 1 ]; then
    jq -r '.delete[] | "retire (delete) \(.image_id) \(.name) (\(.version)); snapshots: \(.snapshots | join(" "))"' "$tmp/decision.json"
    if [ "$apply" != 1 ]; then echo "plan only: nothing was changed (pass --apply to retire these; this cannot be undone)"; continue; fi
    while IFS= read -r row; do
      id="$(jq -r .image_id <<<"$row")"
      # deregister first: a snapshot cannot be deleted while an image uses it
      if ! "$aws_cmd" ec2 deregister-image --region "$region" --image-id "$id" >/dev/null; then
        echo "could not deregister $id in $region" >&2; failed=1; continue
      fi
      echo "retired $id"
      for snap in $(jq -r '.snapshots[]' <<<"$row"); do
        "$aws_cmd" ec2 delete-snapshot --region "$region" --snapshot-id "$snap" >/dev/null \
          || { echo "could not delete snapshot $snap in $region" >&2; failed=1; }
      done
    done < <(jq -c '.delete[]' "$tmp/decision.json")
    continue
  fi
  # the default: make private, keep everything
  jq -r '.delete[] | "make private \(.image_id) \(.name) (\(.version)); the image and its snapshots are kept"' "$tmp/decision.json"
  if [ "$apply" != 1 ]; then echo "plan only: nothing was changed (pass --apply to make these private; --delete instead retires them, which cannot be undone)"; continue; fi
  while IFS= read -r row; do
    id="$(jq -r .image_id <<<"$row")"
    if ! public="$("$aws_cmd" ec2 describe-image-attribute --region "$region" --image-id "$id" --attribute launchPermission --output json)"; then
      echo "could not read who may launch $id in $region" >&2; failed=1; continue
    fi
    if ! jq -e '[.LaunchPermissions[]? | select(.Group == "all")] | length > 0' <<<"$public" >/dev/null; then
      echo "$id is already private: kept"; continue
    fi
    if "$aws_cmd" ec2 modify-image-attribute --region "$region" --image-id "$id" --launch-permission 'Remove=[{Group=all}]' >/dev/null; then
      echo "made $id private: kept"
    else
      echo "could not make $id private in $region" >&2; failed=1
    fi
  done < <(jq -c '.delete[]' "$tmp/decision.json")
done
exit "$failed"
