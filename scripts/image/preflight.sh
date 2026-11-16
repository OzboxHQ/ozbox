#!/usr/bin/env bash
# Before a public release builds anything: public sharing of images must be allowed in every region it publishes to. A new AWS
# account blocks it by default, and finding that out after a build (and its copies) is a wasted release. Read-only.
#
#   scripts/image/preflight.sh --regions us-east-1,eu-west-1,ap-southeast-1 [--owner 123456789012 --need 2]
#
# With --owner and --need it also checks, before anything is built, that AWS's per-region quota on public images can hold the
# release at all: the public images this process can never free (anything that is not an Oz Box image of ours) plus the --need
# images of the release must fit. Older Oz Box versions do not count against it, because make-room.sh makes them private.
set -euo pipefail
regions=""
owner=""
need=""
while [ $# -gt 0 ]; do
  case "$1" in
    --regions) regions="${2:?}"; shift 2 ;;
    --owner) owner="${2:?}"; shift 2 ;;
    --need) need="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$regions" ] || { echo "--regions is required" >&2; exit 2; }
if [ -n "$owner$need" ]; then
  printf '%s' "$owner" | grep -Eq '^[0-9]{12}$' || { echo "--owner must be a 12-digit account id (and goes with --need)" >&2; exit 2; }
  printf '%s' "$need" | grep -Eq '^[1-9][0-9]*$' || { echo "--need must be a positive number (and goes with --owner)" >&2; exit 2; }
fi
aws_cmd="${OZBOX_AWS:-aws}"
bad=0
for region in ${regions//,/ }; do
  printf '%s' "$region" | grep -Eq '^[a-z]{2}-[a-z]+-[0-9]$' || { echo "not a region name: $region" >&2; exit 2; }
  state="$("$aws_cmd" ec2 get-image-block-public-access-state --region "$region" --query ImageBlockPublicAccessState --output text)"
  if [ "$state" = "unblocked" ]; then
    echo "$region: public image sharing is allowed"
  else
    echo "$region: public image sharing is $state; run 'aws ec2 disable-image-block-public-access --region $region' as an administrator of the publishing account before a public release" >&2
    bad=1
    continue
  fi
  [ -n "$need" ] || continue
  q="$("$aws_cmd" service-quotas list-service-quotas --region "$region" --service-code ec2 \
        --query "Quotas[?contains(QuotaName, 'Public AMIs')].Value | [0]" --output text 2>/dev/null)" || q=""
  q="${q%%.*}"
  printf '%s' "$q" | grep -Eq '^[1-9][0-9]*$' || { echo "$region: could not read the public-image quota from Service Quotas; assuming AWS's default of 5" >&2; q=5; }
  fixed="$("$aws_cmd" ec2 describe-images --region "$region" --owners self --filters "Name=is-public,Values=true" --output json \
    | jq --arg owner "$owner" '[.Images[]? | select(.OwnerId == $owner and ((.Tags // []) | any(.Key == "ozbox-managed" and .Value == "true")) and ((.Name // "") | startswith("ozbox-")) | not)] | length')"
  if [ $((fixed + need)) -gt "$q" ]; then
    echo "$region: AWS allows $q public images and $fixed that this process never makes private are public, so the release's $need cannot fit. Make some of those private, or ask AWS Support to raise the 'Public AMIs' quota in $region (Service Quotas), before a release." >&2
    bad=1
  else
    echo "$region: the public-image quota ($q) can hold this release's $need images (older Oz Box versions are made private first)"
  fi
done
exit "$bad"
