#!/usr/bin/env bash
# Before a public release builds anything: public sharing of images must be allowed in every region it publishes to. A new AWS
# account blocks it by default, and finding that out after a build (and its copies) is a wasted release. Read-only.
#
#   scripts/image/preflight.sh --regions us-east-1,eu-west-1,ap-southeast-1
set -euo pipefail
regions=""
while [ $# -gt 0 ]; do
  case "$1" in
    --regions) regions="${2:?}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$regions" ] || { echo "--regions is required" >&2; exit 2; }
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
  fi
done
exit "$bad"
