#!/usr/bin/env bash
# Structural guard for the no-inbound-network rule (ADR 0005): fails if any module declares an
# ingress rule resource or block. `tofu test` cannot see resource types that are absent, so this
# complements the per-module tests. Comments are ignored.
set -euo pipefail
cd "$(dirname "$0")"

status=0
while IFS= read -r file; do
  # A bare `rule {` block opens a firewall rule on Hetzner, but it is also how S3 bucket configuration (object lock,
  # encryption, lifecycle) is written. The security baseline module has no firewall, so only it may use that spelling.
  pattern='aws_vpc_security_group_ingress_rule|aws_security_group_rule|^[[:space:]]*ingress[[:space:]]*(=|\{)|direction[[:space:]]*=[[:space:]]*"in"|^[[:space:]]*rule[[:space:]]*\{'
  case "$file" in
    modules/aws-security-baseline/*)
      pattern='aws_vpc_security_group_ingress_rule|aws_security_group_rule|aws_security_group|aws_vpc_security_group|hcloud_firewall|^[[:space:]]*ingress[[:space:]]*(=|\{)|direction[[:space:]]*=[[:space:]]*"in"' ;;
  esac
  # Drop comment lines, then look for anything that opens an inbound path.
  if grep -v -E '^[[:space:]]*(#|//)' "$file" | grep -n -E "$pattern"; then
    echo "check-no-ingress: $file declares an inbound rule" >&2
    status=1
  fi
done < <(find modules -name '*.tf')

if [ "$status" -eq 0 ]; then
  echo "check-no-ingress: clean"
fi
exit "$status"
