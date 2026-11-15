#!/usr/bin/env bash
# Fails if the tree mentions anything that ties this project to a specific private deployment:
# company or product names, account ids, private hostnames, internal paths. The repository will be public;
# examples must use neutral defaults (example.com, /ozbox/<box>/, a placeholder account id).
#
# The patterns are assembled from parts so this file never matches itself.
set -euo pipefail
cd "$(dirname "$0")/.."

parts=(
  "cli""nik"        # a product name
  "bett""ar"        # a company name
  "4126""5439""6839" # an account id
  "/clini""kehr/"
  "jemag""aji"
  "oz""ni"
)
pattern="$(IFS='|'; echo "${parts[*]}")"

if git ls-files -z | xargs -0 grep -I -n -i -E "$pattern" -- 2>/dev/null; then
  echo
  echo "public-safety: the lines above reference a private deployment. Use neutral defaults." >&2
  exit 1
fi

# Controls, never certifications: no public text may claim that the project is compliant with, or certified or audited
# against, a framework. Describe the control that exists instead (see docs/shared-responsibility.md). Assembled from parts so
# this file never matches itself.
frameworks="HIP""AA|SOC ?2|ISO[ /A-Z]*27001|ISO ?27701|HIT""RUST|PCI[ -]?DSS|GD""PR|Fed""RAMP"
claims="compliant|certified|compliance|certification|attested|attestation|audited"
claim_pattern="(${frameworks})[ -]+(${claims})|(${claims})[ ]+(with|to|for|against)[ ]+(${frameworks})"
if git ls-files -z | xargs -0 grep -I -n -i -E "$claim_pattern" -- 2>/dev/null; then
  echo
  echo "public-safety: the lines above claim a compliance or certification. Oz Box describes controls, never certifications." >&2
  exit 1
fi
echo "public-safety: clean"
