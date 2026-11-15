#!/usr/bin/env bash
# Only public-facing documentation lives in this repository: the README files, the roadmap, security and contributing
# guides, the architecture overview and the other public guides in docs/, the architecture decision records, the user-facing use-case guides, the documentation site pages (docs-site/, generated from docs/) and the example skills (skills/<name>/SKILL.md). Specifications, contracts and build
# cookbooks are kept outside it. Anything else that looks like a document fails the build.
set -euo pipefail
cd "$(dirname "$0")/.."
allowed='^(README\.md|ROADMAP\.md|SECURITY\.md|CONTRIBUTING\.md|TRADEMARKS\.md|DOCS-LICENSE\.md|CODE_OF_CONDUCT\.md|\.github/PULL_REQUEST_TEMPLATE\.md|(packages|skills|examples|infra)/README\.md|docs/[0-9a-zA-Z-]+\.md|docs/adr/[0-9a-zA-Z-]+\.md|docs/use-cases/[0-9a-zA-Z-]+\.md|skills/[0-9a-zA-Z-]+/SKILL\.md|docs-site/([0-9a-zA-Z_-]+/)*[0-9a-zA-Z_-]+\.mdx?)$'
bad="$( { git ls-files '*.md' '*.mdx' '*.adoc' '*.rst'; git ls-files 'docs/*'; } | sort -u | grep -v -E "$allowed" || true)"
if [ -n "$bad" ]; then
  echo "no-build-docs: these files are not allowed in this repository:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "no-build-docs: clean"
