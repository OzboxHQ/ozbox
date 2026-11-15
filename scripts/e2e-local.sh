#!/usr/bin/env bash
# Runs the dashboard's browser tests against a local `ozbox serve` (the fake provider, a temporary state directory,
# an in-memory secret store, no cloud and no network service). The test runner's own setup starts the server on
# localhost, waits for it to answer, and stops it afterwards; this script builds what is needed and runs the suite,
# so the whole thing can be run on any machine with Node and Rust, such as a bigger Oz box, not only in CI.
#
#   scripts/e2e-local.sh                  build, then run every browser test
#   scripts/e2e-local.sh --public         only the public-address test (a fake https address through a local proxy)
#   scripts/e2e-local.sh --no-build       use the program and dashboard already built
#   scripts/e2e-local.sh -- --grep tunnel arguments after -- go to Playwright
#
# OZBOX_BIN names the `ozbox` program to test (default: target/debug/ozbox). OZBOX_E2E_WITH_DEPS=1 also installs the
# operating system packages the browser needs (it may ask for sudo).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build=1
specs=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --public) specs=(e2e/14-public-address.spec.ts) ;;
    --no-build) build=0 ;;
    --) shift; break ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "e2e-local: unknown option $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

cd "$root/packages/dashboard"
if [ ! -d node_modules ]; then
  npm ci
fi
if [ "$build" = 1 ]; then
  npm run build
  (cd "$root" && cargo build -p ozbox-cli)
fi
# The sign-in check of a real cloud must fail at once on a machine with no cloud account, never wait on the instance
# metadata address of a cloud this machine is not on (which can take longer than the page waits for its answer).
export AWS_EC2_METADATA_DISABLED=true
export OZBOX_BIN="${OZBOX_BIN:-$root/target/debug/ozbox}"
if [ ! -x "$OZBOX_BIN" ]; then
  echo "e2e-local: $OZBOX_BIN is not built; run without --no-build" >&2
  exit 1
fi

if [ "${OZBOX_E2E_WITH_DEPS:-0}" = 1 ]; then
  # The system libraries come from the distribution's package servers. If those cannot be reached (a CI runner whose
  # resolver is down has failed this way), install the browser alone and say so: a runner image that already carries
  # a browser has the libraries, and a machine that does not will fail at the first test with the missing library named.
  if ! npx playwright install --with-deps chromium; then
    echo "e2e-local: the system libraries could not be installed; installing the browser alone" >&2
    npx playwright install chromium
  fi
else
  npx playwright install chromium
fi

# Run Playwright as a child so an interrupt reaches it: its teardown stops the server it started.
npm run e2e -- ${specs[@]+"${specs[@]}"} "$@" &
child=$!
trap 'kill -TERM "$child" 2>/dev/null || true' INT TERM
status=0
wait "$child" || status=$?
exit "$status"
