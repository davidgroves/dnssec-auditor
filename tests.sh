#!/usr/bin/env bash
# Run unit and optional e2e / integration tests.
#
#   ./tests.sh                 unit tests (Go + frontend)
#   ./tests.sh --all           unit + e2e scenario suites
#   ./tests.sh --e2e           e2e suites 2-3 + interop (if tagged)
#   ./tests.sh --e2e-large     large-zone / incremental performance
#   ./tests.sh --integration   Go tests with -tags integration
set -euo pipefail
cd "$(dirname "$BASH_SOURCE[0]")"

RUN_UNIT=true
RUN_E2E=false
RUN_E2E_LARGE=false
RUN_INTEGRATION=false

for arg in "$@"; do
  case "$arg" in
    --all) RUN_E2E=true ;;
    --e2e) RUN_E2E=true; RUN_UNIT=false ;;
    --e2e-large) RUN_E2E_LARGE=true; RUN_UNIT=false ;;
    --integration) RUN_INTEGRATION=true; RUN_UNIT=false ;;
  esac
done

if $RUN_UNIT; then
  echo "=== Go unit tests ==="
  go test ./...

  if [ -f package.json ]; then
    echo ""
    echo "=== Frontend unit tests ==="
    if [ -d node_modules ]; then
      npm test
    else
      echo "skipping (run npm install first)"
    fi
  fi
fi

if $RUN_INTEGRATION; then
  echo "=== Go integration tests ==="
  go test -tags integration ./...
fi

if $RUN_E2E; then
  echo "=== E2E scenario suites ==="
  go test -tags e2e ./tests/e2e -run 'TestDefects|TestDDNS|TestCatalog|TestInterop|TestOracle' -count=1 -timeout 10m
fi

if $RUN_E2E_LARGE; then
  echo "=== E2E large / incremental ==="
  go test -tags e2e ./tests/e2e -run 'TestLarge|TestIncremental' -count=1 -timeout 30m
fi

echo ""
echo "All requested tests passed."
