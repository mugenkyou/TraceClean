#!/usr/bin/env bash
set -uo pipefail

# Validate the running compose stack. Minimal output; exit code only:
#   0 = every service passes, 1 = any service fails.
#
#   tc-core       -> HTTP /health must answer
#   harness/heavy -> one-shot CLIs must exit 0 on --help

BASE_URL="${TRACECLEAN_SERVICE_URL:-http://127.0.0.1:8765}"
COMPOSE=(docker compose --profile harness --profile heavy)
FAIL=0

if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
  echo "tc-core: OK"
else
  echo "tc-core: FAIL (no /health at $BASE_URL)"
  FAIL=1
fi

for svc in tc-markllm tc-markdiffusion tc-ctrlregen tc-synthid; do
  if "${COMPOSE[@]}" run --rm "$svc" --help >/dev/null 2>&1; then
    echo "$svc: OK"
  else
    echo "$svc: FAIL"
    FAIL=1
  fi
done

exit "$FAIL"
