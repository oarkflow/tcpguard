#!/usr/bin/env bash
set -euo pipefail

file="${1:-/tmp/bench.txt}"

extract_ns() {
  local name="$1"
  local line
  line=$(grep "$name" "$file" | head -n1 || true)
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  echo "$line" | sed -E 's/.* ([0-9]+(\.[0-9]+)?) ns\/op.*/\1/'
}

lean_ns=$(extract_ns 'BenchmarkGuardEvaluateCleanAllowLean')
default_ns=$(extract_ns 'BenchmarkGuardEvaluateDefaultDetectors')

if [[ -z "$lean_ns" || -z "$default_ns" ]]; then
  echo "missing required benchmark lines"
  exit 1
fi

lean_max=15000
default_max=30000

if (( ${lean_ns%.*} > lean_max )); then
  echo "lean benchmark too slow: ${lean_ns}ns > ${lean_max}ns"
  exit 1
fi
if (( ${default_ns%.*} > default_max )); then
  echo "default benchmark too slow: ${default_ns}ns > ${default_max}ns"
  exit 1
fi

echo "benchmark SLO check passed"
