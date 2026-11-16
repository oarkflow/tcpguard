#!/usr/bin/env bash
set -euo pipefail

file="${1:-/tmp/bench.txt}"

extract_ns() {
  local name="$1"
  awk -v name="$name" '
    index($1, name) {
      for (i = 1; i <= NF; i++) if ($i == "ns/op") {
        value = $(i - 1) + 0
        if (value > max) max = value
        found = 1
      }
    }
    END { if (found) printf "%.0f\n", max }
  ' "$file"
}

extract_bytes() {
  local name="$1"
  awk -v name="$name" '
    index($1, name) {
      for (i = 1; i <= NF; i++) if ($i == "B/op") {
        value = $(i - 1) + 0
        if (value > max) max = value
        found = 1
      }
    }
    END { if (found) printf "%.0f\n", max }
  ' "$file"
}

lean_ns=$(extract_ns 'BenchmarkGuardEvaluateCleanAllowLean')
default_ns=$(extract_ns 'BenchmarkGuardEvaluateDefaultDetectors')
large_pack_ns=$(extract_ns 'BenchmarkGuardEvaluateDynamicRulesByPackSize/1000')
large_pack_bytes=$(extract_bytes 'BenchmarkGuardEvaluateDynamicRulesByPackSize/1000')

if [[ -z "$lean_ns" || -z "$default_ns" || -z "$large_pack_ns" || -z "$large_pack_bytes" ]]; then
  echo "missing required benchmark lines"
  exit 1
fi

lean_max=15000
default_max=200000
large_pack_max=20000000
large_pack_bytes_max=8000000

if (( ${lean_ns%.*} > lean_max )); then
  echo "lean benchmark too slow: ${lean_ns}ns > ${lean_max}ns"
  exit 1
fi
if (( ${default_ns%.*} > default_max )); then
  echo "default benchmark too slow: ${default_ns}ns > ${default_max}ns"
  exit 1
fi
if (( large_pack_ns > large_pack_max )); then
  echo "1000-rule dynamic benchmark too slow: ${large_pack_ns}ns > ${large_pack_max}ns"
  exit 1
fi
if (( large_pack_bytes > large_pack_bytes_max )); then
  echo "1000-rule dynamic benchmark allocates too much: ${large_pack_bytes}B > ${large_pack_bytes_max}B"
  exit 1
fi

echo "benchmark SLO check passed"
