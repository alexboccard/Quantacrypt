#!/usr/bin/env bash
# The test gate. Three passes, because one command cannot serve all three.
#
#   1. non-GUI, parallel  — 612 tests, ~7s at -n auto
#   2. GUI, one process per file, serial
#   3. (--random) the same, with pytest-randomly shuffling order
#
# Why not one `pytest`:
#
# * Tk is not xdist-safe. The macOS window server is process-external shared
#   state; running Tk in several workers makes focus and key delivery
#   nondeterministic (measured: 29 GUI failures under -n auto, all passing
#   serially).
# * Tk state accumulates within a process. Destroying a root leaves the Python
#   object to the cyclic GC, and six GUI modules in one interpreter took
#   14:24 against 6:05 for the same files in separate processes — a 2.4x
#   penalty for nothing.
# * Randomisation costs a further ~1.8x by breaking module-scoped root reuse,
#   so it belongs on a periodic job rather than every local run. It is still
#   the only thing that catches order-dependence, so do not drop it entirely.
#
# Usage:
#   scripts/run_tests.sh              # the fast gate
#   scripts/run_tests.sh --random     # shuffled order, for CI / periodic runs
#   scripts/run_tests.sh --cov        # with the per-file coverage gate
set -uo pipefail

cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
[ -x "$PY" ] || PY="python3"

RANDOM_MODE=0
COV_MODE=0
for arg in "$@"; do
  case "$arg" in
    --random) RANDOM_MODE=1 ;;
    --cov)    COV_MODE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 64 ;;
  esac
done

BASE=(-q -o addopts="" -p no:cacheprovider --no-header
      --timeout=300 --timeout-method=thread)
if [ "$RANDOM_MODE" -eq 0 ]; then
  BASE+=(-p no:randomly)
fi
COV_DIR=".coverage-parts"
if [ "$COV_MODE" -eq 1 ]; then
  # One data file per invocation, combined at the end. --cov-append across
  # separate pytest runs silently lost the parallel pass's data: the gate
  # reported volume.py at 79% when that pass alone measured it at 99%.
  BASE+=(--cov=src/quantacrypt --cov-report= --cov-fail-under=0)
  rm -rf "$COV_DIR" .coverage coverage.json
  mkdir -p "$COV_DIR"
fi

# Run pytest with its own coverage data file when --cov is on.
run_pytest() {
  local tag="$1"; shift
  if [ "$COV_MODE" -eq 1 ]; then
    COVERAGE_FILE="$PWD/$COV_DIR/.coverage.$tag" "$PY" -u -m pytest "$@"
  else
    "$PY" -u -m pytest "$@"
  fi
}

fail=0
start=$(date +%s)

echo "── pass 1: non-GUI, parallel ─────────────────────────────────────────"
run_pytest nongui tests/ "${BASE[@]}" -m "not gui" -n auto || fail=1

echo
echo "── pass 2: GUI, one process per file ─────────────────────────────────"
# Discover rather than hardcode: a new GUI file must not silently skip the
# split and land in the parallel pass, where Tk breaks.
# No mapfile: macOS ships bash 3.2, where it does not exist.
GUI_FILES=()
while IFS= read -r line; do
  [ -n "$line" ] && GUI_FILES+=("$line")
done < <(
  "$PY" -m pytest tests/ -q -o addopts="" -p no:cacheprovider --no-header \
    -m gui --collect-only 2>/dev/null \
    | grep -oE '^tests/[A-Za-z0-9_]+\.py' | sort -u
)
if [ "${#GUI_FILES[@]}" -eq 0 ]; then
  echo "no GUI tests collected — is the 'gui' marker still applied in conftest?" >&2
  fail=1
fi
for f in "${GUI_FILES[@]}"; do
  printf '%-40s ' "$f"
  tag=$(basename "$f" .py)
  if raw=$(run_pytest "$tag" "$f" "${BASE[@]}" -m gui 2>&1); then
    echo "$raw" | tail -1
  else
    echo "$raw" | tail -1
    # Name them. A summary line saying "5 failed" is not actionable from a
    # CI log, which is exactly how 14 failures arrived unidentified.
    echo "$raw" | grep -E "^FAILED |^ERROR " | sed 's/^/    /'
    fail=1
  fi
done

echo
if [ "$COV_MODE" -eq 1 ]; then
  echo "── per-file coverage gate ──────────────────────────────────────────"
  "$PY" -m coverage combine "$COV_DIR" >/dev/null 2>&1 || true
  rm -rf "$COV_DIR"
  "$PY" scripts/check_coverage.py --min 95 || fail=1
fi

echo
echo "total: $(( $(date +%s) - start ))s"
exit "$fail"
