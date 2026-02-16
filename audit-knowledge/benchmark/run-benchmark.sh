#!/usr/bin/env bash
# =============================================================================
# Audit Knowledge Benchmark Harness
# =============================================================================
# Usage:
#   ./run-benchmark.sh [case_id]     # run one case or all
#   ./run-benchmark.sh --score-only  # re-score existing outputs
#
# Requires: jq, node/bun (for scoring script)
# Output:   benchmark/results/<timestamp>/
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KB_ROOT="$(dirname "$SCRIPT_DIR")"
GROUND_TRUTH="$SCRIPT_DIR/ground-truth.json"
RESULTS_DIR="$SCRIPT_DIR/results/$(date +%Y%m%d-%H%M%S)"
SCORE_ONLY=false
TARGET_CASE=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --score-only) SCORE_ONLY=true; shift ;;
    *) TARGET_CASE="$1"; shift ;;
  esac
done

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Step 1: Extract case list from ground truth
# ---------------------------------------------------------------------------
CASES=$(jq -r '.cases[].id' "$GROUND_TRUTH")
if [[ -n "$TARGET_CASE" ]]; then
  CASES="$TARGET_CASE"
fi

echo "=== Audit Benchmark Harness ==="
echo "Ground truth: $GROUND_TRUTH"
echo "Results dir:  $RESULTS_DIR"
echo "Cases:        $(echo $CASES | wc -w | tr -d ' ')"
echo ""

# ---------------------------------------------------------------------------
# Step 2: For each case, run the audit agent (or skip if --score-only)
# ---------------------------------------------------------------------------
for CASE_ID in $CASES; do
  echo "--- [$CASE_ID] ---"
  
  SOURCE_DIR=$(jq -r ".cases[] | select(.id == \"$CASE_ID\") | .source_code_dir" "$GROUND_TRUTH")
  PROTO_TYPE=$(jq -r ".cases[] | select(.id == \"$CASE_ID\") | .protocol_type" "$GROUND_TRUTH")
  EXPECTED_COUNT=$(jq -r ".cases[] | select(.id == \"$CASE_ID\") | .findings | length" "$GROUND_TRUTH")
  
  CASE_DIR="$RESULTS_DIR/$CASE_ID"
  mkdir -p "$CASE_DIR"
  
  # Save expected findings for scoring
  jq ".cases[] | select(.id == \"$CASE_ID\") | .findings" "$GROUND_TRUTH" > "$CASE_DIR/expected.json"
  
  FULL_SOURCE="$KB_ROOT/$SOURCE_DIR"
  
  if [[ "$SCORE_ONLY" == "false" ]]; then
    if [[ ! -d "$FULL_SOURCE" ]]; then
      echo "  ⚠ Source code not found: $FULL_SOURCE — skipping audit run"
      echo '{"error": "source_not_found", "path": "'"$FULL_SOURCE"'"}' > "$CASE_DIR/audit-output.json"
      continue
    fi
    
    echo "  Protocol: $PROTO_TYPE | Expected findings: $EXPECTED_COUNT"
    echo "  Source:   $FULL_SOURCE"
    echo "  → Running audit agent... (this is a placeholder — wire your agent here)"
    
    # -----------------------------------------------------------------------
    # Audit agent: simple heuristic scanner (baseline)
    # Replace with LLM-based agent for production benchmarks.
    # -----------------------------------------------------------------------
    node "$SCRIPT_DIR/simple-scanner.mjs" "$FULL_SOURCE" "$PROTO_TYPE" \
      > "$CASE_DIR/audit-output.json" 2>/dev/null || \
      echo '{"findings": [], "error": "scanner_failed"}' > "$CASE_DIR/audit-output.json"
    # -----------------------------------------------------------------------
    
    echo "  ✓ Output saved to $CASE_DIR/audit-output.json"
  fi
done

# ---------------------------------------------------------------------------
# Step 3: Score all cases
# ---------------------------------------------------------------------------
echo ""
echo "=== Scoring ==="

node "$SCRIPT_DIR/score.mjs" "$GROUND_TRUTH" "$RESULTS_DIR" | tee "$RESULTS_DIR/summary.txt"

echo ""
echo "Full results: $RESULTS_DIR/summary.txt"
echo "Per-case:     $RESULTS_DIR/<case-id>/scorecard.json"
