#!/usr/bin/env bash
# Runs Slither on a Solidity project and outputs JSON results for parse-findings.py
# Usage: bash slither-scan.sh <target> [--solc-version 0.8.20]
# Dependencies: pip install slither-analyzer

set -euo pipefail

TARGET="${1:-.}"
SOLC_VERSION="${2:-}"
OUTPUT_FILE="slither-output.json"

if ! command -v slither &>/dev/null; then
    echo "ERROR: slither not found. Install with: pip install slither-analyzer" >&2
    exit 1
fi

echo "=== Slither Smart Contract Security Scanner ===" >&2
echo "Target: $TARGET" >&2
echo "Output: $OUTPUT_FILE" >&2
echo "" >&2

SLITHER_ARGS=(
    "$TARGET"
    --json "$OUTPUT_FILE"
    --exclude-dependencies
    --exclude-informational
)

if [[ -n "$SOLC_VERSION" ]]; then
    SLITHER_ARGS+=(--solc-solcs-select "$SOLC_VERSION")
fi

# Run Slither (exit code 255 = findings found, which is expected)
if slither "${SLITHER_ARGS[@]}" 2>/dev/null; then
    echo "No findings detected." >&2
else
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 255 ]]; then
        echo "Findings detected — see $OUTPUT_FILE" >&2
    else
        echo "ERROR: Slither failed with exit code $EXIT_CODE" >&2
        exit $EXIT_CODE
    fi
fi

# Print human-readable summary to stderr
echo "" >&2
echo "=== Summary ===" >&2
slither "$TARGET" --print human-summary 2>/dev/null || true

echo "" >&2
echo "Run: python3 scripts/parse-findings.py $OUTPUT_FILE" >&2
