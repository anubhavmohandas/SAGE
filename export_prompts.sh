#!/bin/bash
# export_prompts.sh — Bundle all pending CVE prompts into one file for AI review
# Usage: bash export_prompts.sh [repo_name]
# Example: bash export_prompts.sh CyberTrace

set -e

REPO="${1:-}"

# Auto-detect repo name if not provided
if [ -z "$REPO" ]; then
    # Try to find the most recently modified prompts dir
    REPO=$(ls -t data/ 2>/dev/null | head -1)
    if [ -z "$REPO" ]; then
        echo "Usage: bash export_prompts.sh <repo_name>"
        echo "Example: bash export_prompts.sh CyberTrace"
        exit 1
    fi
    echo "[sage] Auto-detected repo: $REPO"
fi

PROMPTS_DIR="data/$REPO/prompts"
RESPONSES_DIR="data/$REPO/responses"
OUT_FILE="data/$REPO/all_prompts.txt"

if [ ! -d "$PROMPTS_DIR" ]; then
    echo "[sage] No prompts directory found at $PROMPTS_DIR"
    echo "       Run: python3 main.py --repo /path/to/$REPO --days 7"
    exit 1
fi

mkdir -p "$RESPONSES_DIR"

# Find pending prompts (no matching response file)
PENDING=()
for prompt_file in "$PROMPTS_DIR"/CVE-*.txt; do
    [ -f "$prompt_file" ] || continue
    cve_id=$(basename "$prompt_file" .txt)
    response_file="$RESPONSES_DIR/$cve_id.json"
    if [ ! -f "$response_file" ]; then
        PENDING+=("$prompt_file")
    fi
done

if [ ${#PENDING[@]} -eq 0 ]; then
    echo "[sage] No pending prompts — all responses already saved."
    exit 0
fi

echo "[sage] Found ${#PENDING[@]} pending CVE(s) — bundling into $OUT_FILE"

# Write the bundle file
cat > "$OUT_FILE" << 'HEADER'
You are a security vulnerability analyst. Below are multiple CVE analysis tasks.
For EACH CVE, respond with EXACTLY this format — no extra text, no markdown:

=== CVE-XXXX-XXXXX ===
{"vulnerable": true or false, "confidence": 0.0-1.0, "reason": "one sentence", "affected_functions": ["fn1"], "attack_vector": "how attacker reaches it, or empty string", "recommendation": "fix, or empty string"}

Analyze each CVE independently. Output ALL responses before moving to the next.
---

HEADER

for prompt_file in "${PENDING[@]}"; do
    cve_id=$(basename "$prompt_file" .txt)
    echo "======================================" >> "$OUT_FILE"
    echo "TASK: $cve_id" >> "$OUT_FILE"
    echo "======================================" >> "$OUT_FILE"
    cat "$prompt_file" >> "$OUT_FILE"
    echo "" >> "$OUT_FILE"
    echo "" >> "$OUT_FILE"
done

TOTAL_LINES=$(wc -l < "$OUT_FILE")
TOTAL_SIZE=$(wc -c < "$OUT_FILE" | tr -d ' ')

echo "[sage] Bundle written → $OUT_FILE"
echo "[sage] Size: ${TOTAL_SIZE} bytes, ${TOTAL_LINES} lines, ${#PENDING[@]} CVEs"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Next steps:"
echo "  1. Upload $OUT_FILE to Claude / ChatGPT / Gemini"
echo "  2. Save the AI's full response as:"
echo "     data/$REPO/all_responses.txt"
echo "  3. Run: bash import_responses.sh $REPO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Try to open the file
if command -v open &>/dev/null; then
    open "$OUT_FILE"
elif command -v xdg-open &>/dev/null; then
    xdg-open "$OUT_FILE"
fi
