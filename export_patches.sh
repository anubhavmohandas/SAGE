#!/bin/bash
# export_patches.sh — Bundle all pending patch prompts into one file for AI review
# Usage: bash export_patches.sh [repo_name]

set -e
REPO="${1:-}"
if [ -z "$REPO" ]; then
    REPO=$(ls -t data/ 2>/dev/null | head -1)
    [ -z "$REPO" ] && echo "Usage: bash export_patches.sh <repo_name>" && exit 1
    echo "[sage] Auto-detected repo: $REPO"
fi

PATCHES_DIR="data/$REPO/patches"
OUT_FILE="data/$REPO/all_patch_prompts.txt"

if [ ! -d "$PATCHES_DIR" ]; then
    echo "[sage] No patches directory at $PATCHES_DIR — run the pipeline first."
    exit 1
fi

PENDING=()
for f in "$PATCHES_DIR"/patch_prompt_CVE-*.txt; do
    [ -f "$f" ] || continue
    cve_id=$(basename "$f" .txt | sed 's/patch_prompt_//')
    resp="$PATCHES_DIR/patch_response_$cve_id.json"
    [ ! -f "$resp" ] && PENDING+=("$f")
done

if [ ${#PENDING[@]} -eq 0 ]; then
    echo "[sage] No pending patch prompts."
    exit 0
fi

echo "[sage] Found ${#PENDING[@]} pending patch(es) — bundling into $OUT_FILE"

cat > "$OUT_FILE" << 'HEADER'
You are a security engineer. Below are multiple code patching tasks.
For EACH task, respond with EXACTLY this format — no extra text, no markdown:

=== CVE-XXXX-XXXXX ===
{"patched_files": [{"file": "relative/path.py", "original_function": "fn_name", "patched_code": "complete patched function", "explanation": "what changed and why"}], "summary": "one sentence"}

---

HEADER

for f in "${PENDING[@]}"; do
    cve_id=$(basename "$f" .txt | sed 's/patch_prompt_//')
    echo "======================================" >> "$OUT_FILE"
    echo "TASK: $cve_id" >> "$OUT_FILE"
    echo "======================================" >> "$OUT_FILE"
    cat "$f" >> "$OUT_FILE"
    echo -e "\n" >> "$OUT_FILE"
done

echo "[sage] Bundle → $OUT_FILE (${#PENDING[@]} patches)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  1. Upload $OUT_FILE to Claude / ChatGPT"
echo "  2. Save AI response anywhere"
echo "  3. Run: bash import_patches.sh $REPO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
command -v open &>/dev/null && open "$OUT_FILE" || true
