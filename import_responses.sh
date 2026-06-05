#!/bin/bash
# import_responses.sh — Split AI's combined response into individual CVE JSON files
# Usage: bash import_responses.sh [repo_name] [/path/to/response_file.txt]
# Example: bash import_responses.sh CyberTrace
#          bash import_responses.sh CyberTrace ~/Downloads/ai_response.txt

set -e

REPO="${1:-}"
RESPONSES_FILE="${2:-}"

if [ -z "$REPO" ]; then
    REPO=$(ls -t data/ 2>/dev/null | head -1)
    if [ -z "$REPO" ]; then
        echo "Usage: bash import_responses.sh <repo_name> [response_file]"
        exit 1
    fi
    echo "[sage] Auto-detected repo: $REPO"
fi

RESPONSES_DIR="data/$REPO/responses"
mkdir -p "$RESPONSES_DIR"

# If no file path given, open a file picker
if [ -z "$RESPONSES_FILE" ]; then
    echo "[sage] Select the AI response file..."

    # macOS: use AppleScript file picker
    if [[ "$OSTYPE" == "darwin"* ]]; then
        RESPONSES_FILE=$(osascript -e \
            'tell application "Finder"
                activate
                set f to choose file with prompt "Select the AI response file (all_responses.txt):" of type {"txt", "text", "public.plain-text"}
                return POSIX path of f
            end tell' 2>/dev/null) || true

    # Linux: try zenity, then kdialog, then ask manually
    elif command -v zenity &>/dev/null; then
        RESPONSES_FILE=$(zenity --file-selection \
            --title="Select AI response file" \
            --file-filter="Text files | *.txt" 2>/dev/null) || true
    elif command -v kdialog &>/dev/null; then
        RESPONSES_FILE=$(kdialog --getopenfilename . "*.txt" \
            --title "Select AI response file" 2>/dev/null) || true
    fi

    # Fallback: ask user to type the path
    if [ -z "$RESPONSES_FILE" ]; then
        echo ""
        echo "  Could not open file picker. Enter the path to your response file:"
        echo "  (e.g. ~/Downloads/ai_response.txt)"
        read -r -p "  Path: " RESPONSES_FILE
        RESPONSES_FILE="${RESPONSES_FILE/#\~/$HOME}"  # expand ~
    fi
fi

if [ -z "$RESPONSES_FILE" ] || [ ! -f "$RESPONSES_FILE" ]; then
    echo "[sage] File not found: $RESPONSES_FILE"
    exit 1
fi

echo "[sage] Parsing $RESPONSES_FILE ..."

# Use Python for reliable parsing — bash is too fragile for JSON splitting
python3 - "$RESPONSES_FILE" "$RESPONSES_DIR" << 'PYEOF'
import sys, re, json, pathlib

responses_file = pathlib.Path(sys.argv[1])
responses_dir  = pathlib.Path(sys.argv[2])

text = responses_file.read_text(encoding="utf-8")

# Match === CVE-XXXX-XXXXX === followed by JSON on next line(s)
# Handles both single-line and multi-line JSON responses
pattern = re.compile(
    r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|$)',
    re.IGNORECASE
)

saved = 0
errors = 0

for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()

    # Strip markdown fences if present
    raw_json = re.sub(r'^```(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*```$', '', raw_json)
    raw_json = raw_json.strip()

    # Extract just the JSON object (first { ... })
    brace_match = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace_match:
        print(f"  [!] {cve_id} — no JSON found, skipping")
        errors += 1
        continue

    json_str = brace_match.group(0)

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        print(f"  [!] {cve_id} — invalid JSON: {e}")
        errors += 1
        continue

    # Validate required fields
    required = {"vulnerable", "confidence", "reason"}
    missing = required - data.keys()
    if missing:
        print(f"  [!] {cve_id} — missing fields: {missing}")
        errors += 1
        continue

    out_path = responses_dir / f"{cve_id}.json"
    out_path.write_text(json.dumps(data, indent=2))
    status = "vulnerable" if data.get("vulnerable") else "clean"
    conf   = data.get("confidence", 0)
    print(f"  ✓  {cve_id}  [{status}]  confidence={conf:.0%}")
    saved += 1

print(f"\n[sage] Saved {saved} response(s)  |  {errors} error(s)")
if errors > 0:
    print("       Check the format — each CVE must be preceded by === CVE-XXXX-XXXXX ===")
PYEOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Next step: re-run the pipeline to pick up responses"
echo "  python3 main.py --synapse /path/to/$REPO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
