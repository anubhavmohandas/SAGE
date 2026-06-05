#!/bin/bash
# import_patches.sh — Split AI's patch response into individual files
# Usage: bash import_patches.sh [repo_name] [response_file]

set -e
REPO="${1:-}"
RESPONSE_FILE="${2:-}"

if [ -z "$REPO" ]; then
    REPO=$(ls -t data/ 2>/dev/null | head -1)
    [ -z "$REPO" ] && echo "Usage: bash import_patches.sh <repo_name>" && exit 1
fi

PATCHES_DIR="data/$REPO/patches"
mkdir -p "$PATCHES_DIR"

if [ -z "$RESPONSE_FILE" ]; then
    echo "[sage] Select the AI patch response file..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        RESPONSE_FILE=$(osascript -e \
            'tell application "Finder"
                activate
                set f to choose file with prompt "Select AI patch response file:"
                return POSIX path of f
            end tell' 2>/dev/null) || true
    elif command -v zenity &>/dev/null; then
        RESPONSE_FILE=$(zenity --file-selection --title="Select AI patch response" 2>/dev/null) || true
    fi
    if [ -z "$RESPONSE_FILE" ]; then
        read -r -p "  Path to response file: " RESPONSE_FILE
        RESPONSE_FILE="${RESPONSE_FILE/#\~/$HOME}"
    fi
fi

[ ! -f "$RESPONSE_FILE" ] && echo "[sage] File not found: $RESPONSE_FILE" && exit 1

echo "[sage] Parsing $RESPONSE_FILE ..."

python3 - "$RESPONSE_FILE" "$PATCHES_DIR" "$REPO" << 'PYEOF'
import sys, re, json, pathlib

resp_file   = pathlib.Path(sys.argv[1])
patches_dir = pathlib.Path(sys.argv[2])
repo        = sys.argv[3]

text = resp_file.read_text(encoding="utf-8")
pattern = re.compile(r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|$)', re.IGNORECASE)

saved, errors = 0, 0
for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()
    raw_json = re.sub(r'^```(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*```$', '', raw_json).strip()
    brace = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace:
        print(f"  [!] {cve_id} — no JSON found")
        errors += 1
        continue
    try:
        data = json.loads(brace.group(0))
    except json.JSONDecodeError as e:
        print(f"  [!] {cve_id} — invalid JSON: {e}")
        errors += 1
        continue
    out = patches_dir / f"patch_response_{cve_id}.json"
    out.write_text(json.dumps(data, indent=2))
    n_files = len(data.get("patched_files", []))
    print(f"  ✓  {cve_id}  →  {n_files} file(s) patched  |  {data.get('summary','')[:60]}")
    saved += 1

print(f"\n[sage] Saved {saved} patch(es)  |  {errors} error(s)")
if saved:
    print(f"\n  Re-run pipeline to apply patches:")
    print(f"  python3 main.py --synapse /path/to/{repo}")
PYEOF
