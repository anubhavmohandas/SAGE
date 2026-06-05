# import_responses.ps1 — Split AI's combined response into individual CVE JSON files
# Usage: .\import_responses.ps1 [repo_name] [response_file_path]
# Example: .\import_responses.ps1 CyberTrace
#          .\import_responses.ps1 CyberTrace "C:\Users\you\Downloads\ai_response.txt"

param(
    [string]$Repo = "",
    [string]$ResponseFile = ""
)

# Auto-detect repo
if (-not $Repo) {
    $dirs = Get-ChildItem -Path "data" -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    if ($dirs) { $Repo = $dirs[0].Name }
}
if (-not $Repo) {
    Write-Host "Usage: .\import_responses.ps1 <repo_name> [response_file]"
    exit 1
}

$responsesDir = "data\$Repo\responses"
if (-not (Test-Path $responsesDir)) { New-Item -ItemType Directory -Path $responsesDir | Out-Null }

# If no file provided, open file picker
if (-not $ResponseFile) {
    Write-Host "[sage] Select the AI response file..."
    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title  = "Select AI response file (the one you got from Claude/ChatGPT)"
    $picker.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $picker.InitialDirectory = [Environment]::GetFolderPath("UserProfile") + "\Downloads"

    $result = $picker.ShowDialog()
    if ($result -ne "OK") {
        Write-Host "[sage] No file selected."
        exit 1
    }
    $ResponseFile = $picker.FileName
}

if (-not (Test-Path $ResponseFile)) {
    Write-Host "[sage] File not found: $ResponseFile"
    exit 1
}

Write-Host "[sage] Parsing $ResponseFile ..."
Write-Host ""

# Parse using Python (reliable JSON handling)
$py = @"
import re, json, pathlib, sys

text = pathlib.Path(r'$ResponseFile').read_text(encoding='utf-8')
responses_dir = pathlib.Path(r'$responsesDir')

pattern = re.compile(
    r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|$)',
    re.IGNORECASE
)

saved, errors = 0, 0

for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()
    # Strip markdown fences
    raw_json = re.sub(r'^` + '`' + `+ `` + '`' + `(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*` + '`' + `+ `` + '`' + `$', '', raw_json).strip()
    brace = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace:
        print(f'  [!] {cve_id} -- no JSON found, skipping')
        errors += 1
        continue
    try:
        data = json.loads(brace.group(0))
    except json.JSONDecodeError as e:
        print(f'  [!] {cve_id} -- invalid JSON: {e}')
        errors += 1
        continue
    out = responses_dir / f'{cve_id}.json'
    out.write_text(json.dumps(data, indent=2), encoding='utf-8')
    status = 'VULNERABLE' if data.get('vulnerable') else 'clean'
    conf   = data.get('confidence', 0)
    print(f'  OK  {cve_id}  [{status}]  confidence={conf:.0%}')
    saved += 1

print()
print(f'[sage] Saved {saved} response(s)  |  {errors} error(s)')
"@

# Write to temp file to avoid escaping issues
$tmpScript = [System.IO.Path]::GetTempFileName() + ".py"

# Build clean Python script without string interpolation issues
$pyClean = @"
import re, json, pathlib

text = pathlib.Path(r"""$ResponseFile""").read_text(encoding='utf-8')
responses_dir = pathlib.Path(r"""$responsesDir""")

pattern = re.compile(r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|`$)', re.IGNORECASE)

saved, errors = 0, 0

for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()
    raw_json = re.sub(r'^```(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*```$', '', raw_json).strip()
    brace = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace:
        print(f'  [!] {cve_id} -- no JSON found, skipping')
        errors += 1
        continue
    try:
        data = json.loads(brace.group(0))
    except json.JSONDecodeError as e:
        print(f'  [!] {cve_id} -- invalid JSON: {e}')
        errors += 1
        continue
    out = responses_dir / f'{cve_id}.json'
    out.write_text(json.dumps(data, indent=2), encoding='utf-8')
    status = 'VULNERABLE' if data.get('vulnerable') else 'clean'
    conf   = data.get('confidence', 0)
    print(f'  OK  {cve_id}  [{status:<10}]  confidence={conf:.0%}')
    saved += 1

print()
print(f'[sage] Saved {saved} response(s)  |  {errors} error(s)')
"@

[System.IO.File]::WriteAllText($tmpScript, $pyClean, [System.Text.Encoding]::UTF8)
python3 $tmpScript
Remove-Item $tmpScript -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("=" * 56)
Write-Host "  Next step: re-run the pipeline"
Write-Host "  python3 main.py --synapse path\to\$Repo"
Write-Host ("=" * 56)
