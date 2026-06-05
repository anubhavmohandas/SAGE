# import_patches.ps1 — Split AI's patch response into individual files
# Usage: .\import_patches.ps1 [repo_name] [response_file]

param([string]$Repo = "", [string]$ResponseFile = "")

if (-not $Repo) {
    $dirs = Get-ChildItem -Path "data" -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($dirs) { $Repo = $dirs[0].Name }
}
if (-not $Repo) { Write-Host "Usage: .\import_patches.ps1 <repo_name>"; exit 1 }

$patchesDir = "data\$Repo\patches"
if (-not (Test-Path $patchesDir)) { New-Item -ItemType Directory -Path $patchesDir | Out-Null }

if (-not $ResponseFile) {
    Write-Host "[sage] Select the AI patch response file..."
    Add-Type -AssemblyName System.Windows.Forms
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title  = "Select AI patch response file"
    $picker.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
    $picker.InitialDirectory = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    if ($picker.ShowDialog() -ne "OK") { Write-Host "[sage] No file selected."; exit 1 }
    $ResponseFile = $picker.FileName
}

if (-not (Test-Path $ResponseFile)) { Write-Host "[sage] File not found: $ResponseFile"; exit 1 }

Write-Host "[sage] Parsing $ResponseFile ..."

$tmpScript = [System.IO.Path]::GetTempFileName() + ".py"
$pyScript = @"
import re, json, pathlib

text = pathlib.Path(r"""$ResponseFile""").read_text(encoding='utf-8')
patches_dir = pathlib.Path(r"""$patchesDir""")
pattern = re.compile(r'===\s*(CVE-[\w-]+)\s*===\s*\n([\s\S]*?)(?====\s*CVE-|`$)', re.IGNORECASE)

saved, errors = 0, 0
for match in pattern.finditer(text):
    cve_id   = match.group(1).strip()
    raw_json = match.group(2).strip()
    raw_json = re.sub(r'^` + '`'*3 + `(?:json)?\s*', '', raw_json)
    raw_json = re.sub(r'\s*` + '`'*3 + `$', '', raw_json).strip()
    brace = re.search(r'\{[\s\S]*\}', raw_json)
    if not brace:
        print(f'  [!] {cve_id} -- no JSON found')
        errors += 1
        continue
    try:
        data = json.loads(brace.group(0))
    except json.JSONDecodeError as e:
        print(f'  [!] {cve_id} -- invalid JSON: {e}')
        errors += 1
        continue
    out = patches_dir / f'patch_response_{cve_id}.json'
    out.write_text(json.dumps(data, indent=2))
    n = len(data.get('patched_files', []))
    print(f'  OK  {cve_id}  ->  {n} file(s) patched  |  {data.get(\"summary\",\"\")[:60]}')
    saved += 1

print(f'')
print(f'[sage] Saved {saved} patch(es)  |  {errors} error(s)')
"@

[System.IO.File]::WriteAllText($tmpScript, $pyScript, [System.Text.Encoding]::UTF8)
python3 $tmpScript
Remove-Item $tmpScript -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("=" * 56)
Write-Host "  Re-run pipeline to apply patches:"
Write-Host "  python3 main.py --synapse path\to\$Repo"
Write-Host ("=" * 56)
