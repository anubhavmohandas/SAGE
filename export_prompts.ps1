# export_prompts.ps1 — Bundle all pending CVE prompts into one file for AI review
# Usage: .\export_prompts.ps1 [repo_name]
# Example: .\export_prompts.ps1 CyberTrace

param([string]$Repo = "")

# Auto-detect repo if not given
if (-not $Repo) {
    $dirs = Get-ChildItem -Path "data" -Directory -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending
    if ($dirs) { $Repo = $dirs[0].Name }
}
if (-not $Repo) {
    Write-Host "Usage: .\export_prompts.ps1 <repo_name>"
    Write-Host "Example: .\export_prompts.ps1 CyberTrace"
    exit 1
}

Write-Host "[sage] Repo: $Repo"

$promptsDir   = "data\$Repo\prompts"
$responsesDir = "data\$Repo\responses"
$outFile      = "data\$Repo\all_prompts.txt"

if (-not (Test-Path $promptsDir)) {
    Write-Host "[sage] No prompts directory found at $promptsDir"
    Write-Host "       Run: python main.py --repo path\to\$Repo --days 7"
    exit 1
}

if (-not (Test-Path $responsesDir)) { New-Item -ItemType Directory -Path $responsesDir | Out-Null }

# Find pending prompts (no matching response file)
$pending = @()
Get-ChildItem "$promptsDir\CVE-*.txt" | ForEach-Object {
    $cveId = $_.BaseName
    $respFile = "$responsesDir\$cveId.json"
    if (-not (Test-Path $respFile)) {
        $pending += $_
    }
}

if ($pending.Count -eq 0) {
    Write-Host "[sage] No pending prompts — all responses already saved."
    exit 0
}

Write-Host "[sage] Found $($pending.Count) pending CVE(s) — bundling into $outFile"

$header = @"
You are a security vulnerability analyst. Below are multiple CVE analysis tasks.
For EACH CVE, respond with EXACTLY this format — no extra text, no markdown:

=== CVE-XXXX-XXXXX ===
{"vulnerable": true or false, "confidence": 0.0-1.0, "reason": "one sentence", "affected_functions": ["fn1"], "attack_vector": "how attacker reaches it, or empty string", "recommendation": "fix, or empty string"}

Analyze each CVE independently. Output ALL responses before moving to the next.
---

"@

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add($header)

foreach ($f in $pending) {
    $lines.Add("=" * 38)
    $lines.Add("TASK: $($f.BaseName)")
    $lines.Add("=" * 38)
    $lines.Add((Get-Content $f.FullName -Raw -Encoding UTF8))
    $lines.Add("")
    $lines.Add("")
}

$content = $lines -join "`n"
[System.IO.File]::WriteAllText((Resolve-Path "." | Join-Path -ChildPath $outFile), $content, [System.Text.Encoding]::UTF8)

$size = (Get-Item $outFile).Length
Write-Host "[sage] Bundle written -> $outFile"
Write-Host "[sage] Size: $size bytes, $($pending.Count) CVEs"
Write-Host ""
Write-Host ("=" * 56)
Write-Host "  Next steps:"
Write-Host "  1. Upload $outFile to Claude / ChatGPT / Gemini"
Write-Host "  2. Save the AI's full response anywhere on your PC"
Write-Host "  3. Run: .\import_responses.ps1 $Repo"
Write-Host ("=" * 56)

# Open the file in default text editor
Start-Process $outFile
