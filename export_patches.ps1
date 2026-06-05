# export_patches.ps1 — Bundle pending patch prompts for AI review
# Usage: .\export_patches.ps1 [repo_name]

param([string]$Repo = "")

if (-not $Repo) {
    $dirs = Get-ChildItem -Path "data" -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($dirs) { $Repo = $dirs[0].Name }
}
if (-not $Repo) { Write-Host "Usage: .\export_patches.ps1 <repo_name>"; exit 1 }

$patchesDir = "data\$Repo\patches"
$outFile    = "data\$Repo\all_patch_prompts.txt"

if (-not (Test-Path $patchesDir)) {
    Write-Host "[sage] No patches directory at $patchesDir — run the pipeline first."
    exit 1
}

$pending = @()
Get-ChildItem "$patchesDir\patch_prompt_CVE-*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
    $cveId = $_.BaseName -replace "patch_prompt_", ""
    if (-not (Test-Path "$patchesDir\patch_response_$cveId.json")) {
        $pending += $_
    }
}

if ($pending.Count -eq 0) { Write-Host "[sage] No pending patch prompts."; exit 0 }

Write-Host "[sage] Found $($pending.Count) pending patch(es) — bundling into $outFile"

$header = @"
You are a security engineer. Below are multiple code patching tasks.
For EACH task, respond with EXACTLY this format — no extra text, no markdown:

=== CVE-XXXX-XXXXX ===
{"patched_files": [{"file": "relative/path.py", "original_function": "fn_name", "patched_code": "complete patched function", "explanation": "what changed and why"}], "summary": "one sentence"}

---

"@

$parts = @($header)
foreach ($f in $pending) {
    $cveId = $f.BaseName -replace "patch_prompt_", ""
    $parts += "=" * 38
    $parts += "TASK: $cveId"
    $parts += "=" * 38
    $parts += (Get-Content $f.FullName -Raw -Encoding UTF8)
    $parts += ""
}

[System.IO.File]::WriteAllText((Join-Path (Get-Location) $outFile), ($parts -join "`n"), [System.Text.Encoding]::UTF8)

Write-Host "[sage] Bundle → $outFile ($($pending.Count) patches)"
Write-Host ""
Write-Host ("=" * 56)
Write-Host "  1. Upload $outFile to Claude / ChatGPT"
Write-Host "  2. Save AI response anywhere on your PC"
Write-Host "  3. Run: .\import_patches.ps1 $Repo"
Write-Host ("=" * 56)
Start-Process $outFile
