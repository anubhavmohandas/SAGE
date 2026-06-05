# sage_scan.ps1 — Interactive SAGE setup + scan launcher (Windows)
#
# Usage:
#   .\sage_scan.ps1                          # interactive
#   .\sage_scan.ps1 C:\path\to\repo          # skip path question
#   .\sage_scan.ps1 C:\path\to\repo --days 7

param(
    [string]$RepoPath = "",
    [string]$Days = ""
)

$SageDir  = $PSScriptRoot
$EnvFile  = "$SageDir\.env"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   SAGE — Security Analysis & Graph Engine    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Get repo path ─────────────────────────────────────────────────────
if (-not $RepoPath) {
    Write-Host "Which repo do you want to scan?" -ForegroundColor White
    Write-Host "Enter full path, or press Enter to browse..." -ForegroundColor DarkGray

    $typed = Read-Host "  Repo path"

    if (-not $typed) {
        # Open folder picker
        Add-Type -AssemblyName System.Windows.Forms
        $picker = New-Object System.Windows.Forms.FolderBrowserDialog
        $picker.Description = "Select the repository to scan"
        $picker.ShowNewFolderButton = $false
        if ($picker.ShowDialog() -eq "OK") {
            $RepoPath = $picker.SelectedPath
        } else {
            Write-Host "[sage] No repo selected." -ForegroundColor Red
            exit 1
        }
    } else {
        $RepoPath = $typed
    }
}

if (-not (Test-Path $RepoPath)) {
    Write-Host "[sage] Directory not found: $RepoPath" -ForegroundColor Red
    exit 1
}

$RepoName = Split-Path $RepoPath -Leaf
Write-Host ""
Write-Host "Repo: $RepoPath ($RepoName)" -ForegroundColor White

# ── Step 2: Detect GitHub remote ─────────────────────────────────────────────
$DetectedGitHub = ""
if (Test-Path "$RepoPath\.git") {
    try {
        $rawRemote = git -C $RepoPath remote get-url origin 2>$null
        if ($rawRemote) {
            if ($rawRemote -match "github\.com[/:]([^/]+/[^/]+?)(\.git)?$") {
                $DetectedGitHub = $Matches[1]
            }
        }
    } catch {}
}

# ── Step 3: Read current .env ─────────────────────────────────────────────────
$CurrentEnvRepo = ""
if (Test-Path $EnvFile) {
    $envContent = Get-Content $EnvFile
    foreach ($line in $envContent) {
        if ($line -match "^GITHUB_REPO=(.+)$") {
            $CurrentEnvRepo = $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
}

Write-Host ""
if ($DetectedGitHub) {
    Write-Host "  GitHub remote detected: $DetectedGitHub" -ForegroundColor Green
} else {
    Write-Host "  No GitHub remote found in repo" -ForegroundColor Yellow
}
Write-Host "  GITHUB_REPO in .env:    $(if ($CurrentEnvRepo) { $CurrentEnvRepo } else { 'not set' })" -ForegroundColor DarkGray

# ── Step 4: Handle mismatch ───────────────────────────────────────────────────
$TargetRepo = ""

if ($DetectedGitHub -and $DetectedGitHub -eq $CurrentEnvRepo) {
    $TargetRepo = $DetectedGitHub
    Write-Host "  ✓ GitHub repo matches .env — no changes needed" -ForegroundColor Green

} elseif ($DetectedGitHub -and $CurrentEnvRepo -and $DetectedGitHub -ne $CurrentEnvRepo) {
    Write-Host ""
    Write-Host "  GITHUB_REPO in .env doesn't match this repo's remote." -ForegroundColor Yellow
    Write-Host "  [1] Update .env to use $DetectedGitHub (detected)"
    Write-Host "  [2] Keep .env as $CurrentEnvRepo"
    Write-Host "  [3] Enter manually"
    $choice = Read-Host "  Choice (1/2/3)"
    switch ($choice) {
        "1" { $TargetRepo = $DetectedGitHub }
        "2" { $TargetRepo = $CurrentEnvRepo }
        "3" { $TargetRepo = Read-Host "  Enter owner/repo (e.g. anubhavmohandas/MyApp)" }
        default { $TargetRepo = $DetectedGitHub }
    }

} elseif (-not $CurrentEnvRepo) {
    Write-Host ""
    if ($DetectedGitHub) {
        Write-Host "  GITHUB_REPO not set in .env."
        Write-Host "  [1] Set to $DetectedGitHub (detected)"
        Write-Host "  [2] Enter manually"
        Write-Host "  [3] Skip (no PR creation)"
        $choice = Read-Host "  Choice (1/2/3)"
        switch ($choice) {
            "1" { $TargetRepo = $DetectedGitHub }
            "2" { $TargetRepo = Read-Host "  Enter owner/repo" }
            default { $TargetRepo = "" }
        }
    } else {
        Write-Host "  [1] Enter GitHub repo for PR creation"
        Write-Host "  [2] Skip"
        $choice = Read-Host "  Choice (1/2)"
        if ($choice -eq "1") { $TargetRepo = Read-Host "  Enter owner/repo" }
    }
} else {
    $TargetRepo = $CurrentEnvRepo
}

# ── Step 5: Update .env ───────────────────────────────────────────────────────
if ($TargetRepo -and $TargetRepo -ne $CurrentEnvRepo) {
    if (Test-Path $EnvFile) {
        $envLines = Get-Content $EnvFile
        $updated  = $envLines | ForEach-Object {
            if ($_ -match "^GITHUB_REPO=") { "GITHUB_REPO=$TargetRepo" } else { $_ }
        }
        if (-not ($envLines -match "^GITHUB_REPO=")) {
            $updated += "GITHUB_REPO=$TargetRepo"
        }
        [System.IO.File]::WriteAllLines($EnvFile, $updated, [System.Text.Encoding]::UTF8)
    } else {
        "GITHUB_REPO=$TargetRepo" | Out-File $EnvFile -Encoding UTF8
    }
    Write-Host "  ✓ .env updated: GITHUB_REPO=$TargetRepo" -ForegroundColor Green
}

# ── Step 6: Clear cached choice ──────────────────────────────────────────────
$cacheFile = "$SageDir\data\$RepoName\.github_repo"
if (Test-Path $cacheFile) { Remove-Item $cacheFile -Force }

# ── Step 7: Scan window ───────────────────────────────────────────────────────
if (-not $Days) {
    Write-Host ""
    Write-Host "Scan window (days of CVE history):" -ForegroundColor White
    Write-Host "  [1] 1 day   — today only (fast)"
    Write-Host "  [2] 7 days  — last week (recommended)"
    Write-Host "  [3] 30 days — last month (thorough)"
    Write-Host "  [4] Custom"
    $dChoice = Read-Host "  Choice [default: 2]"
    switch ($dChoice) {
        "1" { $Days = "1" }
        "3" { $Days = "30" }
        "4" { $Days = Read-Host "  Enter days" }
        default { $Days = "7" }
    }
}

# ── Step 8: Launch ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Scanning:   $RepoPath"
Write-Host "  GitHub PR:  $(if ($TargetRepo) { $TargetRepo } else { 'disabled' })"
Write-Host "  Days:       $Days"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

Set-Location $SageDir

# Activate venv if present
$venvActivate = "$SageDir\venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) { & $venvActivate }

python3 main.py --repo $RepoPath --days $Days
