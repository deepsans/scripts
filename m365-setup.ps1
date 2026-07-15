# ═══════════════════════════════════════════════════════
# STEP 0 — PowerShell version check (hard stop, cannot auto-fix)
# ═══════════════════════════════════════════════════════
if ($PSVersionTable.PSVersion.Major -lt 7 -or 
    ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
    Write-Host ""
    Write-Host "ERROR: PowerShell 7.4 or higher is required." -ForegroundColor Red
    Write-Host "You are running $($PSVersionTable.PSVersion)." -ForegroundColor Red
    Write-Host ""
    Write-Host "Install PowerShell 7.4+ first:" -ForegroundColor Yellow
    Write-Host "  Windows: winget install --id Microsoft.PowerShell --source winget"
    Write-Host "  macOS:   brew install powershell/tap/powershell"
    Write-Host ""
    Write-Host "Then re-run this command in a NEW PowerShell 7 session." -ForegroundColor Yellow
    exit 1
}

Write-Host "PowerShell version OK: $($PSVersionTable.PSVersion)" -ForegroundColor Green

# ═══════════════════════════════════════════════════════
# STEP 1 — Microsoft.Graph module: auto-install if missing, then verify
# ═══════════════════════════════════════════════════════
$graphModule = Get-Module -ListAvailable -Name Microsoft.Graph

if (-not $graphModule) {
    Write-Host ""
    Write-Host "Microsoft.Graph module not found — installing now..." -ForegroundColor Yellow
    Write-Host "(This is a one-time install and may take a few minutes.)" -ForegroundColor Yellow

    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "ERROR: Failed to install Microsoft.Graph module." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Verify it actually installed correctly, regardless of whether it 
# was already present or just installed above
$graphModule = Get-Module -ListAvailable -Name Microsoft.Graph | 
    Sort-Object Version -Descending | Select-Object -First 1

if (-not $graphModule) {
    Write-Host ""
    Write-Host "ERROR: Microsoft.Graph module still not found after install attempt." -ForegroundColor Red
    Write-Host "Try running manually: Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
    exit 1
}

Write-Host "Microsoft.Graph module OK: version $($graphModule.Version)" -ForegroundColor Green
Write-Host ""

# ═══════════════════════════════════════════════════════
# Everything below is the existing corrected setup logic —
# idempotent app-registration check, permission assignment via
# RequiredResourceAccess, browser-based admin consent, and secret
# rotation handling exactly as already built and tested.
# ═══════════════════════════════════════════════════════
