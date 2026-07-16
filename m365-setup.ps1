# =========================================================
# Secure Pulse — Microsoft 365 Scripted Setup
# This script creates (or reuses) an Entra ID app registration with
# read-only Graph permissions for Secure Pulse's M365 security scans.
#
# Run this in PowerShell 7.4+ as a Global Administrator.
# =========================================================

function Start-SecurePulseM365Setup {

    # ═══════════════════════════════════════════════════════
    # STEP 0 — PowerShell version (informational only)
    # ═══════════════════════════════════════════════════════
    # This script only uses Microsoft Graph SDK cmdlets to create an
    # app registration and print credentials — it never runs Prowler
    # itself. The Microsoft Graph SDK officially supports Windows
    # PowerShell 5.1 as well as PowerShell 7+, so no version gate is
    # needed here. (The actual M365 scan does require PowerShell
    # 7.4+, but that runs entirely on Secure Pulse's own scan servers
    # — not on this machine — so it has no bearing on this script.)
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host ""

    # ═══════════════════════════════════════════════════════
    # STEP 1 — Microsoft.Graph module: auto-install if missing, then verify
    # ═══════════════════════════════════════════════════════
    $graphModule = Get-Module -ListAvailable -Name Microsoft.Graph

    if (-not $graphModule) {
        Write-Host ""
        Write-Host "Microsoft.Graph module not found — installing now..." -ForegroundColor Yellow
        Write-Host "(This is a one-time install and may take a few minutes.)" -ForegroundColor Yellow

        try {
            # Ensure PSGallery is trusted first — avoids an interactive
            # "untrusted repository" confirmation prompt that could
            # otherwise hang when this script runs via irm | iex.
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne "Trusted") {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            }

            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } catch {
            Write-Host ""
            Write-Host "ERROR: Failed to install Microsoft.Graph module." -ForegroundColor Red
            Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
            Write-Host "Try running this manually first, then re-run this command:" -ForegroundColor Yellow
            Write-Host "  Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Cyan
            return
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
        return
    }

    Write-Host "Microsoft.Graph module OK: version $($graphModule.Version)" -ForegroundColor Green
    Write-Host ""

    # ═══════════════════════════════════════════════════════
    # STEP 2 — Connect to Microsoft Graph
    # ═══════════════════════════════════════════════════════
    try {
        Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "ERROR: Failed to connect to Microsoft Graph." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $appDisplayName = "Secure Pulse M365 Scanner"
    $graphAppId     = "00000003-0000-0000-c000-000000000000"

    $permissions = @(
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
        "SharePointTenantSettings.Read.All"
    )

    # ═══════════════════════════════════════════════════════
    # STEP 3 — Idempotent app-registration check (avoid duplicates)
    # ═══════════════════════════════════════════════════════
    $existingApp = Get-MgApplication -Filter "displayName eq '$appDisplayName'"

    if ($existingApp) {
        Write-Host "Found existing app registration: $appDisplayName" -ForegroundColor Cyan
        $app = $existingApp
        $sp  = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
    } else {
        Write-Host "Creating new app registration: $appDisplayName" -ForegroundColor Cyan
        $app = New-MgApplication -DisplayName $appDisplayName
        $sp  = New-MgServicePrincipal -AppId $app.AppId
        Start-Sleep -Seconds 5   # brief pause for the service principal to be queryable
    }

    # ═══════════════════════════════════════════════════════
    # STEP 4 — Set required Graph permissions (RequiredResourceAccess)
    # ═══════════════════════════════════════════════════════
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"

    if (-not $graphSp) {
        Write-Host ""
        Write-Host "ERROR: Could not find the Microsoft Graph service principal in this tenant." -ForegroundColor Red
        return
    }

    $resourceAccess = foreach ($permName in $permissions) {
        $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $permName }
        if (-not $role) {
            Write-Host "ERROR: Could not find Graph permission '$permName' — check the permission name is correct." -ForegroundColor Red
            return
        }
        @{ Id = $role.Id; Type = "Role" }
    }

    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @(
        @{ ResourceAppId = $graphAppId; ResourceAccess = $resourceAccess }
    )

    $verifyApp = Get-MgApplication -ApplicationId $app.Id
    if ($verifyApp.RequiredResourceAccess.Count -eq 0) {
        Write-Host "ERROR: Failed to set required permissions on the app registration." -ForegroundColor Red
        Write-Host "Check that your account has Application.ReadWrite.All permission and try again." -ForegroundColor Yellow
        return
    }

    Write-Host "Required permissions configured." -ForegroundColor Green

    # ═══════════════════════════════════════════════════════
    # STEP 5 — Admin consent (skip if already granted)
    # ═══════════════════════════════════════════════════════
    $existingGrants = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue

    if ($existingGrants -and $existingGrants.Count -gt 0) {
        Write-Host "Admin consent already granted for this app." -ForegroundColor Green
        Write-Host "Skipping consent step." -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Waiting for permissions to propagate..." -ForegroundColor Yellow
        Start-Sleep -Seconds 15

        $tenantId   = (Get-MgContext).TenantId
        $consentUrl = "https://login.microsoftonline.com/$tenantId/adminconsent?client_id=$($app.AppId)"

        Write-Host ""
        Write-Host "Opening browser to grant admin consent..." -ForegroundColor Yellow
        Start-Process $consentUrl

        Write-Host ""
        Write-Host "Click 'Accept' on the permissions screen." -ForegroundColor Yellow
        Write-Host "You may see a sign-in error page afterward (AADSTS500113)" -ForegroundColor Yellow
        Write-Host "— this is expected and can be safely ignored. Consent has" -ForegroundColor Yellow
        Write-Host "already been granted at that point. Simply close that tab." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Once you've clicked Accept, return here and press Enter to continue."
        Read-Host
    }

    # ═══════════════════════════════════════════════════════
    # STEP 6 — Client secret: reuse if valid and known, revoke and
    # recreate otherwise
    # ═══════════════════════════════════════════════════════
    $currentApp      = Get-MgApplication -ApplicationId $app.Id
    $existingSecrets = $currentApp.PasswordCredentials
    $validSecret     = $existingSecrets | Where-Object { $_.EndDateTime -gt (Get-Date) } | Select-Object -First 1
    $reenteredSecret = $null

    if ($validSecret) {
        Write-Host ""
        Write-Host "An existing valid client secret was found." -ForegroundColor Cyan
        Write-Host "Note: the secret VALUE cannot be retrieved again after creation." -ForegroundColor Yellow
        $hasSecret = Read-Host "Do you still have the existing secret value saved? (yes/no)"

        if ($hasSecret -eq "yes") {
            $reenteredSecret = Read-Host "Please re-enter your existing Client Secret value"
        } else {
            Write-Host "Revoking the old, now-unrecoverable secret..." -ForegroundColor Yellow
            Remove-MgApplicationPassword -ApplicationId $app.Id -KeyId $validSecret.KeyId
            Write-Host "Old secret revoked." -ForegroundColor Green
        }
    }

    if (-not $reenteredSecret) {
        $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
            displayName = "Secure Pulse scan credential"
            endDateTime = (Get-Date).AddMonths(6)
        }
        $secretValue = $secret.SecretText
    } else {
        $secretValue = $reenteredSecret
    }

    # ═══════════════════════════════════════════════════════
    # STEP 7 — Print credentials with save-now warnings
    # ═══════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "  IMPORTANT — SAVE THESE VALUES NOW" -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "The Client Secret below cannot be retrieved again once" -ForegroundColor Yellow
    Write-Host "this window is closed. Copy all three values into a" -ForegroundColor Yellow
    Write-Host "password manager or the Secure Pulse app before closing" -ForegroundColor Yellow
    Write-Host "this terminal." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Setup completed successfully. Copy the values below into Secure Pulse:" -ForegroundColor Green
    Write-Host ""
    Write-Host "Tenant ID:     $((Get-MgContext).TenantId)"
    Write-Host "Client ID:     $($app.AppId)"
    Write-Host "Client Secret: $secretValue"
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "  Reminder: save these values now before continuing." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
}

Start-SecurePulseM365Setup
