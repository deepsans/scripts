# =========================================================
# Secure Pulse — Azure Scripted Setup
# This script creates (or reuses) an Entra ID app registration with
# read-only Graph permissions AND attempts to assign the Reader role
# on your current Azure subscription for Secure Pulse's Azure
# security scans.
#
# Run this in PowerShell as a user with:
#   - Rights to create App Registrations in Entra ID
#   - Ideally, Owner or User Access Administrator on the Azure
#     subscription you want to scan (if you don't have this, the
#     script will still complete the app/credentials part and print
#     a command for someone who does have that role to run separately)
# =========================================================

function Start-SecurePulseAzureSetup {

    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host ""

    # ═══════════════════════════════════════════════════════
    # STEP 1 — Required modules: auto-install if missing, then verify
    # ═══════════════════════════════════════════════════════
    $requiredModules = @("Microsoft.Graph", "Az.Accounts", "Az.Resources")

    foreach ($moduleName in $requiredModules) {
        $mod = Get-Module -ListAvailable -Name $moduleName

        if (-not $mod) {
            Write-Host "$moduleName module not found — installing now..." -ForegroundColor Yellow
            Write-Host "(This is a one-time install and may take a few minutes.)" -ForegroundColor Yellow

            try {
                $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
                if ($psGallery -and $psGallery.InstallationPolicy -ne "Trusted") {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                }

                Install-Module $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            } catch {
                Write-Host ""
                Write-Host "ERROR: Failed to install $moduleName module." -ForegroundColor Red
                Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host ""
                Write-Host "Try running this manually first, then re-run this command:" -ForegroundColor Yellow
                Write-Host "  Install-Module $moduleName -Scope CurrentUser -Force" -ForegroundColor Cyan
                return
            }
        }

        $verify = Get-Module -ListAvailable -Name $moduleName |
            Sort-Object Version -Descending | Select-Object -First 1

        if (-not $verify) {
            Write-Host ""
            Write-Host "ERROR: $moduleName module still not found after install attempt." -ForegroundColor Red
            Write-Host "Try running manually: Install-Module $moduleName -Scope CurrentUser -Force" -ForegroundColor Yellow
            return
        }

        Write-Host "$moduleName module OK: version $($verify.Version)" -ForegroundColor Green
    }

    Write-Host ""

    # ═══════════════════════════════════════════════════════
    # STEP 2 — Connect to Microsoft Graph (for app registration)
    # ═══════════════════════════════════════════════════════
    try {
        Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "ERROR: Failed to connect to Microsoft Graph." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $appDisplayName = "Secure Pulse Azure Scanner"
    $graphAppId     = "00000003-0000-0000-c000-000000000000"

    $permissions = @(
        "AuditLog.Read.All",
        "Directory.Read.All",
        "Policy.Read.All"
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

    try {
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @(
            @{ ResourceAppId = $graphAppId; ResourceAccess = $resourceAccess }
        ) -ErrorAction Stop
    } catch {
        Write-Host ""
        Write-Host "ERROR: Failed to set required permissions on the app registration." -ForegroundColor Red
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "This usually means:" -ForegroundColor Yellow
        Write-Host "  - Your signed-in account does not have Global Administrator or" -ForegroundColor Yellow
        Write-Host "    Application Administrator rights in this tenant, OR" -ForegroundColor Yellow
        Write-Host "  - The Connect-MgGraph session above did not receive the" -ForegroundColor Yellow
        Write-Host "    Application.ReadWrite.All scope (try closing this window," -ForegroundColor Yellow
        Write-Host "    opening a new one, and running the command again so a fresh" -ForegroundColor Yellow
        Write-Host "    sign-in prompt appears)." -ForegroundColor Yellow
        return
    }

    $verifyApp = Get-MgApplication -ApplicationId $app.Id
    if ($verifyApp.RequiredResourceAccess.Count -eq 0) {
        Write-Host "ERROR: Permissions did not save correctly — RequiredResourceAccess is still empty." -ForegroundColor Red
        return
    }

    Write-Host "Required Graph permissions configured." -ForegroundColor Green

    # ═══════════════════════════════════════════════════════
    # STEP 5 — Admin consent for Graph permissions (skip if already granted)
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
    # STEP 6 — Connect to Azure (for subscription role assignment)
    # ═══════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "Now connecting to Azure to assign the subscription Reader role..." -ForegroundColor Cyan
    Write-Host "A separate browser sign-in window may open." -ForegroundColor Cyan

    $readerAssigned      = $false
    $subscriptionId      = $null
    $subscriptionName    = $null

    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null

        $context = Get-AzContext
        $subscriptionId   = $context.Subscription.Id
        $subscriptionName = $context.Subscription.Name

        Write-Host "Using subscription: $subscriptionName ($subscriptionId)" -ForegroundColor Cyan
        Write-Host "(To use a different subscription, run Set-AzContext -SubscriptionId <id> and re-run this script.)" -ForegroundColor Yellow

        # ═══════════════════════════════════════════════════════
        # STEP 7 — Assign Reader role (skip if already assigned)
        # ═══════════════════════════════════════════════════════
        $existingReader = Get-AzRoleAssignment -ApplicationId $app.AppId -Scope "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -eq "Reader" }

        if ($existingReader) {
            Write-Host "Reader role already assigned on this subscription." -ForegroundColor Green
            $readerAssigned = $true
        } else {
            New-AzRoleAssignment -ApplicationId $app.AppId -RoleDefinitionName "Reader" -Scope "/subscriptions/$subscriptionId" -ErrorAction Stop | Out-Null
            Write-Host "Reader role assigned automatically." -ForegroundColor Green
            $readerAssigned = $true
        }
    } catch {
        Write-Host ""
        Write-Host "Could not assign the Reader role automatically." -ForegroundColor Yellow
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "This usually means you are not an Owner or User Access" -ForegroundColor Yellow
        Write-Host "Administrator on this subscription." -ForegroundColor Yellow

        if ($subscriptionId) {
            Write-Host ""
            Write-Host "Ask someone with that role to run this command:" -ForegroundColor Yellow
            Write-Host "  az role assignment create --role Reader --assignee $($app.AppId) --scope /subscriptions/$subscriptionId" -ForegroundColor Cyan
        } else {
            Write-Host ""
            Write-Host "A subscription could not be determined. If you don't have an" -ForegroundColor Yellow
            Write-Host "Azure subscription yet, create one first at:" -ForegroundColor Yellow
            Write-Host "  https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBlade" -ForegroundColor Cyan
            Write-Host "Then re-run this script." -ForegroundColor Yellow
        }
    }

    # ═══════════════════════════════════════════════════════
    # STEP 8 — Client secret: reuse if valid and known, revoke and
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
    # STEP 9 — Print credentials with save-now warnings + summary
    # ═══════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "  IMPORTANT — SAVE THESE VALUES NOW" -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "The Client Secret below cannot be retrieved again once" -ForegroundColor Yellow
    Write-Host "this window is closed. Copy all values into a password" -ForegroundColor Yellow
    Write-Host "manager or the Secure Pulse app before closing this" -ForegroundColor Yellow
    Write-Host "terminal." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Setup completed. Copy the values below into Secure Pulse:" -ForegroundColor Green
    Write-Host ""
    Write-Host "Tenant ID:        $((Get-MgContext).TenantId)"
    Write-Host "Client ID:        $($app.AppId)"
    Write-Host "Client Secret:    $secretValue"
    Write-Host "Subscription ID:  $(if ($subscriptionId) { $subscriptionId } else { '(not set — see summary below)' })"
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "  Reminder: save these values now before continuing." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Setup summary:" -ForegroundColor Cyan
    Write-Host "  Graph permissions:  Consented" -ForegroundColor Green
    Write-Host "  Reader role:        $(if ($readerAssigned) { 'Assigned automatically' } else { 'NEEDS MANUAL ASSIGNMENT — see instructions above' })" -ForegroundColor $(if ($readerAssigned) { 'Green' } else { 'Yellow' })
    Write-Host ""
    Write-Host "Note: the custom 'ProwlerRole' (needed for a small number of" -ForegroundColor Cyan
    Write-Host "additional checks) is not created by this script yet. You can" -ForegroundColor Cyan
    Write-Host "add it later from the Secure Pulse app or Azure Portal — Reader" -ForegroundColor Cyan
    Write-Host "access alone is enough to connect and run most scans." -ForegroundColor Cyan
}

Start-SecurePulseAzureSetup
