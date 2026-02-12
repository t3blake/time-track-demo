# Time Entry Demo - Automated Deployment Script
# Deploys a complete time entry web app to Azure Static Web Apps with:
#   - Azure Table Storage for persistence
#   - Entra ID (single-tenant) authentication
#   - Azure Functions API backend
#   - Service principal auth for Table Storage access
#
# Prerequisites:
#   - Azure CLI (az) installed and logged in
#   - Node.js 18+ installed
#   - PowerShell 7+
#
# Usage:
#   ./deploy.ps1                          # Deploy with defaults
#   ./deploy.ps1 -Location westus2        # Override region
#   ./deploy.ps1 -Prefix myteam          # Custom resource prefix
#   ./deploy.ps1 -SkipAuth               # Skip Entra ID setup (anonymous access)
#   ./deploy.ps1 -Teardown               # Remove all resources

param(
    [string]$Prefix = "timeentry",
    [string]$Location = "eastus2",
    [switch]$SkipAuth,
    [switch]$Teardown
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step($msg) { Write-Host "`n🔷 $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "  ✅ $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  ⚠️  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "  ❌ $msg" -ForegroundColor Red }

function Assert-Tool($cmd, $name, $installHint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Err "$name is required but not found."
        if ($installHint) { Write-Host "    Install: $installHint" -ForegroundColor DarkGray }
        exit 1
    }
}

function Get-ScriptDir {
    if ($PSScriptRoot) { return $PSScriptRoot }
    return Split-Path -Parent $MyInvocation.MyCommand.Path
}

# ── Banner ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          Time Entry Demo - Deployment Script            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# ── Pre-flight checks ───────────────────────────────────────────────────────

Assert-Tool "az"   "Azure CLI"   "winget install Microsoft.AzureCLI"
Assert-Tool "node" "Node.js"     "winget install OpenJS.NodeJS.LTS"
Assert-Tool "npm"  "npm"         "(included with Node.js)"

Write-Step "Checking Azure CLI login..."
$account = az account show --query "{name:name, id:id, tenantId:tenantId}" -o json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Warn "Not logged in. Opening browser for login..."
    az login | Out-Null
    $account = az account show --query "{name:name, id:id, tenantId:tenantId}" -o json | ConvertFrom-Json
}
Write-OK "Subscription: $($account.name) ($($account.id))"
Write-OK "Tenant:       $($account.tenantId)"

$subId    = $account.id
$tenantId = $account.tenantId

# ── Resource names ───────────────────────────────────────────────────────────

$rgName      = "rg-$Prefix-demo"
$swaName     = "$Prefix-demo"
$storageName = ($Prefix -replace '[^a-z0-9]','') + "demostore"
if ($storageName.Length -gt 24) { $storageName = $storageName.Substring(0, 24) }
$authAppName = "$Prefix-swa-auth"
$apiAppName  = "$Prefix-table-api"
$scriptDir   = Get-ScriptDir

Write-Step "Resource plan:"
Write-Host "  Resource Group:   $rgName"
Write-Host "  Static Web App:   $swaName"
Write-Host "  Storage Account:  $storageName"
Write-Host "  Location:         $Location"
if (-not $SkipAuth) { Write-Host "  Auth App:         $authAppName (single-tenant)" }
Write-Host "  API App:          $apiAppName"
Write-Host ""

# ── Teardown ─────────────────────────────────────────────────────────────────

if ($Teardown) {
    Write-Step "Tearing down all resources..."
    Write-Warn "This will delete resource group '$rgName' and all Entra app registrations."
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -ne 'yes') { Write-Host "Aborted."; exit 0 }

    foreach ($appName in @($authAppName, $apiAppName)) {
        $apps = az ad app list --display-name $appName --query "[].appId" -o tsv 2>$null
        foreach ($appId in $apps) {
            Write-Host "  Deleting app registration $appId ($appName)..."
            az ad app delete --id $appId 2>$null
        }
    }

    $rgExists = az group exists --name $rgName -o tsv 2>$null
    if ($rgExists -eq "true") {
        az group delete --name $rgName --yes --no-wait 2>$null
        Write-OK "Resource group deletion initiated (runs in background)."
    } else {
        Write-Warn "Resource group '$rgName' not found — nothing to delete."
    }

    Write-OK "Teardown complete."
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
#  DEPLOYMENT
# ═════════════════════════════════════════════════════════════════════════════

# ── 1. Resource Group ────────────────────────────────────────────────────────

Write-Step "1/8  Creating resource group..."
az group create --name $rgName --location $Location -o none
Write-OK "Resource group '$rgName' ready."

# ── 2. Storage Account + Table ───────────────────────────────────────────────

Write-Step "2/8  Creating storage account and table..."
az storage account create `
    --name $storageName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard_LRS `
    --min-tls-version TLS1_2 `
    --allow-blob-public-access false `
    -o none
Write-OK "Storage account '$storageName' created."

$storageUrl = "https://$storageName.table.core.windows.net"

# Create the TimeEntries table via ARM management plane.
# NOTE: The "Storage Table Data Contributor" RBAC role only grants entity-level
# operations (read/write/delete rows), NOT table creation. The createTable call
# in the API code handles this gracefully (catches 403), but we create the table
# at deploy time to ensure it exists without requiring elevated permissions.
az rest --method PUT `
    --url "/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$storageName/tableServices/default/tables/TimeEntries?api-version=2023-01-01" `
    --body '{}' -o none 2>$null
Write-OK "TimeEntries table created."

# ── 3. Service Principal for Table Storage ───────────────────────────────────

Write-Step "3/8  Creating service principal for Table Storage access..."

# Create (or find existing) app registration
$existingApp = az ad app list --display-name $apiAppName --query "[0].appId" -o tsv 2>$null
if ($existingApp) {
    $apiAppId = $existingApp
    Write-Host "  Using existing app registration: $apiAppId"
} else {
    $apiApp = az ad app create --display-name $apiAppName -o json | ConvertFrom-Json
    $apiAppId = $apiApp.appId
}

# Ensure service principal exists (idempotent — silently ignores "already exists")
az ad sp create --id $apiAppId 2>$null | Out-Null
$spObjectId = az ad sp show --id $apiAppId --query id -o tsv

# Create a client secret (1-year expiry)
# Some tenants have a policy blocking password credentials on app registrations.
# If that happens, fall back to a certificate-based credential.
$apiSecret = $null
try {
    $apiCred = az ad app credential reset --id $apiAppId --append `
        --display-name "deploy-$(Get-Date -Format 'yyyyMMdd')" --years 1 -o json 2>&1
    if ($LASTEXITCODE -eq 0) {
        $apiCred = $apiCred | ConvertFrom-Json
        $apiSecret = $apiCred.password
        Write-OK "Password credential created for API service principal."
    } else {
        throw "Password credential blocked"
    }
} catch {
    Write-Warn "Password credential blocked by policy — creating self-signed certificate credential..."
    $certName = "$apiAppName-cert"
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$certName" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(1) `
        -KeySpec Signature `
        -HashAlgorithm SHA256
    $certThumbprint = $cert.Thumbprint
    $certPath = "$scriptDir\$certName.pem"
    # Export public key and upload to app registration
    $pemContent = [Convert]::ToBase64String($cert.RawData)
    az ad app credential reset --id $apiAppId --cert $pemContent --append -o none 2>$null
    # Export PFX for the ClientCertificateCredential
    $pfxPath = "$scriptDir\$certName.pfx"
    $emptyPwd = New-Object System.Security.SecureString
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $emptyPwd | Out-Null
    $apiCertPath = $pfxPath
    Write-OK "Certificate credential created (thumbprint: $certThumbprint)."
    Write-Warn "The API will need to be updated to use ClientCertificateCredential."
    Write-Warn "Certificate exported to: $pfxPath"
}

# Assign "Storage Table Data Contributor" role on the storage account
$storageId = az storage account show --name $storageName --resource-group $rgName --query id -o tsv
az role assignment create `
    --assignee-object-id $spObjectId `
    --assignee-principal-type ServicePrincipal `
    --role "Storage Table Data Contributor" `
    --scope $storageId `
    -o none 2>$null
Write-OK "Service principal '$apiAppName' ready with Storage Table Data Contributor role."

# ── 4. Static Web App ───────────────────────────────────────────────────────

Write-Step "4/8  Creating Static Web App (Standard tier)..."
az staticwebapp create `
    --name $swaName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard `
    -o none 2>$null
Write-OK "Static Web App '$swaName' created (Standard tier)."

# Enable system-assigned managed identity.
# NOTE: MI is not usable by SWA managed function code at runtime, but enabling
# it is good practice and may be required by organizational policies.
Write-Host "  Enabling managed identity..."
$miResult = az staticwebapp identity assign `
    --name $swaName `
    --resource-group $rgName `
    --identities [system] `
    -o json 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-OK "System-assigned managed identity enabled."
} else {
    Write-Warn "Could not enable managed identity (non-blocking). $miResult"
}

$swaHostname = az staticwebapp show --name $swaName --resource-group $rgName --query "defaultHostname" -o tsv
$swaUrl = "https://$swaHostname"
Write-OK "URL: $swaUrl"

# ── 5. Entra ID Authentication ──────────────────────────────────────────────

$entraClientId = ""
$entraSecret = ""

if (-not $SkipAuth) {
    Write-Step "5/8  Configuring Entra ID authentication..."

    $existingAuth = az ad app list --display-name $authAppName --query "[0].appId" -o tsv 2>$null
    if ($existingAuth) {
        $entraClientId = $existingAuth
        # Update redirect URI in case SWA hostname changed
        az ad app update --id $entraClientId `
            --web-redirect-uris "$swaUrl/.auth/login/entra/callback" 2>$null
        Write-Host "  Using existing auth app: $entraClientId"
    } else {
        $authApp = az ad app create `
            --display-name $authAppName `
            --sign-in-audience AzureADMyOrg `
            --web-redirect-uris "$swaUrl/.auth/login/entra/callback" `
            -o json | ConvertFrom-Json
        $entraClientId = $authApp.appId
    }

    # Some tenants block password credentials via policy.
    $entraSecret = $null
    try {
        $authCredResult = az ad app credential reset --id $entraClientId --append `
            --display-name "swa-auth" --years 1 -o json 2>&1
        if ($LASTEXITCODE -eq 0) {
            $authCred = $authCredResult | ConvertFrom-Json
            $entraSecret = $authCred.password
        } else {
            throw "Password credential blocked"
        }
    } catch {
        Write-Warn "Password credential blocked by policy for auth app."
        Write-Warn "You will need to manually create a certificate or federated credential"
        Write-Warn "for the auth app '$authAppName' in the Azure portal."
        $entraSecret = "REPLACE_WITH_MANUAL_SECRET"
    }
    Write-OK "Entra auth app ready: $entraClientId"
} else {
    Write-Step "5/8  Skipping Entra ID authentication (--SkipAuth)."
    Write-Warn "The app will be accessible to anyone with the URL."
}

# ── 6. Generate staticwebapp.config.json ─────────────────────────────────────

Write-Step "6/8  Generating staticwebapp.config.json..."

if (-not $SkipAuth) {
    # Route order matters! SWA evaluates routes top-to-bottom.
    #
    # KEY FIX: The /.auth/* route MUST appear before the /* catch-all.
    # Without it, unauthenticated requests to /.auth/login/entra are caught
    # by the /* rule (which requires "authenticated"), triggering a 401,
    # which redirects back to /.auth/login/entra — causing an infinite loop.
    $swaConfig = @{
        auth = @{
            identityProviders = @{
                customOpenIdConnectProviders = @{
                    entra = @{
                        registration = @{
                            clientIdSettingName = "ENTRA_CLIENT_ID"
                            clientCredential = @{ clientSecretSettingName = "ENTRA_CLIENT_SECRET" }
                            openIdConnectConfiguration = @{
                                wellKnownOpenIdConfiguration = "https://login.microsoftonline.com/$tenantId/v2.0/.well-known/openid-configuration"
                            }
                        }
                        login = @{
                            nameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
                            scopes = @("openid", "profile", "email")
                        }
                    }
                }
            }
        }
        routes = @(
            @{ route = "/.auth/login/github";  statusCode = 404 }
            @{ route = "/.auth/login/twitter"; statusCode = 404 }
            @{ route = "/.auth/login/aad";     statusCode = 404 }
            @{ route = "/.auth/*"; allowedRoles = @("anonymous", "authenticated") }
            @{ route = "/*";       allowedRoles = @("authenticated") }
        )
        responseOverrides = @{
            "401" = @{ redirect = "/.auth/login/entra"; statusCode = 302 }
        }
        navigationFallback = @{ rewrite = "/index.html"; exclude = @("/api/*") }
        platform = @{ apiRuntime = "node:18" }
    }
} else {
    $swaConfig = @{
        navigationFallback = @{ rewrite = "/index.html"; exclude = @("/api/*") }
        platform = @{ apiRuntime = "node:18" }
    }
}

$swaConfig | ConvertTo-Json -Depth 10 | Set-Content "$scriptDir\app\staticwebapp.config.json" -Encoding UTF8
Write-OK "Config written to app/staticwebapp.config.json"

# ── 7. App Settings + API Dependencies ──────────────────────────────────────

Write-Step "7/8  Configuring app settings and installing dependencies..."

$settings = @(
    "AZURE_TENANT_ID=$tenantId",
    "AZURE_CLIENT_ID=$apiAppId",
    "AZURE_CLIENT_CERTIFICATE=$apiCertB64",
    "TABLE_STORAGE_URL=$storageUrl"
)
if (-not $SkipAuth) {
    $settings += "ENTRA_CLIENT_ID=$entraClientId"
    if ($entraSecret -and $entraSecret -ne "REPLACE_WITH_MANUAL_SECRET") {
        $settings += "ENTRA_CLIENT_SECRET=$entraSecret"
    } else {
        Write-Warn "ENTRA_CLIENT_SECRET not set — add it manually in Azure portal."
    }
}

az staticwebapp appsettings set `
    --name $swaName `
    --resource-group $rgName `
    --setting-names @settings `
    -o none
Write-OK "App settings configured."

Push-Location "$scriptDir\api"
npm install --production 2>&1 | Out-Null
Pop-Location
Write-OK "API dependencies installed."

# ── 8. Deploy ───────────────────────────────────────────────────────────────

Write-Step "8/8  Deploying application..."

$deployToken = az staticwebapp secrets list `
    --name $swaName `
    --resource-group $rgName `
    --query "properties.apiKey" -o tsv

# Locate StaticSitesClient.exe (downloaded by SWA CLI)
$swaCliDir = "$env:USERPROFILE\.swa\deploy"
$sscExe = $null
if (Test-Path $swaCliDir) {
    $sscExe = Get-ChildItem $swaCliDir -Filter "StaticSitesClient.exe" -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}

# If not found, install SWA CLI to get the deployment binary
if (-not $sscExe) {
    Write-Host "  Installing SWA CLI..."
    npm install -g @azure/static-web-apps-cli 2>&1 | Out-Null
    swa --version 2>$null | Out-Null
    Start-Sleep -Seconds 3
    if (Test-Path $swaCliDir) {
        $sscExe = Get-ChildItem $swaCliDir -Filter "StaticSitesClient.exe" -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
    }
}

$env:FUNCTION_LANGUAGE = "node"
$env:FUNCTION_LANGUAGE_VERSION = "18"

if ($sscExe) {
    Write-Host "  Using StaticSitesClient for deployment..."
    & $sscExe upload `
        --app "$scriptDir\app" `
        --api "$scriptDir\api" `
        --apiToken $deployToken `
        --skipAppBuild true `
        --skipApiBuild true 2>&1 | ForEach-Object {
            if ($_ -match "Status: Succeeded") { Write-OK $_ }
            elseif ($_ -match "Status:")        { Write-Host "  $_" }
            elseif ($_ -match "Visit your site") { Write-OK $_ }
        }
} elseif (Get-Command "swa" -ErrorAction SilentlyContinue) {
    Write-Host "  Using SWA CLI for deployment..."
    swa deploy "$scriptDir\app" `
        --api-location "$scriptDir\api" `
        --deployment-token $deployToken 2>&1 | ForEach-Object {
            if ($_ -match "Project deployed") { Write-OK $_ }
            else { Write-Host "  $_" }
        }
} else {
    Write-Err "No deployment tool found (StaticSitesClient or SWA CLI)."
    Write-Err "Install the SWA CLI manually:  npm install -g @azure/static-web-apps-cli"
    exit 1
}

# ── Done ─────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                  Deployment Complete!                   ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  🌐 App URL:        $swaUrl"       -ForegroundColor White
Write-Host "  📦 Resource Group: $rgName"        -ForegroundColor White
Write-Host "  📊 Storage:        $storageName"   -ForegroundColor White
Write-Host "  🔑 API SP:         $apiAppName"    -ForegroundColor White
if (-not $SkipAuth) {
    Write-Host "  🔒 Auth:          Entra ID single-tenant ($tenantId)" -ForegroundColor White
}
Write-Host ""
Write-Host "  To tear down all resources:" -ForegroundColor DarkGray
Write-Host "    ./deploy.ps1 -Prefix $Prefix -Teardown" -ForegroundColor DarkGray
Write-Host ""
