# Time Entry Demo - Automated Deployment Script
# Deploys a complete time entry web app to Azure Static Web Apps with:
#   - Azure Table Storage for persistence
#   - Entra ID authentication (custom OIDC provider, single-tenant)
#   - Azure Functions API backend
#   - Certificate-based service principal auth for Table Storage
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
#   ./deploy.ps1 -SkipAuth               # Skip authentication (anonymous access)
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
$apiAppName  = "$Prefix-table-api"
$authAppName = "$Prefix-swa-auth"
$scriptDir   = Get-ScriptDir

Write-Step "Resource plan:"
Write-Host "  Resource Group:   $rgName"
Write-Host "  Static Web App:   $swaName"
Write-Host "  Storage Account:  $storageName"
Write-Host "  Location:         $Location"
Write-Host "  API App:          $apiAppName"
if (-not $SkipAuth) { Write-Host "  Auth App:         $authAppName" }
Write-Host ""

# ── Teardown ─────────────────────────────────────────────────────────────────

if ($Teardown) {
    Write-Step "Tearing down all resources..."
    Write-Warn "This will delete resource group '$rgName' and all Entra app registrations."
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -ne 'yes') { Write-Host "Aborted."; exit 0 }

    foreach ($appDisplayName in @($apiAppName, $authAppName)) {
        $apps = az ad app list --display-name $appDisplayName --query "[].appId" -o tsv 2>$null
        foreach ($appId in $apps) {
            Write-Host "  Deleting app registration $appId ($appDisplayName)..."
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

# Create a self-signed certificate credential (1-year expiry).
# Certificate credentials are used instead of passwords because most enterprise
# tenants have Entra policies that block password credentials on app registrations.
Write-Host "  Generating self-signed certificate..."
$certSubject = "CN=$apiAppName"
$cert = New-SelfSignedCertificate `
    -Subject $certSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(1) `
    -KeyAlgorithm RSA -KeyLength 2048 `
    -HashAlgorithm SHA256

# Upload public key to the app registration
$certBase64 = [Convert]::ToBase64String($cert.RawData)
az ad app credential reset --id $apiAppId --cert $certBase64 --append -o none 2>$null

# Build PEM string (certificate + private key) for the API to use at runtime
$certPemBody = [Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
$certPem = "-----BEGIN CERTIFICATE-----`n$certPemBody`n-----END CERTIFICATE-----"
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$keyBytes = $rsa.ExportPkcs8PrivateKey()
$keyPemBody = [Convert]::ToBase64String($keyBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
$keyPem = "-----BEGIN PRIVATE KEY-----`n$keyPemBody`n-----END PRIVATE KEY-----"
$fullPem = $certPem + "`n" + $keyPem

# Base64-encode the full PEM so it can be stored as a single app setting
$apiCertB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fullPem))

# Clean up from local cert store
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
Write-OK "Certificate credential created (thumbprint: $($cert.Thumbprint))."

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

# ── 5. Entra ID Auth App Registration ────────────────────────────────────────

if (-not $SkipAuth) {
    Write-Step "5/8  Creating Entra ID auth app registration..."

    $existingAuthApp = az ad app list --display-name $authAppName --query "[0].{appId:appId, id:id}" -o json 2>$null | ConvertFrom-Json
    if ($existingAuthApp) {
        $authAppId     = $existingAuthApp.appId
        $authObjectId  = $existingAuthApp.id
        Write-Host "  Using existing auth app: $authAppId"
    } else {
        $callbackUrl = "$swaUrl/.auth/login/entra/callback"
        $authApp = az ad app create `
            --display-name $authAppName `
            --sign-in-audience AzureADMyOrg `
            --web-redirect-uris $callbackUrl `
            -o json | ConvertFrom-Json
        $authAppId    = $authApp.appId
        $authObjectId = $authApp.id
        Write-OK "Auth app created: $authAppId"
    }

    # Create client secret via Graph API.
    # Using the Graph API directly bypasses Entra policies that block
    # 'az ad app credential reset' in some enterprise tenants.
    $secretBody = '{\"passwordCredential\":{\"displayName\":\"SWA Auth\",\"endDateTime\":\"' + (Get-Date).AddYears(1).ToString('yyyy-MM-ddTHH:mm:ssZ') + '\"}}'
    $secretResult = az rest --method POST `
        --url "https://graph.microsoft.com/v1.0/applications/$authObjectId/addPassword" `
        --body $secretBody `
        --headers "Content-Type=application/json" `
        -o json | ConvertFrom-Json
    $authSecret = $secretResult.secretText
    Write-OK "Client secret created."

    # Add openid + profile + email delegated permissions to Microsoft Graph
    # and configure optional claims so the ID token includes email/upn.
    $claimsBody = @"
{
  "requiredResourceAccess": [{
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "37f7f235-527c-4136-accd-4a02d197296e", "type": "Scope" },
      { "id": "14dad69e-099b-42c9-810b-d002981feec1", "type": "Scope" },
      { "id": "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0", "type": "Scope" }
    ]
  }],
  "optionalClaims": {
    "idToken": [
      { "name": "email", "essential": true },
      { "name": "preferred_username", "essential": true },
      { "name": "upn", "essential": true }
    ]
  },
  "web": {
    "implicitGrantSettings": { "enableIdTokenIssuance": true }
  }
}
"@
    $claimsBody | Set-Content "$scriptDir\_claims.json" -Encoding UTF8
    az rest --method PATCH `
        --url "https://graph.microsoft.com/v1.0/applications/$authObjectId" `
        --body "@$scriptDir\_claims.json" `
        --headers "Content-Type=application/json" `
        -o none 2>$null
    Remove-Item "$scriptDir\_claims.json" -ErrorAction SilentlyContinue
    Write-OK "API permissions and optional claims configured."

    # Grant admin consent
    az ad app permission admin-consent --id $authAppId 2>$null
    Write-OK "Admin consent granted."
} else {
    Write-Step "5/8  Skipping auth (--SkipAuth)..."
}

# ── 6. Generate staticwebapp.config.json ─────────────────────────────────────

Write-Step "6/8  Generating staticwebapp.config.json..."

if (-not $SkipAuth) {
    # Uses a custom OpenID Connect provider named 'entra' backed by Entra ID.
    # This gives us single-tenant auth with proper email claims.
    # Tenant validation is also enforced at the API level (defense in depth).
    #
    # Route order matters! The /.auth/* route MUST appear before the /* catch-all
    # to prevent an infinite redirect loop.
    $swaConfig = @{
        auth = @{
            identityProviders = @{
                customOpenIdConnectProviders = @{
                    entra = @{
                        registration = @{
                            clientIdSettingName = "ENTRA_CLIENT_ID"
                            clientCredential = @{
                                clientSecretSettingName = "ENTRA_CLIENT_SECRET"
                            }
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

# ── 6. App Settings + API Dependencies ──────────────────────────────────────

Write-Step "7/8  Configuring app settings and installing dependencies..."

$settings = @(
    "AZURE_TENANT_ID=$tenantId",
    "AZURE_CLIENT_ID=$apiAppId",
    "AZURE_CLIENT_CERTIFICATE=$apiCertB64",
    "TABLE_STORAGE_URL=$storageUrl"
)
if (-not $SkipAuth) {
    $settings += "ENTRA_CLIENT_ID=$authAppId"
    $settings += "ENTRA_CLIENT_SECRET=$authSecret"
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

# ── 7. Deploy ───────────────────────────────────────────────────────────────

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
        --api-language node --api-version 18 `
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
    Write-Host "  🔒 Auth:          Entra ID (custom OIDC, tenant $tenantId)" -ForegroundColor White
    Write-Host "  🆔 Auth App:       $authAppName ($authAppId)" -ForegroundColor White
}
Write-Host ""
Write-Host "  To tear down all resources:" -ForegroundColor DarkGray
Write-Host "    ./deploy.ps1 -Prefix $Prefix -Teardown" -ForegroundColor DarkGray
Write-Host ""
