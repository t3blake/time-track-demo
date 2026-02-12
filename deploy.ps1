# Time Entry Demo - Automated Deployment Script
# Deploys a complete time entry web app to Azure Static Web Apps with:
#   - Azure Table Storage for persistence
#   - Entra ID (single-tenant) authentication
#   - Azure Functions API backend
#
# Prerequisites:
#   - Azure CLI (az) installed and logged in
#   - Node.js 18+ installed
#   - PowerShell 7+
#
# Usage:
#   ./deploy.ps1                          # Interactive - prompts for everything
#   ./deploy.ps1 -Location westus2        # Override region
#   ./deploy.ps1 -Prefix myteam          # Custom resource prefix
#   ./deploy.ps1 -SkipAuth               # Skip Entra ID setup (leave app open)

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

function Assert-Tool($cmd, $name) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Err "$name is required but not found. Please install it first."
        exit 1
    }
}

# ── Pre-flight checks ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          Time Entry Demo - Deployment Script            ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Assert-Tool "az" "Azure CLI"
Assert-Tool "node" "Node.js"
Assert-Tool "npm" "npm"

# Verify logged in
Write-Step "Checking Azure CLI login..."
$account = az account show --query "{name:name, id:id, tenantId:tenantId}" -o json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Warn "Not logged in. Opening browser for login..."
    az login | Out-Null
    $account = az account show --query "{name:name, id:id, tenantId:tenantId}" -o json | ConvertFrom-Json
}
Write-OK "Logged in to: $($account.name)"
Write-OK "Subscription: $($account.id)"
Write-OK "Tenant ID:    $($account.tenantId)"
$tenantId = $account.tenantId

# ── Resource names ───────────────────────────────────────────────────────────
$rgName       = "rg-$Prefix-demo"
$swaName      = "$Prefix-demo"
$storageName  = ($Prefix -replace '[^a-z0-9]','') + "store"
# Storage account names must be 3-24 chars, lowercase alphanumeric only
if ($storageName.Length -gt 24) { $storageName = $storageName.Substring(0, 24) }
$authAppName  = "$Prefix-swa-auth"
$apiAppName   = "$Prefix-table-api"

Write-Step "Resource plan:"
Write-Host "  Resource Group:   $rgName"
Write-Host "  Static Web App:   $swaName"
Write-Host "  Storage Account:  $storageName"
Write-Host "  Location:         $Location"
if (-not $SkipAuth) { Write-Host "  Auth App:         $authAppName (single-tenant)" }
Write-Host ""

# ── Teardown mode ────────────────────────────────────────────────────────────
if ($Teardown) {
    Write-Step "Tearing down all resources..."
    Write-Warn "This will delete resource group '$rgName' and all its contents."
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -ne 'yes') { Write-Host "Aborted."; exit 0 }

    # Delete Entra app registrations
    $apps = az ad app list --display-name $authAppName --query "[].appId" -o tsv 2>$null
    foreach ($appId in $apps) {
        Write-Host "  Deleting app registration $appId..."
        az ad app delete --id $appId 2>$null
    }
    $apps = az ad app list --display-name $apiAppName --query "[].appId" -o tsv 2>$null
    foreach ($appId in $apps) {
        Write-Host "  Deleting app registration $appId..."
        az ad app delete --id $appId 2>$null
    }

    az group delete --name $rgName --yes --no-wait 2>$null
    Write-OK "Teardown initiated. Resources will be deleted in the background."
    exit 0
}

# ── 1. Resource Group ────────────────────────────────────────────────────────
Write-Step "Creating resource group '$rgName' in $Location..."
az group create --name $rgName --location $Location -o none
Write-OK "Resource group ready."

# ── 2. Storage Account ───────────────────────────────────────────────────────
Write-Step "Creating storage account '$storageName'..."
az storage account create `
    --name $storageName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard_LRS `
    --min-tls-version TLS1_2 `
    -o none
Write-OK "Storage account created."

$storageUrl = "https://$storageName.table.core.windows.net"

# Create TimeEntries table via ARM (data-plane createTable requires higher permissions)
$subId = $account.id
az rest --method PUT `
    --url "/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$storageName/tableServices/default/tables/TimeEntries?api-version=2023-01-01" `
    --body '{}' -o none 2>$null
Write-OK "TimeEntries table ensured."

# ── 3. Service principal for Table Storage access ────────────────────────────
Write-Step "Creating service principal '$apiAppName' for Table Storage..."
$apiApp = az ad app create --display-name $apiAppName -o json | ConvertFrom-Json
$apiAppId = $apiApp.appId

# Ensure service principal exists
az ad sp create --id $apiAppId 2>$null
$spObjectId = az ad sp show --id $apiAppId --query id -o tsv

# Create client secret
$apiCred = az ad app credential reset --id $apiAppId --append --display-name "deploy" --years 1 -o json | ConvertFrom-Json
$apiSecret = $apiCred.password

# Assign Storage Table Data Contributor role
$storageId = az storage account show --name $storageName --resource-group $rgName --query id -o tsv
az role assignment create `
    --assignee-object-id $spObjectId `
    --assignee-principal-type ServicePrincipal `
    --role "Storage Table Data Contributor" `
    --scope $storageId `
    -o none
Write-OK "Service principal created and role assigned."

# ── 4. Static Web App ───────────────────────────────────────────────────────
Write-Step "Creating Static Web App '$swaName'..."
az staticwebapp create --name $swaName --resource-group $rgName --location $Location -o none 2>$null
Write-OK "Static Web App created."

$swaHostname = az staticwebapp show --name $swaName --resource-group $rgName --query "defaultHostname" -o tsv
$swaUrl = "https://$swaHostname"
Write-OK "URL: $swaUrl"

# ── 5. Entra ID Authentication (optional) ───────────────────────────────────
$entraClientId = ""
$entraSecret = ""

if (-not $SkipAuth) {
    Write-Step "Creating single-tenant Entra ID app '$authAppName'..."
    $authApp = az ad app create `
        --display-name $authAppName `
        --sign-in-audience AzureADMyOrg `
        --web-redirect-uris "$swaUrl/.auth/login/entra/callback" `
        -o json | ConvertFrom-Json
    $entraClientId = $authApp.appId

    $authCred = az ad app credential reset --id $entraClientId --append --display-name "swa-auth" --years 1 -o json | ConvertFrom-Json
    $entraSecret = $authCred.password
    Write-OK "Auth app created: $entraClientId"
}

# ── 6. Generate staticwebapp.config.json ─────────────────────────────────────
Write-Step "Generating staticwebapp.config.json..."
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $SkipAuth) {
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
            @{ route = "/.auth/login/github"; statusCode = 404 }
            @{ route = "/.auth/login/twitter"; statusCode = 404 }
            @{ route = "/.auth/login/aad"; statusCode = 404 }
            @{ route = "/.auth/*"; allowedRoles = @("anonymous", "authenticated") }
            @{ route = "/*"; allowedRoles = @("authenticated") }
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
Write-OK "Config generated."

# ── 7. Install API dependencies ──────────────────────────────────────────────
Write-Step "Installing API dependencies..."
Push-Location "$scriptDir\api"
npm install --production 2>&1 | Out-Null
Pop-Location
Write-OK "Dependencies installed."

# ── 8. Set app settings ─────────────────────────────────────────────────────
Write-Step "Configuring app settings..."
$settings = @(
    "AZURE_TENANT_ID=$tenantId",
    "AZURE_CLIENT_ID=$apiAppId",
    "AZURE_CLIENT_SECRET=$apiSecret",
    "TABLE_STORAGE_URL=$storageUrl"
)
if (-not $SkipAuth) {
    $settings += "ENTRA_CLIENT_ID=$entraClientId"
    $settings += "ENTRA_CLIENT_SECRET=$entraSecret"
}

az staticwebapp appsettings set `
    --name $swaName `
    --resource-group $rgName `
    --setting-names @settings `
    -o none
Write-OK "App settings configured."

# ── 9. Deploy ───────────────────────────────────────────────────────────────
Write-Step "Deploying application..."
$deployToken = az staticwebapp secrets list --name $swaName --resource-group $rgName --query "properties.apiKey" -o tsv

# Get or download StaticSitesClient
$swaCliDir = "$env:USERPROFILE\.swa\deploy"
$sscExe = $null
if (Test-Path $swaCliDir) {
    $sscExe = Get-ChildItem $swaCliDir -Filter "StaticSitesClient.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
}

if (-not $sscExe) {
    Write-Host "  Installing SWA CLI to get deployment client..."
    npm install -g @azure/static-web-apps-cli 2>&1 | Out-Null
    # Trigger SWA CLI to download StaticSitesClient
    $env:SWA_CLI_DEPLOY_BINARY = "true"
    swa --version 2>$null | Out-Null
    swa deploy --print-token 2>$null | Out-Null
    Start-Sleep -Seconds 2
    $sscExe = Get-ChildItem $swaCliDir -Filter "StaticSitesClient.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
}

if (-not $sscExe) {
    Write-Err "Could not find StaticSitesClient.exe. Trying SWA CLI deploy instead..."
    $env:FUNCTION_LANGUAGE = "node"
    $env:FUNCTION_LANGUAGE_VERSION = "18"
    swa deploy "$scriptDir\app" --api-location "$scriptDir\api" --deployment-token $deployToken 2>&1
} else {
    $env:FUNCTION_LANGUAGE = "node"
    $env:FUNCTION_LANGUAGE_VERSION = "18"
    & $sscExe upload `
        --app "$scriptDir\app" `
        --api "$scriptDir\api" `
        --apiToken $deployToken `
        --skipAppBuild true `
        --skipApiBuild true 2>&1 | ForEach-Object {
            if ($_ -match "Status: Succeeded") { Write-OK $_ }
            elseif ($_ -match "Status:") { Write-Host "  $_" }
            elseif ($_ -match "Visit your site") { Write-OK $_ }
        }
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                  Deployment Complete!                    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  🌐 App URL:        $swaUrl" -ForegroundColor White
Write-Host "  📦 Resource Group: $rgName" -ForegroundColor White
Write-Host "  📊 Storage:        $storageName" -ForegroundColor White
if (-not $SkipAuth) {
    Write-Host "  🔒 Auth:          Single-tenant ($tenantId)" -ForegroundColor White
}
Write-Host ""
Write-Host "  To tear down all resources:" -ForegroundColor DarkGray
Write-Host "    ./deploy.ps1 -Prefix $Prefix -Teardown" -ForegroundColor DarkGray
Write-Host ""
