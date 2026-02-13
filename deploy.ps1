# Time Entry Demo - Automated Deployment Script
# Deploys a complete time entry web app to Azure Static Web Apps with:
#   - Azure Table Storage for persistence (private endpoint, no public access)
#   - Entra ID authentication (built-in AAD provider, single-tenant)
#   - Linked Azure Functions API (Flex Consumption, VNet-integrated)
#   - Certificate-based service principal auth for Table Storage
#
# Network architecture:
#   SWA → Linked Backend → Functions App → VNet → Private Endpoint → Storage
#   Storage has public network access DISABLED. The Functions app reaches it
#   through VNet integration and a private endpoint + private DNS zone.
#
# Prerequisites:
#   - Windows 10/11 (uses New-SelfSignedCertificate and the Windows cert store)
#   - Azure CLI (az) installed and logged in
#   - Node.js 18+ installed
#   - PowerShell 7+
#
# Usage:
#   ./deploy.ps1                          # Deploy (prompts for prefix)
#   ./deploy.ps1 -Prefix jsmith            # Deploy with a specific prefix
#   ./deploy.ps1 -Location westus2        # Override region
#   ./deploy.ps1 -SkipAuth               # Skip authentication (anonymous access)
#   ./deploy.ps1 -Teardown               # Remove all resources

param(
    [string]$Prefix,
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

function Assert-Tool($cmd, $name, $wingetId) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        if ($wingetId -and (Get-Command "winget" -ErrorAction SilentlyContinue)) {
            Write-Warn "$name not found. Installing via winget..."
            winget install --id $wingetId --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
            # Refresh PATH so the current session can find the newly installed tool
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath    = [Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path    = "$machinePath;$userPath"
            if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
                Write-Err "$name was installed but is still not found in PATH."
                Write-Err "Close and reopen PowerShell, then re-run this script."
                exit 1
            }
            Write-OK "$name installed successfully."
        } else {
            Write-Err "$name is required but not found."
            if ($wingetId) { Write-Host "    Install: winget install --id $wingetId" -ForegroundColor DarkGray }
            exit 1
        }
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

# ── Prompt for prefix if not provided ────────────────────────────────────────

if (-not $Prefix) {
    $defaultPrefix = ($env:USERNAME -replace '[^a-zA-Z0-9]','').ToLower()
    if ($defaultPrefix.Length -gt 12) { $defaultPrefix = $defaultPrefix.Substring(0, 12) }
    Write-Host ""
    Write-Host "  Each deployment needs a unique prefix for Azure resource names." -ForegroundColor White
    Write-Host "  Use your alias, team name, or initials (lowercase, letters/numbers only)." -ForegroundColor DarkGray
    Write-Host ""
    $prefixInput = Read-Host "  Prefix [$defaultPrefix]"
    $Prefix = if ($prefixInput) { $prefixInput.Trim().ToLower() } else { $defaultPrefix }
    if (-not ($Prefix -match '^[a-z][a-z0-9]{1,11}$')) {
        Write-Err "Prefix must be 2-12 lowercase letters/numbers, starting with a letter."
        exit 1
    }
    Write-OK "Using prefix: $Prefix"
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

Assert-Tool "az"   "Azure CLI"   "Microsoft.AzureCLI"
Assert-Tool "node" "Node.js"     "OpenJS.NodeJS.LTS"
Assert-Tool "npm"  "npm"         $null  # included with Node.js

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
$storageName = (($Prefix -replace '[^a-z0-9]','') + "demostore").ToLower()
if ($storageName.Length -gt 24) { $storageName = $storageName.Substring(0, 24) }
$apiAppName  = "$Prefix-table-api"
$authAppName = "$Prefix-swa-auth"
$funcAppName = "$Prefix-demo-api"
$vnetName    = "$Prefix-demo-vnet"
$scriptDir   = Get-ScriptDir

Write-Step "Resource plan:"
Write-Host "  Resource Group:   $rgName"
Write-Host "  Static Web App:   $swaName"
Write-Host "  Functions App:    $funcAppName  (Flex Consumption)"
Write-Host "  Storage Account:  $storageName  (private endpoint)"
Write-Host "  Virtual Network:  $vnetName"
Write-Host "  Location:         $Location"
Write-Host "  API SP:           $apiAppName"
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

Write-Step "1/9  Creating resource group..."
az group create --name $rgName --location $Location -o none
Write-OK "Resource group '$rgName' ready."

# ── 2. Virtual Network ──────────────────────────────────────────────────────

Write-Step "2/9  Creating virtual network and subnets..."

# Pre-register the Microsoft.App resource provider (required for Flex Consumption
# Functions). We do this early so it has time to complete before Step 5.
Write-Host "  Registering Microsoft.App resource provider (if needed)..."
$rpState = az provider show --namespace Microsoft.App --query registrationState -o tsv 2>$null
if ($rpState -ne 'Registered') {
    az provider register --namespace Microsoft.App -o none 2>$null
    $attempt = 0
    do {
        Start-Sleep 10
        $rpState = az provider show --namespace Microsoft.App --query registrationState -o tsv 2>$null
        $attempt++
        if ($attempt % 6 -eq 0) { Write-Host "    Still waiting for Microsoft.App registration ($rpState)..." }
    } while ($rpState -ne 'Registered' -and $attempt -lt 60)
    if ($rpState -ne 'Registered') {
        Write-Err "Microsoft.App provider did not register after 10 minutes. State: $rpState"
        exit 1
    }
}
Write-OK "Microsoft.App provider registered."

az network vnet create `
    --name $vnetName `
    --resource-group $rgName `
    --location $Location `
    --address-prefix "10.0.0.0/16" `
    -o none 2>$null

# Subnet for Functions VNet integration (delegated to Microsoft.App/environments
# because Flex Consumption runs on Container Apps infrastructure).
az network vnet subnet create `
    --name "func-integration" `
    --resource-group $rgName `
    --vnet-name $vnetName `
    --address-prefix "10.0.0.0/24" `
    --delegations "Microsoft.App/environments" `
    -o none 2>$null

# Subnet for private endpoints (no delegation needed)
az network vnet subnet create `
    --name "private-endpoints" `
    --resource-group $rgName `
    --vnet-name $vnetName `
    --address-prefix "10.0.1.0/24" `
    -o none 2>$null

Write-OK "VNet '$vnetName' ready with func-integration and private-endpoints subnets."

# ── 3. Storage Account + Private Endpoints + Table ───────────────────────────

Write-Step "3/9  Creating storage account with private endpoints..."

az storage account create `
    --name $storageName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard_LRS `
    --min-tls-version TLS1_2 `
    --allow-blob-public-access false `
    -o none
Write-OK "Storage account '$storageName' created."

$storageId = az storage account show --name $storageName --resource-group $rgName --query id -o tsv

# Private endpoints for blob (Functions deployment storage) and table (app data)
$peSubnetId = az network vnet subnet show `
    --name "private-endpoints" `
    --resource-group $rgName `
    --vnet-name $vnetName `
    --query id -o tsv

foreach ($subResource in @("blob", "table", "queue")) {
    $peName = "$storageName-$subResource-pe"
    Write-Host "  Creating private endpoint: $peName ($subResource)..."
    az network private-endpoint create `
        --name $peName `
        --resource-group $rgName `
        --location $Location `
        --vnet-name $vnetName `
        --subnet "private-endpoints" `
        --private-connection-resource-id $storageId `
        --group-id $subResource `
        --connection-name "$storageName-$subResource" `
        -o none 2>$null

    # Private DNS zone for this sub-resource
    $dnsZone = "privatelink.$subResource.core.windows.net"
    az network private-dns zone create `
        --name $dnsZone `
        --resource-group $rgName `
        -o none 2>$null

    # Link DNS zone to our VNet so VNet-integrated apps resolve private IPs
    az network private-dns zone vnet-link create `
        --name "$vnetName-$subResource-link" `
        --resource-group $rgName `
        --zone-name $dnsZone `
        --virtual-network $vnetName `
        --registration-enabled false `
        -o none 2>$null

    # Create DNS records for the private endpoint
    az network private-endpoint dns-zone-group create `
        --name "$subResource-dns-group" `
        --resource-group $rgName `
        --endpoint-name $peName `
        --private-dns-zone $dnsZone `
        --zone-name $subResource `
        -o none 2>$null
}
Write-OK "Private endpoints and DNS zones configured (blob, table, queue)."

# Ensure public network access is disabled (enterprise policy should enforce
# this, but we set it explicitly for correctness).
az storage account update `
    --name $storageName `
    --resource-group $rgName `
    --public-network-access Disabled `
    -o none 2>$null

# Create the TimeEntries table via ARM management plane.
# ARM operations use the management endpoint (management.azure.com), not the
# storage data plane, so they work regardless of network restrictions.
az rest --method PUT `
    --url "/subscriptions/$subId/resourceGroups/$rgName/providers/Microsoft.Storage/storageAccounts/$storageName/tableServices/default/tables/TimeEntries?api-version=2023-01-01" `
    --body '{}' -o none 2>$null
Write-OK "TimeEntries table created."

# ── 4. Service Principal for Table Storage ───────────────────────────────────

Write-Step "4/9  Creating service principal for Table Storage access..."

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
az role assignment create `
    --assignee-object-id $spObjectId `
    --assignee-principal-type ServicePrincipal `
    --role "Storage Table Data Contributor" `
    --scope $storageId `
    -o none 2>$null
Write-OK "Service principal '$apiAppName' ready with Storage Table Data Contributor role."

# ── 5. Azure Functions App (Flex Consumption) ────────────────────────────────

Write-Step "5/9  Creating Functions app (Flex Consumption with VNet integration)..."

$storageUrl = "https://$storageName.table.core.windows.net"
$funcSubnetId = az network vnet subnet show `
    --name "func-integration" `
    --resource-group $rgName `
    --vnet-name $vnetName `
    --query id -o tsv

# Create the Flex Consumption function app with VNet integration from the start.
# WEBSITE_CONTENTOVERVNET routes deployment storage traffic through the VNet,
# which is required because the storage account has public access disabled.
# Both --vnet and --subnet are required for Flex Consumption networking.
$vnetId = az network vnet show `
    --name $vnetName `
    --resource-group $rgName `
    --query id -o tsv

az functionapp create `
    --name $funcAppName `
    --resource-group $rgName `
    --storage-account $storageName `
    --flexconsumption-location $Location `
    --runtime node `
    --runtime-version 20 `
    --functions-version 4 `
    --vnet $vnetId `
    --subnet $funcSubnetId `
    -o none 2>&1 | ForEach-Object { Write-Host "    $_" }

if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to create Functions app. See output above."
    exit 1
}

# Verify the app was actually created
$funcCheck = az functionapp show --name $funcAppName --resource-group $rgName --query name -o tsv 2>$null
if (-not $funcCheck) {
    Write-Err "Functions app '$funcAppName' was not created. Check that the Microsoft.App provider is registered and VNet/subnet are correct."
    exit 1
}

Write-OK "Functions app '$funcAppName' created with VNet integration."

# Configure app settings for the API
az functionapp config appsettings set `
    --name $funcAppName `
    --resource-group $rgName `
    --settings `
        "WEBSITE_CONTENTOVERVNET=1" `
        "AZURE_TENANT_ID=$tenantId" `
        "AZURE_CLIENT_ID=$apiAppId" `
        "AZURE_CLIENT_CERTIFICATE=$apiCertB64" `
        "TABLE_STORAGE_URL=$storageUrl" `
    -o none
Write-OK "Functions app settings configured."

# Deploy the API code to the Functions app
Write-Host "  Installing API dependencies..."
Push-Location "$scriptDir\api"
npm install --production 2>&1 | Out-Null
Pop-Location

Write-Host "  Packaging and deploying API code..."
$zipPath = "$scriptDir\_api-deploy.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath }
Compress-Archive -Path "$scriptDir\api\*" -DestinationPath $zipPath -Force

az functionapp deployment source config-zip `
    --name $funcAppName `
    --resource-group $rgName `
    --src $zipPath `
    -o none 2>$null

Remove-Item $zipPath -ErrorAction SilentlyContinue
Write-OK "API code deployed to Functions app."

# ── 6. Static Web App ───────────────────────────────────────────────────────

Write-Step "6/9  Creating Static Web App (Standard tier)..."
az staticwebapp create `
    --name $swaName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard `
    -o none 2>$null
Write-OK "Static Web App '$swaName' created (Standard tier)."

# Enable system-assigned managed identity (may be required by org policies)
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

# Link the Functions app as the SWA backend.
# This routes /api/* requests from SWA to the Functions app, forwarding
# the x-ms-client-principal header for auth validation.
Write-Host "  Linking Functions app as backend..."
$funcAppId = az functionapp show --name $funcAppName --resource-group $rgName --query id -o tsv
$swaId = az staticwebapp show --name $swaName --resource-group $rgName --query id -o tsv

az rest --method PUT `
    --url "$swaId/linkedBackends/${funcAppName}?api-version=2022-09-01" `
    --body "{`"properties`":{`"backendResourceId`":`"$funcAppId`",`"region`":`"$Location`"}}" `
    --headers "Content-Type=application/json" `
    -o none 2>$null
Write-OK "Functions app linked as SWA backend."

# ── 7. Entra ID Auth App Registration ────────────────────────────────────────

if (-not $SkipAuth) {
    Write-Step "7/9  Creating Entra ID auth app registration..."

    $aadCallbackUrl = "$swaUrl/.auth/login/aad/callback"

    $existingAuthApp = az ad app list --display-name $authAppName --query "[0].{appId:appId, id:id}" -o json 2>$null | ConvertFrom-Json
    if ($existingAuthApp) {
        $authAppId     = $existingAuthApp.appId
        $authObjectId  = $existingAuthApp.id
        Write-Host "  Using existing auth app: $authAppId"
    } else {
        $authApp = az ad app create `
            --display-name $authAppName `
            --sign-in-audience AzureADMyOrg `
            --web-redirect-uris $aadCallbackUrl `
            -o json | ConvertFrom-Json
        $authAppId    = $authApp.appId
        $authObjectId = $authApp.id
        Write-OK "Auth app created: $authAppId"
    }

    # Ensure redirect URI is set (idempotent — handles re-runs)
    az rest --method PATCH `
        --url "https://graph.microsoft.com/v1.0/applications/$authObjectId" `
        --body "{`"web`":{`"redirectUris`":[`"$aadCallbackUrl`"]}}" `
        --headers "Content-Type=application/json" `
        -o none 2>$null
    Write-OK "Redirect URI configured."

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

    # Ensure auth app has a service principal (required for admin consent)
    az ad sp create --id $authAppId 2>$null | Out-Null

    # Grant admin consent for the delegated permissions (openid, profile, email).
    # This requires Global Admin, Cloud Application Admin, or Application Admin role.
    # If it fails, the app will still work — users will see a one-time consent prompt.
    $consentResult = az ad app permission admin-consent --id $authAppId 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Admin consent granted."
    } else {
        Write-Warn "Could not grant admin consent (you may lack the required Entra role)."
        Write-Warn "Users will be prompted to consent on first login instead."
        Write-Host "  To grant consent later, run:" -ForegroundColor DarkGray
        Write-Host "    az ad app permission admin-consent --id $authAppId" -ForegroundColor DarkGray
    }
} else {
    Write-Step "7/9  Skipping auth (-SkipAuth)..."
}

# ── 8. Generate staticwebapp.config.json + Deploy ────────────────────────────

Write-Step "8/9  Generating staticwebapp.config.json..."

if (-not $SkipAuth) {
    # Route order matters! The /.auth/* route MUST appear before the /* catch-all
    # to prevent an infinite redirect loop.

    # Built-in Microsoft identity provider (azureActiveDirectory).
    # No client secret required — SWA handles token exchange internally.
    $loginRoute = "/.auth/login/aad"
    $swaConfig = @{
        auth = @{
            identityProviders = @{
                azureActiveDirectory = @{
                    registration = @{
                        openIdIssuer = "https://login.microsoftonline.com/$tenantId/v2.0"
                        clientIdSettingName = "AAD_CLIENT_ID"
                    }
                }
            }
        }
        routes = @(
            @{ route = "/.auth/login/github";  statusCode = 404 }
            @{ route = "/.auth/login/twitter"; statusCode = 404 }
            @{ route = "/.auth/*"; allowedRoles = @("anonymous", "authenticated") }
            @{ route = "/*";       allowedRoles = @("authenticated") }
        )
        responseOverrides = @{
            "401" = @{ redirect = $loginRoute; statusCode = 302 }
        }
        navigationFallback = @{ rewrite = "/index.html"; exclude = @("/api/*") }
    }
} else {
    $swaConfig = @{
        navigationFallback = @{ rewrite = "/index.html"; exclude = @("/api/*") }
    }
}

$swaConfig | ConvertTo-Json -Depth 10 | Set-Content "$scriptDir\app\staticwebapp.config.json" -Encoding UTF8
Write-OK "Config written to app/staticwebapp.config.json"

# ── 9. Deploy Static Content + App Settings ──────────────────────────────────

Write-Step "9/9  Deploying static content and configuring app settings..."

# SWA app settings (auth only — storage/API settings are on the Functions app)
if (-not $SkipAuth) {
    az staticwebapp appsettings set `
        --name $swaName `
        --resource-group $rgName `
        --setting-names "AAD_CLIENT_ID=$authAppId" `
        -o none
    Write-OK "SWA auth settings configured."
}

# Deploy static content only (no --api; the API is on the linked Functions app)
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

if ($sscExe) {
    Write-Host "  Using StaticSitesClient for deployment..."
    & $sscExe upload `
        --app "$scriptDir\app" `
        --apiToken $deployToken `
        --skipAppBuild true 2>&1 | ForEach-Object {
            if ($_ -match "Status: Succeeded") { Write-OK $_ }
            elseif ($_ -match "Status:")        { Write-Host "  $_" }
            elseif ($_ -match "Visit your site") { Write-OK $_ }
        }
} elseif (Get-Command "swa" -ErrorAction SilentlyContinue) {
    Write-Host "  Using SWA CLI for deployment..."
    swa deploy "$scriptDir\app" `
        --deployment-token $deployToken 2>&1 | ForEach-Object {
            if ($_ -match "Project deployed") { Write-OK $_ }
            else { Write-Host "  $_" }
        }
} else {
    Write-Err "No deployment tool found (StaticSitesClient or SWA CLI)."
    Write-Err "Install the SWA CLI manually:  npm install -g @azure/static-web-apps-cli"
    exit 1
}

if ($LASTEXITCODE -ne 0) {
    Write-Err "Deployment failed (exit code $LASTEXITCODE). Check the output above for details."
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
Write-Host "  📊 Storage:        $storageName  (private endpoint)" -ForegroundColor White
Write-Host "  🔗 Functions:      $funcAppName  (Flex Consumption + VNet)" -ForegroundColor White
Write-Host "  🔑 API SP:         $apiAppName"    -ForegroundColor White
if (-not $SkipAuth) {
    Write-Host "  🔒 Auth:          Entra ID (built-in AAD, tenant $tenantId)" -ForegroundColor White
    Write-Host "  🆔 Auth App:       $authAppName ($authAppId)" -ForegroundColor White
}
Write-Host ""
Write-Host "  To tear down all resources:" -ForegroundColor DarkGray
Write-Host "    ./deploy.ps1 -Prefix $Prefix -Teardown" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  First time? Wait ~30 seconds for the API to cold-start," -ForegroundColor DarkGray
Write-Host "  then open the URL above in your browser." -ForegroundColor DarkGray
Write-Host ""
