# Time Entry Demo - Automated Deployment Script
# Deploys a complete time entry web app to Azure Static Web Apps with:
#   - Azure Table Storage for persistence (private endpoint, no public access)
#   - Entra ID authentication (built-in AAD provider, single-tenant)
#   - Linked Azure Functions API (Flex Consumption, VNet-integrated)
#   - Managed identity for all storage access (no keys, no passwords)
#
# Network architecture:
#   SWA → Linked Backend → Functions App → VNet → Private Endpoint → Storage
#   Storage has public network access DISABLED and shared-key auth DISABLED.
#   The Functions app reaches storage through VNet integration + private endpoints.
#
# Prerequisites:
#   - Azure CLI (az) installed and logged in
#   - Node.js 18+ installed
#   - PowerShell 7+
#
# Usage:
#   ./deploy.ps1                          # Deploy (prompts for prefix, RG, subnet)
#   ./deploy.ps1 -Prefix jsmith            # Deploy with a specific prefix
#   ./deploy.ps1 -ResourceGroup myRG       # Use an existing resource group
#   ./deploy.ps1 -SubnetId /subscriptions/... # Use an existing Functions subnet
#   ./deploy.ps1 -Location westus2        # Override region
#   ./deploy.ps1 -SkipAuth               # Skip authentication (anonymous access)
#   ./deploy.ps1 -Teardown               # Remove all resources

param(
    [string]$Prefix,
    [string]$Location = "eastus2",
    [string]$ResourceGroup,
    [string]$SubnetId,
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

function Show-NumberedPicker {
    <#
    .SYNOPSIS
        Displays a numbered list and prompts the user to pick one (or a "create new" option).
        Returns the 0-based index of the selection, or -1 for "create new".
    #>
    param(
        [string[]]$Items,
        [string]$Prompt,
        [string]$CreateNewLabel = "Create new"
    )
    Write-Host ""
    for ($i = 0; $i -lt $Items.Count; $i++) {
        Write-Host "    [$($i + 1)]  $($Items[$i])" -ForegroundColor White
    }
    Write-Host "    [N]  $CreateNewLabel" -ForegroundColor DarkGray
    Write-Host ""
    while ($true) {
        $pick = Read-Host $Prompt
        if ($pick -match '^[Nn]$') { return -1 }
        $num = 0
        if ([int]::TryParse($pick, [ref]$num) -and $num -ge 1 -and $num -le $Items.Count) {
            return ($num - 1)
        }
        Write-Warn "Enter a number 1-$($Items.Count) or N for new."
    }
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

$swaName     = "$Prefix-demo"
$storageName = (($Prefix -replace '[^a-z0-9]','') + "demostore").ToLower()
if ($storageName.Length -gt 24) { $storageName = $storageName.Substring(0, 24) }
$authAppName = "$Prefix-swa-auth"
$funcAppName = "$Prefix-demo-api"
$vnetName    = "$Prefix-demo-vnet"
$scriptDir   = Get-ScriptDir

# RG name may be overridden by the picker below; set a default for now
$rgName = if ($ResourceGroup) { $ResourceGroup } else { "rg-$Prefix-demo" }

# ── Teardown ─────────────────────────────────────────────────────────────────

if ($Teardown) {
    Write-Step "Tearing down resources..."

    # Determine if this RG was created by the script (default name pattern) or user-supplied
    $defaultRgName = "rg-$Prefix-demo"
    $isOurRg = ($rgName -eq $defaultRgName) -and (-not $ResourceGroup)

    # ── 1. Always safe: delete Entra app registrations we created ──
    Write-Host ""
    Write-Host "  The following Entra app registrations will be deleted:" -ForegroundColor White
    Write-Host "    - $authAppName (SWA auth app)" -ForegroundColor DarkGray

    if ($isOurRg) {
        Write-Host ""
        Write-Host "  Resource group '$rgName' appears to be script-created (default name)." -ForegroundColor White
        Write-Host "  It will be deleted along with everything inside it." -ForegroundColor White
    } else {
        Write-Host ""
        Write-Warn "Resource group '$rgName' was not created by this script (or was specified with -ResourceGroup)."
        Write-Warn "To avoid breaking other resources, only individual demo resources will be deleted:"
        Write-Host "    - $funcAppName     (Functions app)" -ForegroundColor DarkGray
        Write-Host "    - $swaName         (Static Web App)" -ForegroundColor DarkGray
        Write-Host "    - $storageName     (Storage account)" -ForegroundColor DarkGray
        Write-Host "    - $authAppName     (Auth app registration)" -ForegroundColor DarkGray
        Write-Warn "VNet, subnets, private endpoints, and DNS zones will NOT be deleted."
        Write-Warn "Clean those up manually if no longer needed."
    }

    Write-Host ""
    $confirm = Read-Host "Type 'yes' to confirm"
    if ($confirm -ne 'yes') { Write-Host "Aborted."; exit 0 }

    # Delete app registrations (always safe)
    foreach ($appDisplayName in @($authAppName)) {
        $apps = az ad app list --display-name $appDisplayName --query "[].appId" -o tsv 2>$null
        foreach ($appId in $apps) {
            Write-Host "  Deleting app registration $appId ($appDisplayName)..."
            az ad app delete --id $appId 2>$null
        }
    }
    Write-OK "App registrations deleted."

    if ($isOurRg) {
        # Script-created RG — safe to delete the whole thing
        $rgExists = az group exists --name $rgName -o tsv 2>$null
        if ($rgExists -eq "true") {
            az group delete --name $rgName --yes --no-wait 2>$null
            Write-OK "Resource group '$rgName' deletion initiated (runs in background)."
        } else {
            Write-Warn "Resource group '$rgName' not found — nothing to delete."
        }
    } else {
        # User-owned RG — only delete individual resources we know we created
        $rgExists = az group exists --name $rgName -o tsv 2>$null
        if ($rgExists -eq "true") {
            Write-Host "  Deleting individual demo resources from '$rgName'..."

            # Functions app
            $funcExists = az functionapp show --name $funcAppName --resource-group $rgName --query name -o tsv 2>$null
            if ($funcExists) {
                az functionapp delete --name $funcAppName --resource-group $rgName -o none 2>$null
                Write-OK "Deleted Functions app '$funcAppName'."
            }

            # Static Web App
            $swaExists = az staticwebapp show --name $swaName --resource-group $rgName --query name -o tsv 2>$null
            if ($swaExists) {
                az staticwebapp delete --name $swaName --resource-group $rgName --yes -o none 2>$null
                Write-OK "Deleted Static Web App '$swaName'."
            }

            # Storage account
            $storageExists = az storage account show --name $storageName --resource-group $rgName --query name -o tsv 2>$null
            if ($storageExists) {
                # Delete private endpoints first (they reference the storage account)
                foreach ($subResource in @("blob", "table", "queue")) {
                    $peName = "$storageName-$subResource-pe"
                    $peExists = az network private-endpoint show --name $peName --resource-group $rgName --query name -o tsv 2>$null
                    if ($peExists) {
                        az network private-endpoint delete --name $peName --resource-group $rgName -o none 2>$null
                        Write-OK "Deleted private endpoint '$peName'."
                    }
                }
                az storage account delete --name $storageName --resource-group $rgName --yes -o none 2>$null
                Write-OK "Deleted storage account '$storageName'."
            }

            # Warn about leftovers the user should review
            Write-Host ""
            Write-Warn "The following resources were left in place (review and remove manually if unneeded):"
            Write-Host "    - VNet / subnet(s): may be shared with other workloads" -ForegroundColor DarkGray
            Write-Host "    - Private DNS zones: may be used by other private endpoints" -ForegroundColor DarkGray
            Write-Host "    - Application Insights: az monitor app-insights component delete ..." -ForegroundColor DarkGray
        } else {
            Write-Warn "Resource group '$rgName' not found — nothing to delete."
        }
    }

    Write-OK "Teardown complete."
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
#  DEPLOYMENT
# ═════════════════════════════════════════════════════════════════════════════

# ── 1. Resource Group ────────────────────────────────────────────────────────

Write-Step "1/8  Resource group..."

$usingExistingRg = $false

if (-not $ResourceGroup) {
    # List existing resource groups in the subscription and let the user pick
    $rgList = az group list --query "[?provisioningState=='Succeeded'].name" -o tsv 2>$null
    if ($rgList) {
        $rgArray = @($rgList -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($rgArray.Count -gt 0) {
            Write-Host "  Found $($rgArray.Count) existing resource group(s) in this subscription." -ForegroundColor White
            Write-Host "  Pick one to deploy into, or create a new one." -ForegroundColor DarkGray
            $rgIdx = Show-NumberedPicker -Items $rgArray -Prompt "  Resource group [1-$($rgArray.Count) or N]"
            if ($rgIdx -ge 0) {
                $rgName = $rgArray[$rgIdx]
                $usingExistingRg = $true
                # Inherit location from the existing RG
                $rgLocation = az group show --name $rgName --query location -o tsv 2>$null
                if ($rgLocation) { $Location = $rgLocation }
                Write-OK "Using existing resource group '$rgName' ($Location)."
            }
        }
    }
} else {
    # User passed -ResourceGroup on the command line
    $rgExists = az group exists --name $ResourceGroup -o tsv 2>$null
    if ($rgExists -eq 'true') {
        $usingExistingRg = $true
        $rgLocation = az group show --name $ResourceGroup --query location -o tsv 2>$null
        if ($rgLocation) { $Location = $rgLocation }
        Write-OK "Using existing resource group '$rgName' ($Location)."
    }
}

if (-not $usingExistingRg) {
    Write-Host "  Creating new resource group '$rgName' in $Location..."
    az group create --name $rgName --location $Location -o none
    Write-OK "Resource group '$rgName' created."
}

# ── 2. Virtual Network & Subnets ─────────────────────────────────────────────

Write-Step "2/8  Virtual network and subnets..."

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

# ── Subnet picker ──
# The Functions app needs a subnet delegated to Microsoft.App/environments with
# at least a /28 (Flex Consumption minimum).  We also need a companion subnet for
# private endpoints (no delegation, any size).

$usingExistingSubnet = $false
$funcSubnetId        = $null     # resource ID — set by this section
$peSubnetId          = $null     # resource ID for the PE subnet
$selectedVnetName    = $null     # populated if user picks an existing subnet
$selectedVnetRg      = $null

if (-not $SubnetId) {
    # Discover subnets in the current subscription that already have the required
    # delegation.  This lets users who have a centrally-managed VNet reuse it.
    Write-Host "  Scanning for subnets delegated to Microsoft.App/environments..."
    $allSubnets = az network vnet list --query "[].{vnet:name, rg:resourceGroup, subnets:subnets}" -o json 2>$null | ConvertFrom-Json

    $candidates = @()
    foreach ($vnet in $allSubnets) {
        foreach ($sn in $vnet.subnets) {
            $hasDelegation = $sn.delegations | Where-Object { $_.serviceName -eq 'Microsoft.App/environments' }
            if ($hasDelegation) {
                $candidates += [PSCustomObject]@{
                    Label    = "$($vnet.vnet)/$($sn.name)  ($($sn.addressPrefix))  [$($vnet.rg)]"
                    SubnetId = $sn.id
                    VnetName = $vnet.vnet
                    VnetRg   = $vnet.rg
                    Prefix   = $sn.addressPrefix
                    Name     = $sn.name
                }
            }
        }
    }

    if ($candidates.Count -gt 0) {
        Write-Host "  Found $($candidates.Count) compatible subnet(s)." -ForegroundColor White
        Write-Host "  Pick one to use for Functions VNet integration, or create a new VNet." -ForegroundColor DarkGray
        $labels = $candidates | ForEach-Object { $_.Label }
        $snIdx = Show-NumberedPicker -Items $labels -Prompt "  Subnet [1-$($candidates.Count) or N]"
        if ($snIdx -ge 0) {
            $chosen = $candidates[$snIdx]
            $funcSubnetId       = $chosen.SubnetId
            $selectedVnetName   = $chosen.VnetName
            $selectedVnetRg     = $chosen.VnetRg
            $usingExistingSubnet = $true
        }
    }
} else {
    # User passed -SubnetId on the command line — validate it
    $funcSubnetId = $SubnetId
    # Parse VNet name and RG from the resource ID
    if ($SubnetId -match '/resourceGroups/([^/]+)/providers/Microsoft.Network/virtualNetworks/([^/]+)/subnets/') {
        $selectedVnetRg   = $Matches[1]
        $selectedVnetName = $Matches[2]
    }
    $usingExistingSubnet = $true
}

# ── Validate an existing subnet ──
if ($usingExistingSubnet -and $funcSubnetId) {
    Write-Host "  Validating subnet..." -ForegroundColor White
    $snInfo = az network vnet subnet show --ids $funcSubnetId -o json 2>$null | ConvertFrom-Json
    if (-not $snInfo) {
        Write-Err "Could not find subnet: $funcSubnetId"
        exit 1
    }

    # Check 1 — Delegation
    $hasDelegation = $snInfo.delegations | Where-Object { $_.serviceName -eq 'Microsoft.App/environments' }
    if (-not $hasDelegation) {
        $currentDelegations = ($snInfo.delegations | ForEach-Object { $_.serviceName }) -join ', '
        if (-not $currentDelegations) { $currentDelegations = '(none)' }
        Write-Warn "Subnet '$($snInfo.name)' is not delegated to Microsoft.App/environments."
        Write-Host "    Current delegations: $currentDelegations" -ForegroundColor DarkGray
        Write-Host ""
        if ($snInfo.delegations -and $snInfo.delegations.Count -gt 0) {
            # Has a DIFFERENT delegation — can't safely change this
            Write-Err   "This subnet is delegated to another service. Changing delegation would"
            Write-Err   "break existing resources using it. Please choose a different subnet or"
            Write-Err   "create a new one (press N at the picker)."
            Write-Host  "    To fix manually: remove the current delegation, then re-run this script." -ForegroundColor DarkGray
            Write-Host  "    az network vnet subnet update --ids $funcSubnetId --remove delegations" -ForegroundColor DarkGray
            exit 1
        } else {
            # No delegation at all — safe to add one (no existing service will break)
            Write-Host  "  This subnet has no delegation. Flex Consumption requires" -ForegroundColor Yellow
            Write-Host  "  delegation to Microsoft.App/environments." -ForegroundColor Yellow
            Write-Host  "  We can add the delegation now (non-destructive, no existing" -ForegroundColor Yellow
            Write-Host  "  resources will be affected)." -ForegroundColor Yellow
            Write-Host ""
            $fix = Read-Host "  Add delegation to Microsoft.App/environments? [Y/n]"
            if ($fix -match '^[Nn]') {
                Write-Host "  Aborted. To add delegation manually:" -ForegroundColor DarkGray
                Write-Host "    az network vnet subnet update --ids $funcSubnetId --delegations Microsoft.App/environments" -ForegroundColor DarkGray
                exit 1
            }
            az network vnet subnet update --ids $funcSubnetId `
                --delegations "Microsoft.App/environments" -o none 2>&1 | ForEach-Object { Write-Host "    $_" }
            if ($LASTEXITCODE -ne 0) {
                Write-Err "Failed to add delegation. You may not have permission on this subnet."
                Write-Host "    Ask your network admin to run:" -ForegroundColor DarkGray
                Write-Host "    az network vnet subnet update --ids $funcSubnetId --delegations Microsoft.App/environments" -ForegroundColor DarkGray
                exit 1
            }
            Write-OK "Delegation added to Microsoft.App/environments."
        }
    } else {
        Write-OK "Delegation: Microsoft.App/environments"
    }

    # Check 2 — Minimum size /28 (16 addresses)
    $cidr = [int]($snInfo.addressPrefix -split '/')[1]
    if ($cidr -gt 28) {
        Write-Err   "Subnet CIDR is /$cidr ($($snInfo.addressPrefix)) — Flex Consumption requires at least /28 (16 addresses)."
        Write-Host  "" 
        Write-Host  "  Resizing a subnet in-place is not supported by Azure — it requires" -ForegroundColor Yellow
        Write-Host  "  deleting and recreating it, which would break any connected resources." -ForegroundColor Yellow
        Write-Host  "  Options:" -ForegroundColor Yellow
        Write-Host  "    1. Pick a different subnet with /28 or larger (press N to go back)" -ForegroundColor DarkGray
        Write-Host  "    2. Create a new subnet in the same VNet:" -ForegroundColor DarkGray
        Write-Host  "       az network vnet subnet create --name func-integration \" -ForegroundColor DarkGray
        Write-Host  "         --resource-group $selectedVnetRg --vnet-name $selectedVnetName \" -ForegroundColor DarkGray
        Write-Host  "         --address-prefix <CIDR /28 or larger> \" -ForegroundColor DarkGray
        Write-Host  "         --delegations Microsoft.App/environments" -ForegroundColor DarkGray
        Write-Host  "    3. Re-run this script and let it create a new VNet (press N at the subnet picker)" -ForegroundColor DarkGray
        exit 1
    }
    Write-OK "CIDR: $($snInfo.addressPrefix) (meets /28 minimum)"
    Write-OK "Using existing subnet: $($snInfo.name) ($($snInfo.addressPrefix))"

    # Look for a companion "private-endpoints" subnet in the same VNet,
    # or create one if it doesn't exist.
    $peSubnet = az network vnet subnet show `
        --name "private-endpoints" `
        --resource-group $selectedVnetRg `
        --vnet-name $selectedVnetName `
        --query id -o tsv 2>$null
    if ($peSubnet) {
        $peSubnetId = $peSubnet
        Write-OK "Private-endpoints subnet found in same VNet."
    } else {
        Write-Host "  Creating 'private-endpoints' subnet in $selectedVnetName..."
        # Find a non-overlapping /24 in the VNet
        $vnetPrefixes = az network vnet show --name $selectedVnetName --resource-group $selectedVnetRg `
            --query "addressSpace.addressPrefixes" -o json 2>$null | ConvertFrom-Json
        # Use 10.0.1.0/24 as default; the user's VNet may have different addressing
        $pePrefix = "10.0.1.0/24"
        az network vnet subnet create `
            --name "private-endpoints" `
            --resource-group $selectedVnetRg `
            --vnet-name $selectedVnetName `
            --address-prefix $pePrefix `
            -o none 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Failed to create private-endpoints subnet ($pePrefix). You may need to choose a non-overlapping CIDR."
            exit 1
        }
        $peSubnetId = az network vnet subnet show `
            --name "private-endpoints" `
            --resource-group $selectedVnetRg `
            --vnet-name $selectedVnetName `
            --query id -o tsv
        Write-OK "Created private-endpoints subnet ($pePrefix)."
    }
    $vnetName = $selectedVnetName
}

# ── Create new VNet + subnets (if not using an existing one) ──
if (-not $usingExistingSubnet) {
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

    Write-OK "VNet '$vnetName' created with func-integration and private-endpoints subnets."

    $selectedVnetRg = $rgName
}

# Resolve subnet resource IDs for later steps (if not already set)
if (-not $funcSubnetId) {
    $funcSubnetId = az network vnet subnet show `
        --name "func-integration" `
        --resource-group $rgName `
        --vnet-name $vnetName `
        --query id -o tsv
}
if (-not $peSubnetId) {
    $peSubnetId = az network vnet subnet show `
        --name "private-endpoints" `
        --resource-group ($selectedVnetRg ?? $rgName) `
        --vnet-name $vnetName `
        --query id -o tsv
}

# Resolve VNet RG (may differ from deployment RG when using existing subnets)
$vnetRg = if ($selectedVnetRg) { $selectedVnetRg } else { $rgName }

Write-Step "Resource plan:"
Write-Host "  Resource Group:   $rgName$(if ($usingExistingRg) {' (existing)'})"
Write-Host "  VNet / Subnet:    $vnetName$(if ($usingExistingSubnet) {' (existing)'})"
Write-Host "  Static Web App:   $swaName"
Write-Host "  Functions App:    $funcAppName  (Flex Consumption)"
Write-Host "  Storage Account:  $storageName  (private endpoint)"
Write-Host "  Location:         $Location"
if (-not $SkipAuth) { Write-Host "  Auth App:         $authAppName" }
Write-Host ""

# ── 3. Storage Account + Private Endpoints + Table ───────────────────────────

Write-Step "3/8  Creating storage account with private endpoints..."

az storage account create `
    --name $storageName `
    --resource-group $rgName `
    --location $Location `
    --sku Standard_LRS `
    --min-tls-version TLS1_2 `
    --allow-blob-public-access false `
    --allow-shared-key-access false `
    --default-action Deny `
    -o none
Write-OK "Storage account '$storageName' created (shared-key disabled, default-action Deny)."

$storageId = az storage account show --name $storageName --resource-group $rgName --query id -o tsv

# Private endpoints for blob (Functions deployment storage) and table (app data)
# $peSubnetId and $vnetName are already resolved from the subnet picker in Step 2.

foreach ($subResource in @("blob", "table", "queue")) {
    $peName = "$storageName-$subResource-pe"
    Write-Host "  Creating private endpoint: $peName ($subResource)..."
    az network private-endpoint create `
        --name $peName `
        --resource-group $rgName `
        --location $Location `
        --subnet $peSubnetId `
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
    $vnetResourceId = az network vnet show --name $vnetName --resource-group $vnetRg --query id -o tsv 2>$null
    az network private-dns zone vnet-link create `
        --name "$vnetName-$subResource-link" `
        --resource-group $rgName `
        --zone-name $dnsZone `
        --virtual-network $vnetResourceId `
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

# ── 4. Azure Functions App (Flex Consumption) ────────────────────────────────

Write-Step "4/8  Creating Functions app (Flex Consumption with VNet integration)..."

$storageUrl = "https://$storageName.table.core.windows.net"

# $funcSubnetId is already resolved from the subnet picker in Step 2.
# Create the Flex Consumption function app with VNet integration, managed identity,
# and identity-based deployment storage from the start.  --https-only enforces TLS.
# WEBSITE_CONTENTOVERVNET routes deployment storage traffic through the VNet,
# which is required because the storage account has public access disabled.
az functionapp create `
    --name $funcAppName `
    --resource-group $rgName `
    --storage-account $storageName `
    --flexconsumption-location $Location `
    --runtime node `
    --runtime-version 20 `
    --functions-version 4 `
    --subnet $funcSubnetId `
    --assign-identity [system] `
    --deployment-storage-auth-type SystemAssignedIdentity `
    --https-only true `
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

Write-OK "Functions app '$funcAppName' created (VNet + MI + HTTPS-only)."

# Retrieve the managed identity principal ID (enabled at creation via --assign-identity).
# Enterprise policy enforces allowSharedKeyAccess=false on storage accounts,
# so the Functions runtime must use identity-based connections.
$miPrincipalId = az functionapp identity show `
    --name $funcAppName `
    --resource-group $rgName `
    --query principalId -o tsv
Write-OK "Managed identity principal: $miPrincipalId"

# Assign storage RBAC roles to the managed identity.
# The Functions runtime needs Blob/Queue access for internal operations
# (triggers, deployment, host keys), and Table access for the app data.
Write-Host "  Assigning storage RBAC roles to managed identity..."
foreach ($role in @("Storage Blob Data Owner", "Storage Queue Data Contributor", "Storage Table Data Contributor")) {
    az role assignment create `
        --assignee-object-id $miPrincipalId `
        --assignee-principal-type ServicePrincipal `
        --role $role `
        --scope $storageId `
        -o none 2>$null
}
Write-OK "Storage RBAC roles assigned."

# Remove any legacy connection-string settings that az functionapp create may have set.
# Deployment storage auth was already configured at creation (--deployment-storage-auth-type),
# but the CLI may still add AzureWebJobsStorage or DEPLOYMENT_STORAGE_CONNECTION_STRING.
az functionapp config appsettings delete `
    --name $funcAppName `
    --resource-group $rgName `
    --setting-names AzureWebJobsStorage DEPLOYMENT_STORAGE_CONNECTION_STRING `
    -o none 2>$null

# Wait for RBAC propagation before deploying.
# Azure RBAC assignments on storage can take 1-10 minutes to become effective.
# We cannot test data-plane access from the CLI (public access is disabled), so
# we use a fixed wait combined with deployment retries as a safety net.
Write-Host "  Waiting 2 minutes for RBAC propagation..."
for ($i = 120; $i -gt 0; $i -= 30) {
    Write-Host "    ${i}s remaining..." -ForegroundColor DarkGray
    Start-Sleep ([Math]::Min(30, $i))
}
Write-OK "RBAC propagation wait complete."

# Configure app settings for the API
az functionapp config appsettings set `
    --name $funcAppName `
    --resource-group $rgName `
    --settings `
        "AzureWebJobsStorage__accountName=$storageName" `
        "WEBSITE_CONTENTOVERVNET=1" `
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

# Retry deployment up to 3 times (RBAC propagation can cause initial 403s)
$deploySuccess = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    Write-Host "  Deploy attempt $attempt/3..."
    $deployResult = az functionapp deployment source config-zip `
        --name $funcAppName `
        --resource-group $rgName `
        --src $zipPath `
        -o json 2>&1
    if ($LASTEXITCODE -eq 0) {
        $deploySuccess = $true
        break
    }
    if ($attempt -lt 3) {
        Write-Warn "Deployment attempt $attempt failed (RBAC may still be propagating). Retrying in 60s..."
        Start-Sleep 60
    }
}

Remove-Item $zipPath -ErrorAction SilentlyContinue
if (-not $deploySuccess) {
    Write-Err "API deployment failed after 3 attempts. Run the script again to retry."
    Write-Host "  Last error: $deployResult" -ForegroundColor DarkGray
    exit 1
}
Write-OK "API code deployed to Functions app."

# ── 5. Static Web App ───────────────────────────────────────────────────────

Write-Step "5/8  Creating Static Web App (Standard tier)..."
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

# Write the body to a temp file to avoid shell escaping issues with az rest.
$linkBody = @{ properties = @{ backendResourceId = $funcAppId; region = $Location } } | ConvertTo-Json -Compress
$linkBodyFile = "$scriptDir\_link.json"
$linkBody | Set-Content $linkBodyFile -Encoding UTF8

az rest --method PUT `
    --url "$swaId/linkedBackends/${funcAppName}?api-version=2022-09-01" `
    --body "@$linkBodyFile" `
    --headers "Content-Type=application/json" `
    -o none 2>&1 | ForEach-Object { Write-Host "    $_" }

Remove-Item $linkBodyFile -ErrorAction SilentlyContinue

if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to link Functions app as SWA backend. See output above."
    exit 1
}

# Verify the link was created
$linkedBackends = az rest --method GET --url "$swaId/linkedBackends?api-version=2022-09-01" -o json 2>$null | ConvertFrom-Json
if (-not $linkedBackends.value -or $linkedBackends.value.Count -eq 0) {
    Write-Err "Linked backend was not created. The API will not be reachable from the SWA."
    exit 1
}
Write-OK "Functions app linked as SWA backend."

# ── 6. Entra ID Auth App Registration ────────────────────────────────────────

if (-not $SkipAuth) {
    Write-Step "6/8  Creating Entra ID auth app registration..."

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
    $redirectBody = @{ web = @{ redirectUris = @($aadCallbackUrl) } } | ConvertTo-Json -Compress
    $redirectBodyFile = "$scriptDir\_redirect.json"
    $redirectBody | Set-Content $redirectBodyFile -Encoding UTF8
    az rest --method PATCH `
        --url "https://graph.microsoft.com/v1.0/applications/$authObjectId" `
        --body "@$redirectBodyFile" `
        --headers "Content-Type=application/json" `
        -o none 2>$null
    Remove-Item $redirectBodyFile -ErrorAction SilentlyContinue
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
    Write-Step "6/8  Skipping auth (-SkipAuth)..."
}

# ── 7. Generate staticwebapp.config.json + Deploy ────────────────────────────

Write-Step "7/8  Generating staticwebapp.config.json..."

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

# ── 8. Deploy Static Content + App Settings ──────────────────────────────────

Write-Step "8/8  Deploying static content and configuring app settings..."

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
