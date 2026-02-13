# Time Entry Demo

A lightweight time-tracking web app built on Azure Static Web Apps with Azure Table Storage for persistence and Entra ID for authentication.

![Azure Static Web Apps](https://img.shields.io/badge/Azure-Static%20Web%20Apps-0078D4?logo=microsoft-azure)
![Azure Functions](https://img.shields.io/badge/Azure-Functions-0062AD?logo=azure-functions)
![Azure Table Storage](https://img.shields.io/badge/Azure-Table%20Storage-0078D4?logo=microsoft-azure)

## What You Get

- **Single-page time entry UI** — date, project, task, hours, billable flag, notes
- **Persistent storage** — Azure Table Storage (no SQL database needed)
- **Azure AD authentication** — built-in AAD provider with single-tenant Entra ID
- **Serverless API** — Azure Functions (Flex Consumption, linked to SWA)
- **Enterprise-ready networking** — VNet + private endpoints (no public storage access)
- **Zero infrastructure to manage** — all serverless, minimal cost
<img width="895" height="983" alt="image" src="https://github.com/user-attachments/assets/04ef8600-d064-49dd-9aae-6af57a4adf11" />

## Architecture

```mermaid
flowchart TB
    subgraph Browser["Browser"]
        UI["index.html<br/>(Single-page app)"]
    end

    subgraph AAD["Microsoft Entra ID"]
        Login["/.auth/login/aad<br/>Built-in AAD provider"]
    end

    subgraph AzureSub["Azure Subscription"]
        subgraph SWA["Static Web App (Standard)"]
            Static["Static Hosting<br/>(app/)"]
        end

        subgraph Functions["Azure Functions (Flex Consumption, Node 20)"]
            Validate["Auth validation<br/>(x-ms-client-principal)"]
            GET["GET /api/entries"]
            POST["POST /api/entries"]
            DELETE["DELETE /api/entries/{id}"]
        end

        subgraph VNet["VNet"]
            PE["Private Endpoints<br/>(blob, table, queue)"]
        end

        subgraph Storage["Storage Account<br/>(public access disabled)"]
            Table["Table Storage<br/>TimeEntries"]
        end
    end

    UI -- "HTTPS" --> Static
    UI -. "/.auth/login/aad<br/>(302 redirect)" .-> Login
    Login -. "ID token + cookie" .-> Static
    Static -- "/api/* (linked backend)" --> Validate
    Validate -- "provider OK" --> GET & POST & DELETE
    Functions -- "Managed Identity<br/>(DefaultAzureCredential)" --> PE
    PE -- "Private DNS" --> Table
```

### How it works

| Layer | Details |
|-------|---------|
| **Front-end** | Single HTML file served by SWA's global CDN. No build step. |
| **Authentication** | Single-tenant Entra ID app registration using the built-in AAD provider. No client secret required — SWA handles token exchange internally. This avoids issues with enterprise Entra policies that block password credentials. Optional claims are configured to ensure SWA can identify the user. |
| **Auth validation** | Each API function checks the `x-ms-client-principal` header to confirm the user authenticated via the built-in AAD provider (`identityProvider === "aad"`). Since the provider is configured with a single-tenant issuer URL, only users from the expected tenant can obtain a valid session. |
| **API** | Three Azure Functions on a Flex Consumption plan with VNet integration. Linked to SWA as a backend — SWA forwards `/api/*` requests and the `x-ms-client-principal` auth header. |
| **Storage auth** | The Functions app's **system-assigned managed identity** has the **Storage Table Data Contributor** RBAC role. The API code uses `DefaultAzureCredential` which automatically picks up the managed identity — no secrets, no certificates, no expiry. |
| **Networking** | A VNet with two subnets: one for Functions VNet integration (outbound), one for private endpoints. Storage has public network access **disabled** and shared-key auth **disabled**. The Functions app reaches storage exclusively through private endpoints + private DNS zones. |
| **Data** | Azure Table Storage — schema-less, pay-per-use, no database server to manage. |

## Prerequisites

| Tool | Minimum Version | Install |
|------|----------------|---------|

| **PowerShell** | 7+ | Built into Windows 11, or [install](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell) |
| **Azure CLI** | 2.50+ | `winget install Microsoft.AzureCLI` |
| **Node.js** | 18+ | `winget install OpenJS.NodeJS.LTS` |

You also need:
- An Azure subscription
- Permissions to create app registrations in your Entra ID tenant

## Quick Start

```powershell
# 1. Clone this repo
git clone https://github.com/t3blake/time-track-demo.git
cd time-track-demo

# 2. Log in to Azure (if not already)
az login

# 3. Deploy everything (you'll be prompted for a unique prefix)
./deploy.ps1
```

The script prompts for a **prefix** (e.g. your alias) to generate unique Azure resource names. Then it will:
1. Create a resource group, VNet, and storage account with private endpoints
2. Create a Flex Consumption Functions app with VNet integration and managed identity
3. Create a Static Web App (Standard) and link the Functions app as its backend
4. Register an Entra ID auth app with API permissions and optional claims
5. Generate the SWA config and deploy static content

At the end it prints the URL to open in your browser.

## Options

```powershell
# Skip the prefix prompt by passing it directly
./deploy.ps1 -Prefix jsmith

# Deploy to a different region
./deploy.ps1 -Prefix jsmith -Location westus2

# Deploy without Entra ID auth (open to anyone)
./deploy.ps1 -Prefix jsmith -SkipAuth

# Tear down everything
./deploy.ps1 -Prefix jsmith -Teardown
```

## Project Structure

```
time-entry-demo/
├── deploy.ps1                    # One-click deployment script
├── app/
│   ├── index.html                # Single-file front-end (HTML + CSS + JS)
│   └── staticwebapp.config.json  # Generated by deploy.ps1
└── api/
    ├── host.json                 # Azure Functions host config
    ├── package.json              # Node.js dependencies
    ├── getEntries/               # GET /api/entries
    │   ├── function.json
    │   └── index.js
    ├── saveEntry/                # POST /api/entries
    │   ├── function.json
    │   └── index.js
    └── deleteEntry/              # DELETE /api/entries/{id}
        ├── function.json
        └── index.js
```

## Cost

| Resource | Tier | Approximate cost |
|----------|------|------------------|
| **Static Web Apps** | Standard | ~$9/month |
| **Azure Functions** | Flex Consumption | ~$0 for demo traffic (pay-per-execution) |
| **Azure Table Storage** | Standard LRS | ~$0.045/GB/month (pennies for demo usage) |
| **VNet + Private Endpoints** | Standard | ~$7/month (3 PEs × ~$2.30 each) |
| **Private DNS Zones** | Standard | ~$0.75/month (3 zones × $0.25 each) |

Total: **~$17/month** for a fully enterprise-compliant deployment with no public storage access.

## Troubleshooting

### "Too many redirects" after deploying
The `/.auth/*` route must appear **before** the `/*` catch-all in `staticwebapp.config.json`. Without it, unauthenticated requests to `/.auth/login/aad` match the `/*` rule (which requires `authenticated`), triggering a 302 back to `/.auth/login/aad` — an infinite loop. The deploy script handles this automatically.

### "Could not load entries" or API returns 500
| Cause | Fix |
|-------|-----|
| **Functions app not linked to SWA** | Check `az staticwebapp backends list`. Re-run `deploy.ps1` to re-link. |
| **Private endpoint DNS not resolving** | Verify the private DNS zones exist and are linked to the VNet. Re-run `deploy.ps1`. |
| **TimeEntries table doesn't exist** | Re-run `deploy.ps1` — it creates the table via ARM at deploy time. |
| **Missing app settings on Functions app** | Check `TABLE_STORAGE_URL` and `AzureWebJobsStorage__accountName` on the Functions app, and `AAD_CLIENT_ID` on the SWA. |
| **Managed identity RBAC not propagated** | RBAC assignments can take up to 10 minutes. Wait and retry, or re-run `deploy.ps1`. |

### Checking API logs
```powershell
# Stream live logs from the Functions app
az functionapp log tail --name <prefix>-demo-api --resource-group rg-<prefix>-demo
```

## Security Notes

- **Built-in AAD provider**: Uses the SWA built-in `azureActiveDirectory` identity provider (`/.auth/login/aad`). No client secret is required — SWA handles the token exchange internally. This avoids issues with enterprise Entra policies that block password credentials on app registrations.
- **Optional claims**: The auth app is configured with optional ID token claims (`email`, `preferred_username`, `upn`) to ensure SWA can identify the user. Without these, SWA returns a 403 `invalidUserInfo` or enters a redirect loop.
- **API-level auth validation**: For defense in depth, every API function checks the `x-ms-client-principal` header to confirm the user authenticated via the built-in AAD provider (`identityProvider === "aad"`). Since the provider is configured with a single-tenant issuer URL, only users from the expected tenant can obtain a valid session.
- **Managed identity storage auth**: The Functions app uses its system-assigned managed identity with `DefaultAzureCredential` to access Table Storage. The managed identity has the **Storage Table Data Contributor** RBAC role. No secrets, certificates, or connection strings are used — nothing to rotate or expire.
- **Storage lockdown**: The storage account has **public network access disabled** and **shared-key auth disabled** (`allowSharedKeyAccess: false`). All access is via managed identity through VNet integration + private endpoints + private DNS zones. No storage data traverses the public internet.
- **Linked backend**: The SWA forwards `/api/*` requests to the Functions app as a linked backend, including the `x-ms-client-principal` header for auth validation. The Functions app accepts inbound traffic from SWA's backend linking mechanism.

## Cleanup

To remove all Azure resources:

```powershell
./deploy.ps1 -Prefix jsmith -Teardown
```

This deletes the resource group (and everything in it) plus all Entra ID app registrations.
Use the same `-Prefix` you used when deploying.
