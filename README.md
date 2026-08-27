# PowerPlatform-CertConnections

PowerShell scripts for creating, sharing, and auditing certificate-authenticated Power Platform
connections - Dataverse, Key Vault, and Power Automate Desktop "run-owner" connections - without
any delegated/interactive sign-in. Every call authenticates as a Service Principal using a
certificate (`client_credentials` + a JWT assertion, RFC 7523).

Works on both Windows PowerShell 5.1 and PowerShell 7+.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+, on Windows
- Existing app registrations (Service Principals) with their certificates already uploaded to
  Entra ID
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), only if you want to source
  a certificate from Azure Key Vault

## Install

Clone or download the repo - there's no build/install step, the scripts import the shared module
from their own folder automatically.

```powershell
git clone https://github.com/JakeGwynn/PowerPlatform-CertConnections.git
cd PowerPlatform-CertConnections
```

## What's included

| File | Purpose |
|---|---|
| `New-PowerPlatformCertConnection.ps1` | Creates a connection (`-ConnectionType Dataverse\|KeyVault\|PadRunOwner`). |
| `Grant-PowerPlatformConnectionAccess.ps1` | Shares an existing connection with one or more people. |
| `Get-PowerPlatformConnectionPermissions.ps1` | Lists who a connection is currently shared with. |
| `Modules\PowerPlatformCertConnection.Common.psm1` | Shared logic used by all three scripts. |

## How it works

Two identities are involved in creating a connection:

- **Caller** - authenticates every API call with its own certificate.
- **Connection / Run Owner** - never authenticates anything itself; its client id + certificate
  are just embedded in the connection for Power Platform to use at run time. This app must
  already have whatever access the target service requires.

Either identity's certificate can come from:

| Source | Parameters |
|---|---|
| Local certificate store | `-<Identity>CertThumbprint` (+ `-<Identity>CertStoreLocation`) |
| Local PFX file | `-<Identity>PfxPath` + `-<Identity>PfxPassword` |
| Azure Key Vault | `-<Identity>KeyVaultName` + `-<Identity>KeyVaultSecretName` |

`<Identity>` is `Caller`, `Connection` (Dataverse/KeyVault types), or `RunOwner` (PadRunOwner
type). The Key Vault source is the one place a signed-in session is used: it calls the `az` CLI
(`az login` if you're not already signed in) to read the certificate's private key. That session
is only ever used to fetch the key - never to call Dataverse, Power Platform, or Graph.

## Prerequisites

- The Caller and Connection/RunOwner app registrations and their certificates already exist.
- The Connection/RunOwner app already has whatever access the target service requires:
  - **Dataverse**: the script will create a Dataverse application user + security role for it if
    one doesn't already exist.
  - **Key Vault**: you need to grant it access yourself (e.g. the "Key Vault Secrets User" RBAC
    role).
  - **PadRunOwner**: it must be a Dataverse application user with at least "Environment Maker",
    and shared on the Machine/Machine Group, Credential record, Desktop Flow, and any Work Queues
    used. See
    [Set a run owner on a desktop flow connection](https://learn.microsoft.com/power-automate/desktop-flows/how-to/set-runowner-desktopflowconnection).
  - **PadRunOwner** also needs an existing Dataverse `Credential` record (unless
    `-RunOwnerCredentialMode Direct`) and a Machine Group registered through the portal or the
    machine runtime app.

## Creating a connection

### Dataverse

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType Dataverse `
    -TenantId $tenantId -EnvironmentId $envId `
    -DataverseUrl 'https://contoso.crm.dynamics.com' `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -ConnectionClientId $connectionAppId -ConnectionCertThumbprint $connectionThumbprint `
    -ShareWithUpns 'admin@contoso.onmicrosoft.com' -ShareAccessLevel CanEdit
```

### Key Vault

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType KeyVault `
    -TenantId $tenantId -EnvironmentId $envId `
    -VaultName 'ContosoKeyVault' `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -ConnectionClientId $connectionAppId `
    -ConnectionKeyVaultName 'CertsVault' -ConnectionKeyVaultSecretName 'connection-cert'
```

### Power Automate Desktop run-owner

Needs `-RunOwnerAppId` (+ a cert source), `-MachineGroupId`, and a `-RunOwnerCredentialMode`:

| Mode | Also needs | Notes |
|---|---|---|
| `KeyVaultPassword` (default) | `-CredentialId`, `-UsernameEnvironmentVariable`, `-PasswordEnvironmentVariable` | Both username and password come from Dataverse environment variables. |
| `KeyVaultCertificate` | `-CredentialId`, `-UsernameEnvironmentVariable` | Password is sent as the literal `"none"`. |
| `CyberArk` | `-CredentialId`, `-UsernameEnvironmentVariable` | Same request as `KeyVaultCertificate` - the difference is in how the Credential record itself is backed. |
| `Direct` | `-DirectUsername`, `-DirectPassword` | Literal username/password, no Credential record needed. |

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType PadRunOwner `
    -TenantId $tenantId -EnvironmentId $envId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -RunOwnerAppId $runOwnerAppId -RunOwnerCertPfxPath .\runowner.pfx -RunOwnerCertPfxPassword (Read-Host -AsSecureString) `
    -RunOwnerCredentialMode KeyVaultPassword `
    -CredentialId $credentialId -UsernameEnvironmentVariable 'new_UserName1' -PasswordEnvironmentVariable 'new_Password1' `
    -MachineGroupId $machineGroupId -ConnectionDisplayName 'Prod RunOwner Connection'
```

PadRunOwner connections can only be shared with other Service Principals, never human users -
pass `-SharePrincipalType ServicePrincipal` if you use `-ShareWithUpns` for this type.

### Connection ID logging

Every connection created prints its `ConnectionId` and appends a line to
`<OutputDirectory>\CreatedConnections.log.txt` (override with `-ConnectionLogPath`), so you have a
running history of everything created.

### `-WhatIf`

All three scripts support `-WhatIf`/`-Confirm`. Certificate loading and token acquisition still
happen (they're read-only), but nothing is created, shared, or logged.

## Sharing a connection

`Grant-PowerPlatformConnectionAccess.ps1` shares an existing connection at one of three levels:

| `-AccessLevel` | Portal label |
|---|---|
| `CanUse` (default) | "Can use" |
| `CanUseAndShare` | "Can use and share" |
| `CanEdit` | "Can edit" |

```powershell
.\Grant-PowerPlatformConnectionAccess.ps1 `
    -TenantId $tenantId -EnvironmentId $envId `
    -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint `
    -PrincipalUpnsOrIds 'janedoe@contoso.onmicrosoft.com', 'admin@contoso.onmicrosoft.com' -AccessLevel CanUse
```

`-PrincipalUpnsOrIds` accepts UPNs/emails (resolved via Graph - the Caller app needs
`User.Read.All` application permission, admin-consented) or raw Entra object IDs directly.

## Checking who has access

```powershell
.\Get-PowerPlatformConnectionPermissions.ps1 `
    -TenantId $tenantId -EnvironmentId $envId `
    -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
    -CallerClientId $callerAppId -CallerCertThumbprint $callerThumbprint
```

```
PrincipalDisplayName PrincipalEmail       PrincipalId                          PrincipalType AccessLevel RoleName
-------------------- -------------------- ------------------------------------ ------------- ----------- --------
Portal Admin         admin@contoso.com    11111111-1111-1111-1111-111111111111 User          Owner       Owner
Jane Doe             janedoe@contoso.com  33333333-3333-3333-3333-333333333333 User          CanEdit     CanEdit
```

Add `-AsRawJson` to also save the unmodified API response. Listing permissions requires the
Caller identity to own the connection (or otherwise be entitled on it) - a non-owner call returns
403.

## Sovereign clouds

All three scripts expose `-LoginAuthorityBaseUrl`, `-PowerPlatformApiResource`,
`-EnvironmentApiDomainSuffix`, `-ApiVersion`, and `-TimeoutSec` overrides. Defaults are the public
commercial cloud; verify the correct values for your cloud before relying on the overrides.
