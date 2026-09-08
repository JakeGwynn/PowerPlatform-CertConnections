# PowerPlatform-CertConnections

PowerShell scripts for creating, sharing, and auditing Power Platform connections - Dataverse,
Key Vault, and Power Automate Desktop "run-owner" connections. The Caller identity that performs
each API call can authenticate either as a Service Principal using a certificate
(`client_credentials` + a JWT assertion, RFC 7523), or via your own delegated (interactive)
sign-in - see [Caller authentication](#caller-authentication).

Works on both Windows PowerShell 5.1 and PowerShell 7+.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+, on Windows
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) - required if the Caller
  uses delegated auth, or if any certificate is sourced from Azure Key Vault
- Existing app registrations (Service Principals) with their certificates already uploaded to
  Entra ID, for whichever identities use Certificate auth (always required for the
  Connection/RunOwner identity; required for the Caller unless it uses delegated auth)

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

- **Caller** - performs every API call. Supports two auth modes, selected via `-CallerAuthMode`:
  `Certificate` (default) or `Delegated`. See [Caller authentication](#caller-authentication).
- **Connection / Run Owner** - never authenticates anything itself; its client id + certificate
  are just embedded in the connection for Power Platform to use at run time. This app must
  already have whatever access the target service requires. Always `Certificate`-based - there's
  no delegated option for it, since it isn't an identity that signs in anywhere.

## Caller authentication

| Mode | How it works | Needs |
|---|---|---|
| `Certificate` (default) | `client_credentials` + a certificate JWT assertion (RFC 7523) | `-CallerClientId` + a certificate source (below) |
| `Delegated` | Your own interactive sign-in, via the `az` CLI's own session (`az login` if not already signed in, then `az account get-access-token`) | Nothing else - `-CallerClientId` and every Caller certificate parameter are ignored |

## Certificate sources

For any identity using `Certificate` auth (the Connection/RunOwner identity always; the Caller
when `-CallerAuthMode Certificate`), its certificate can come from:

| Source | Parameters |
|---|---|
| Local certificate store | `-<Identity>CertThumbprint` (+ `-<Identity>CertStoreLocation`) |
| Local PFX file | `-<Identity>PfxPath` + `-<Identity>PfxPassword` |
| Azure Key Vault | `-<Identity>KeyVaultName` + `-<Identity>KeyVaultSecretName` |

`<Identity>` is `Caller`, `Connection` (Dataverse/KeyVault types), or `RunOwner` (PadRunOwner
type). The Key Vault source calls the `az` CLI (`az login` if you're not already signed in) to
read the certificate's private key - the same sign-in session a Delegated Caller uses, just for a
different purpose (reading a secret vs. authenticating the call itself).

## Prerequisites

- Whichever identities use Certificate auth already have their app registration and certificate
  set up. A Delegated Caller needs no app registration - just an `az`-CLI-signed-in account with
  whatever Dataverse/Power Platform/Graph access it needs to perform the requested operation.
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

Same thing with a delegated Caller (interactive sign-in, no Caller app registration or
certificate needed - only the embedded Connection identity still needs one):

```powershell
.\New-PowerPlatformCertConnection.ps1 -ConnectionType Dataverse `
    -TenantId $tenantId -EnvironmentId $envId `
    -DataverseUrl 'https://contoso.crm.dynamics.com' `
    -CallerAuthMode Delegated `
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

Or with a delegated Caller:

```powershell
.\Grant-PowerPlatformConnectionAccess.ps1 `
    -TenantId $tenantId -EnvironmentId $envId `
    -Connector 'shared_commondataserviceforapps' -ConnectionId $connectionId `
    -CallerAuthMode Delegated `
    -PrincipalUpnsOrIds 'janedoe@contoso.onmicrosoft.com' -AccessLevel CanUse
```

`-PrincipalUpnsOrIds` accepts UPNs/emails (resolved via Graph) or raw Entra object IDs directly.
Resolving a UPN/email needs Graph user-read access: a Certificate Caller needs `User.Read.All`
application permission (admin-consented); a Delegated Caller uses whatever directory-read access
the signed-in account already has.

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

These overrides apply to Certificate-mode token requests, which this repo makes directly. A
Delegated Caller instead gets its token via `az account get-access-token`, so it follows the
Azure CLI's own cloud context (`az cloud set --name AzureUSGovernment`, etc.) rather than
`-LoginAuthorityBaseUrl` - set that with the `az` CLI itself before using `-CallerAuthMode
Delegated` outside the public commercial cloud.
