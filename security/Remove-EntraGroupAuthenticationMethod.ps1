#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Removes specified Microsoft Entra ID authentication methods from every direct
    user member of a given group, with a full audit log of what was found and
    what was changed.

.DESCRIPTION
    For each direct user member of -GroupId, this script:
      1. Loads the account (Id, UserPrincipalName, DisplayName, AccountEnabled, UserType).
      2. Retrieves and logs the user's COMPLETE current authentication method
         inventory (every registered method, not only the ones targeted for
         removal) - this is the audit trail of what existed before any change.
      3. Evaluates the lockout guard (see below).
      4. Removes each present method whose type is in -AuthenticationMethodType,
         one Graph call per method, each gated by -WhatIf/-Confirm.

    This script is intentionally standalone and does NOT use Connect-EntraToolkit
    from the shared module. Connect-EntraToolkit deliberately refuses client
    secrets and delegated auth (see its own documentation) because a bearer
    secret can be replayed by anyone who reads it. That is the right default for
    read/report scripts. This script's job, however, explicitly requires
    supporting a client secret and an interactive device-code sign-in as first-
    class options, which would contradict that module's stated security posture.
    Rather than weaken Connect-EntraToolkit for every consumer of the shared
    module, this script owns its own Connect-MgGraph logic and takes on that
    trade-off only for itself. It still reuses Write-EntraLog from the shared
    module for consistent log formatting.

    DELETABLE AUTHENTICATION METHOD TYPES
    Only method types Microsoft Graph actually supports deleting are accepted by
    -AuthenticationMethodType: Email, Fido2, MicrosoftAuthenticator, Phone,
    SoftwareOath, TemporaryAccessPass, WindowsHelloForBusiness. Two method types
    that exist on a user are deliberately NOT offered:
      - Password: there is no delete operation for passwordAuthenticationMethod.
        A password is reset (Update-MgUserAuthenticationMethod / Reset password),
        never deleted as a method.
      - PlatformCredential (Platform SSO / passkey-in-platform-authenticator):
        Microsoft Graph does not expose a delete operation for this method type
        as of this writing.
    Both are still shown in the inventory log for every user, because knowing a
    user's full authentication surface is part of what "detailed log" means here.

    LOCKOUT GUARD
    Removing every authentication method from a user locks them out of
    self-service sign-in and password/MFA reset. Removing every STRONG
    (MFA-capable) method while leaving only a password silently drops the user
    below any Conditional Access / Security Defaults MFA requirement without an
    obvious symptom until their next sign-in is blocked or, worse, succeeds with
    only a password. Before touching a given user, this script computes what
    would remain after the requested removals and skips ALL removals for that
    user (logging why) if either would happen:
      - Zero authentication methods of any kind would remain.
      - Zero methods from the strong set (Fido2, MicrosoftAuthenticator, Phone,
        SoftwareOath, WindowsHelloForBusiness) would remain AND a password
        method would still exist (i.e. the user would be reduced to
        password-only sign-in).
    -Force bypasses this guard. -Force does NOT bypass -WhatIf/-Confirm - it
    only tells the script's own safety check to stand down; the standard
    PowerShell ShouldProcess confirmation for the destructive call still runs.

    CONFIRMATION MODEL
    This script uses standard ShouldProcess semantics (SupportsShouldProcess,
    ConfirmImpact = 'High'), the same model as Remove-MgUser or Remove-Item.
    With the default $ConfirmPreference ('High'), PowerShell will prompt once
    per individual authentication-method removal. For a large group this means
    many prompts. The intended workflow is:
      1. Run with -WhatIf first to review exactly what would be removed and to
         see any lockout-guard warnings, with zero risk.
      2. Re-run with -Confirm:$false once you have reviewed the -WhatIf log and
         are ready to execute for real without a prompt per method.

    OUTPUT AND LOGGING
    Every account processed writes structured lines to Write-EntraLog (streams,
    see that function's own documentation) AND to a plain-text log file
    (-LogPath, default ./logs/<script>_<UTC timestamp>.log) so a run is captured
    on disk even when console output is not redirected. In addition, one result
    object per (user, targeted method) pair is written to the success stream AND
    collected into a CSV (-CsvPath, default ./out/<script>_<UTC timestamp>.csv)
    for attachment to a change ticket. The CSV is written even for a -WhatIf run,
    so a dry run produces a reviewable artifact, not just console noise.

.PARAMETER GroupId
    Object ID (GUID) of the Entra ID group whose direct user members are
    processed. Must be an ID, not a display name, to avoid acting on the wrong
    group when display names collide. Resolve a display name first:
        (Get-MgGroup -Filter "displayName eq 'Finance Team'").Id
    Only DIRECT members are processed. A user who is only a member via a nested
    group is not included; expand nested groups yourself and call this script
    per resolved group, or pass their UPN via a second run, if that is needed.

.PARAMETER AuthenticationMethodType
    One or more authentication method types to remove from every in-scope user.
    Valid values: Email, Fido2, MicrosoftAuthenticator, Phone, SoftwareOath,
    TemporaryAccessPass, WindowsHelloForBusiness. A type is only acted on for a
    given user if that user actually has a method of that type; it is not an
    error for a user to have none.

.PARAMETER ExcludeUserPrincipalName
    UPNs to skip entirely (e.g. break-glass accounts). Logged as Excluded, not
    silently dropped.

.PARAMETER IncludeGuests
    Also process members with UserType 'Guest'. Off by default: guest accounts
    are usually owned by a different process (the inviting tenant / sponsor),
    and silently stripping their authentication methods from this tenant's side
    is rarely the intended action of a group-based cleanup.

.PARAMETER Force
    Bypass the lockout guard described above. Does not bypass -WhatIf/-Confirm.

.PARAMETER LogPath
    Path to the plain-text audit log. Defaults to
    ./logs/Remove-EntraGroupAuthenticationMethod_<UTC timestamp>.log relative to
    the toolkit root. The parent directory is created if missing.

.PARAMETER CsvPath
    Path to the structured CSV result export. Defaults to
    ./out/Remove-EntraGroupAuthenticationMethod_<UTC timestamp>.csv relative to
    the toolkit root. The parent directory is created if missing.

.PARAMETER ClientId
    Application (client) ID of the app registration (or, for -UseDeviceCode, of
    a public client app registration configured to allow the device code flow).

.PARAMETER TenantId
    Directory (tenant) ID or verified domain name.

.PARAMETER ClientSecret
    Client secret of the app registration, as a SecureString. Use with -ClientId
    and -TenantId. Never pass this as a plain-text literal on the command line
    (it lands in shell history and process listings); read it interactively or
    from a secret store, e.g.:
        $secret = Read-Host -AsSecureString 'Client secret'
    or
        $secret = ConvertTo-SecureString (az keyvault secret show ...) -AsPlainText -Force

.PARAMETER CertificateThumbprint
    Thumbprint of a certificate in the local certificate store (Windows only in
    practice - see -Certificate for Linux/macOS).

.PARAMETER CertificateSubjectName
    Subject name of a certificate in the local certificate store.

.PARAMETER Certificate
    An already-loaded X509Certificate2 with a private key. The practical option
    on Linux/macOS, where the PowerShell Cert: provider is not a real store.

.PARAMETER UseDeviceCode
    Sign in interactively via the device code flow instead of app-only auth.
    This is DELEGATED access: the signed-in user, not the app, is the actor.
    Microsoft Graph requires the signed-in user to hold the Authentication
    Administrator role to change authentication methods for other users, and
    the Privileged Authentication Administrator role specifically if any target
    user holds a privileged directory role themselves. The app registration
    used for -ClientId must be a public client with "Allow public client flows"
    enabled and the delegated permission UserAuthenticationMethod.ReadWrite.All
    (plus Group.Read.All and User.Read.All) consented.

.EXAMPLE
    # Preview only - certificate auth, no changes made.
    ./security/Remove-EntraGroupAuthenticationMethod.ps1 `
        -GroupId '11111111-1111-1111-1111-111111111111' `
        -AuthenticationMethodType Phone, SoftwareOath `
        -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint `
        -WhatIf

.EXAMPLE
    # Execute for real after reviewing the -WhatIf log above, no per-item prompts.
    ./security/Remove-EntraGroupAuthenticationMethod.ps1 `
        -GroupId '11111111-1111-1111-1111-111111111111' `
        -AuthenticationMethodType Phone, SoftwareOath `
        -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint `
        -ExcludeUserPrincipalName 'breakglass-01@contoso.example' `
        -Confirm:$false

.EXAMPLE
    # Client secret auth (CI/CD or an environment where a certificate is impractical).
    $secret = Read-Host -AsSecureString 'Client secret'
    ./security/Remove-EntraGroupAuthenticationMethod.ps1 `
        -GroupId '11111111-1111-1111-1111-111111111111' `
        -AuthenticationMethodType MicrosoftAuthenticator `
        -ClientId $clientId -TenantId $tenantId -ClientSecret $secret `
        -Confirm:$false

.EXAMPLE
    # Interactive device-code sign-in (delegated, an admin operator at a keyboard).
    ./security/Remove-EntraGroupAuthenticationMethod.ps1 `
        -GroupId '11111111-1111-1111-1111-111111111111' `
        -AuthenticationMethodType TemporaryAccessPass `
        -ClientId $publicClientId -TenantId $tenantId -UseDeviceCode `
        -WhatIf

.EXAMPLE
    # Reuse a Graph connection already established earlier in the session.
    Connect-MgGraph -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint
    ./security/Remove-EntraGroupAuthenticationMethod.ps1 `
        -GroupId '11111111-1111-1111-1111-111111111111' `
        -AuthenticationMethodType Fido2 `
        -Force -Confirm:$false

.NOTES
    REQUIRED MICROSOFT GRAPH PERMISSIONS
      App-only (ClientSecret / Certificate*): grant to the app registration with
      admin consent:
        Group.Read.All (or GroupMember.Read.All)   - enumerate direct members
        User.Read.All                              - load member account details
        UserAuthenticationMethod.ReadWrite.All      - read and remove methods
      Delegated (-UseDeviceCode): the same three permissions, consented as
      delegated scopes on the app registration, PLUS the signed-in user must
      hold Authentication Administrator or Privileged Authentication
      Administrator (see -UseDeviceCode above).

    KNOWN GRAPH BEHAVIOUR THAT SURFACES AS A LOGGED FAILURE, NOT A SCRIPT BUG
      - A phone method that is the user's current default MFA method cannot be
        deleted until the user (or an admin, via Update-MgUserAuthenticationMethod
        on the sign-in preference) changes their default method. Graph returns a
        4xx for this; the script logs it and moves on to the next method/user.
      - A user cannot have an alternateMobile phone method without a mobile
        phone method. Deleting mobile while alternateMobile remains, or trying
        to leave alternateMobile as the sole phone method, is rejected by Graph.
      - Deleting a method that was already removed by someone else between the
        inventory read and the delete call returns 404; logged as a failure, not
        treated as success, so the audit trail is honest about the race.

    WHY GroupId MUST BE AN OBJECT ID, NOT A DISPLAY NAME
      Display names are not unique in Entra ID. A script that resolves "Finance
      Team" to a group internally could silently act on the wrong group if two
      exist. Requiring the caller to resolve the ID first makes that resolution
      an explicit, reviewable step instead of a hidden one.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'UseExistingConnection')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidatePattern('^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$',
        ErrorMessage = "GroupId must be the group's object ID (a GUID), not its display name. Resolve it first, e.g. (Get-MgGroup -Filter `"displayName eq 'Finance Team'`").Id")]
    [string]$GroupId,

    [Parameter(Mandatory)]
    [ValidateSet('Email', 'Fido2', 'MicrosoftAuthenticator', 'Phone', 'SoftwareOath', 'TemporaryAccessPass', 'WindowsHelloForBusiness')]
    [string[]]$AuthenticationMethodType,

    [Parameter()]
    [string[]]$ExcludeUserPrincipalName = @(),

    [Parameter()]
    [switch]$IncludeGuests,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [string]$CsvPath,

    # --- Connection parameters, shared across every non-default parameter set ---
    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
    [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
    [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
    [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'ClientSecret')]
    [ValidateNotNull()]
    [securestring]$ClientSecret,

    [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
    [ValidatePattern('^[0-9A-Fa-f]{40}$', ErrorMessage = 'A certificate thumbprint must be 40 hexadecimal characters (SHA-1).')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateSubjectName,

    [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
    [ValidateNotNull()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

    [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode
)

Import-Module (Join-Path $PSScriptRoot '..' 'common' 'EntraToolkit.Common.psd1') -Force -ErrorAction Stop

# Removability and the type-specific Remove-Mg* cmdlet for each canonical type
# name returned by the shared Resolve-EntraAuthenticationMethodType (common
# module). Type -> odata.type resolution itself is NOT duplicated here; it lives
# in that one shared function so this script and any other consumer stay in sync.
$script:MethodCatalog = [ordered]@{
    Password                = @{ Removable = $false }
    Email                   = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationEmailMethod'; IdParam = 'EmailAuthenticationMethodId' }
    Fido2                   = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationFido2Method'; IdParam = 'Fido2AuthenticationMethodId' }
    MicrosoftAuthenticator  = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod'; IdParam = 'MicrosoftAuthenticatorAuthenticationMethodId' }
    Phone                   = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationPhoneMethod'; IdParam = 'PhoneAuthenticationMethodId' }
    SoftwareOath            = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationSoftwareOathMethod'; IdParam = 'SoftwareOathAuthenticationMethodId' }
    TemporaryAccessPass     = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationTemporaryAccessPassMethod'; IdParam = 'TemporaryAccessPassAuthenticationMethodId' }
    WindowsHelloForBusiness = @{ Removable = $true; RemoveCmdlet = 'Remove-MgUserAuthenticationWindowsHelloForBusinessMethod'; IdParam = 'WindowsHelloForBusinessAuthenticationMethodId' }
    PlatformCredential      = @{ Removable = $false }
}

# Methods capable of satisfying an MFA requirement on their own. Used only by
# the lockout guard's "would this leave the user on password-only sign-in?" check.
$script:StrongMethodTypes = @('Fido2', 'MicrosoftAuthenticator', 'Phone', 'SoftwareOath', 'WindowsHelloForBusiness')

function Write-ScriptLog {
    <#
        Writes to both the console/PS streams (via the shared Write-EntraLog,
        for formatting consistency with the rest of the toolkit) and to this
        run's plain-text log file, so the audit trail exists on disk even if
        stream output is not captured by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string]$Message,
        [Parameter(Position = 1)] [ValidateSet('Info', 'Warning', 'Error', 'Verbose')] [string]$Level = 'Info'
    )
    Write-EntraLog -Message $Message -Level $Level -Source 'Remove-EntraGroupAuthenticationMethod'
    $line = '[{0}] [{1,-7}] {2}' -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $Level.ToUpperInvariant(), $Message
    Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding utf8
}

function Assert-CertificateStoreAvailable {
    <#
        Mirrors the platform guard in Connect-EntraToolkit.ps1. Duplicated
        rather than imported: that function is a private, unexported helper of
        the common module, and this script intentionally does not take a
        dependency on Connect-EntraToolkit's connection logic (see .DESCRIPTION).
    #>
    [CmdletBinding()]
    param([string]$Hint)

    if ($IsWindows) { return }

    $hasCerts = $false
    try {
        $hasCerts = [bool](Get-ChildItem -Path 'Cert:\CurrentUser\My' -ErrorAction Stop | Select-Object -First 1)
    }
    catch {
        $hasCerts = $false
    }

    if (-not $hasCerts) {
        throw ("Cannot look up a certificate by $Hint on this platform: 'Cert:\CurrentUser\My' is empty or unavailable. " +
               'On Linux/macOS, load the certificate yourself and pass it with -Certificate.')
    }
}

function Connect-ToGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ParameterSetName,
        [string]$ClientId,
        [string]$TenantId,
        [securestring]$ClientSecret,
        [string]$CertificateThumbprint,
        [string]$CertificateSubjectName,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if ($ParameterSetName -eq 'UseExistingConnection') {
        $context = Get-MgContext
        if (-not $context) {
            throw ('No active Microsoft Graph connection and no connection parameters were supplied. ' +
                   'Either run Connect-MgGraph yourself first, or pass -ClientId/-TenantId with -ClientSecret, ' +
                   'a certificate parameter (-CertificateThumbprint / -CertificateSubjectName / -Certificate), or -UseDeviceCode.')
        }
        Write-ScriptLog -Level Info -Message "Reusing existing Graph context (AuthType $($context.AuthType), ClientId $($context.ClientId), Tenant $($context.TenantId))."
        return $context
    }

    $connectParams = @{
        TenantId     = $TenantId
        NoWelcome    = $true
        ErrorAction  = 'Stop'
        ContextScope = 'Process'
    }

    switch ($ParameterSetName) {
        'ClientSecret' {
            $connectParams['ClientSecretCredential'] = [System.Management.Automation.PSCredential]::new($ClientId, $ClientSecret)
            Write-ScriptLog -Level Info -Message "Authenticating app $ClientId against tenant $TenantId with a client secret."
        }
        'CertificateThumbprint' {
            Assert-CertificateStoreAvailable -Hint "thumbprint $CertificateThumbprint"
            $connectParams['ClientId'] = $ClientId
            $connectParams['CertificateThumbprint'] = $CertificateThumbprint
            Write-ScriptLog -Level Info -Message "Authenticating app $ClientId against tenant $TenantId with certificate thumbprint $CertificateThumbprint."
        }
        'CertificateSubject' {
            Assert-CertificateStoreAvailable -Hint "subject '$CertificateSubjectName'"
            $connectParams['ClientId'] = $ClientId
            $connectParams['CertificateSubjectName'] = $CertificateSubjectName
            Write-ScriptLog -Level Info -Message "Authenticating app $ClientId against tenant $TenantId with certificate subject '$CertificateSubjectName'."
        }
        'CertificateObject' {
            if (-not $Certificate.HasPrivateKey) {
                throw 'The supplied certificate has no private key. Client assertions cannot be signed with a public certificate.'
            }
            if ($Certificate.NotAfter -lt [DateTime]::UtcNow) {
                throw "The supplied certificate expired on $($Certificate.NotAfter.ToString('u'))."
            }
            $connectParams['ClientId'] = $ClientId
            $connectParams['Certificate'] = $Certificate
            Write-ScriptLog -Level Info -Message "Authenticating app $ClientId against tenant $TenantId with a supplied certificate object."
        }
        'DeviceCode' {
            $connectParams['ClientId'] = $ClientId
            $connectParams['UseDeviceCode'] = $true
            $connectParams['Scopes'] = @('Group.Read.All', 'User.Read.All', 'UserAuthenticationMethod.ReadWrite.All')
            Write-ScriptLog -Level Warning -Message ('Device code sign-in is DELEGATED access: the signed-in user needs the Authentication ' +
                'Administrator or Privileged Authentication Administrator Entra role to remove authentication methods from other ' +
                'users - Privileged Authentication Administrator specifically if any target user holds a privileged directory role.')
        }
    }

    try {
        Connect-MgGraph @connectParams
    }
    catch {
        throw "Microsoft Graph connection failed: $($_.Exception.Message)"
    }

    $context = Get-MgContext
    if (-not $context) {
        throw 'Connect-MgGraph reported success but no context is available.'
    }
    Write-ScriptLog -Level Info -Message "Connected to tenant $($context.TenantId) as $($context.ClientId) (AuthType $($context.AuthType))."
    return $context
}

function Assert-RequiredGraphPermission {
    <#
        A local, tolerant equivalent of the common module's Assert-EntraPermission.
        That function throws on anything that is not AppOnly, which would reject
        the -UseDeviceCode (delegated) path this script explicitly supports.
        Each row below is a set of acceptable alternative scopes; at least one
        member of each row must be present.
    #>
    [CmdletBinding()]
    param()

    $context = Get-MgContext
    $granted = @($context.Scopes)

    if ($granted.Count -eq 0) {
        Write-ScriptLog -Level Warning -Message ('The current context reports no permissions, so required scopes could not be verified ' +
            'locally. Proceeding; Microsoft Graph will reject the request if a permission is missing.')
        return
    }

    $grantedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$granted, [System.StringComparer]::OrdinalIgnoreCase)
    $requirementRows = @(
        , @('Group.Read.All', 'GroupMember.Read.All', 'Group.ReadWrite.All')
        , @('User.Read.All', 'User.ReadWrite.All', 'Directory.Read.All')
        , @('UserAuthenticationMethod.ReadWrite.All')
    )

    $missingRows = @($requirementRows | Where-Object { -not ($_ | Where-Object { $grantedSet.Contains($_) }) } | ForEach-Object { $_ -join ' or ' })

    if ($missingRows.Count -gt 0) {
        throw ("Missing required Microsoft Graph permission(s): $($missingRows -join '; '). Granted: $($granted -join ', '). " +
               'Add the permission to the app registration and grant admin consent (or, for -UseDeviceCode, have the signed-in ' +
               'user consent), then reconnect. A cached token does not pick up newly granted permissions.')
    }

    Write-ScriptLog -Level Verbose -Message "Permission check passed. Granted scopes: $($granted -join ', ')."
}

function New-ResultRow {
    <#
        Builds one audit row, appends it to the run-wide $script:allResults list
        (guaranteeing it lands in the CSV export regardless of what the caller
        does with pipeline output), and returns it. 'Inventory' rows are built
        for every existing method on every processed user and are deliberately
        NOT written to the success stream (Out-Null'd at the call site) to keep
        interactive console output readable; they still reach the CSV. Every
        other Action is returned un-suppressed so it flows to the success
        stream, consistent with the toolkit's "objects on stream 1" convention.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Builds an in-memory record only; it never touches Graph, disk, or anything ShouldProcess is meant to gate. The actual destructive Graph call is gated by $PSCmdlet.ShouldProcess in the main script body.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$UserId,
        [Parameter(Mandatory)] [string]$UserPrincipalName,
        [string]$DisplayName,
        [Parameter(Mandatory)] [string]$AuthenticationMethodType,
        [string]$AuthenticationMethodId,
        [Parameter(Mandatory)] [ValidateSet('Inventory', 'WhatIf', 'Removed', 'Failed', 'BlockedByLockoutGuard')] [string]$Action,
        [string]$Detail
    )
    $row = [pscustomobject]@{
        PSTypeName               = 'EntraToolkit.AuthMethodRemovalResult'
        TimestampUtc             = [DateTime]::UtcNow
        GroupId                  = $GroupId
        UserId                   = $UserId
        UserPrincipalName        = $UserPrincipalName
        DisplayName              = $DisplayName
        AuthenticationMethodType = $AuthenticationMethodType
        AuthenticationMethodId   = $AuthenticationMethodId
        Action                   = $Action
        Detail                   = $Detail
    }
    $script:allResults.Add($row)
    return $row
}

# ------------------------------------------------------------------------
# Setup: logging destinations, connection, permissions, group resolution
# ------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$toolkitRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$runTimestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')

if (-not $PSBoundParameters.ContainsKey('LogPath')) {
    $LogPath = Join-Path $toolkitRoot "logs/Remove-EntraGroupAuthenticationMethod_$runTimestamp.log"
}
if (-not $PSBoundParameters.ContainsKey('CsvPath')) {
    $CsvPath = Join-Path $toolkitRoot "out/Remove-EntraGroupAuthenticationMethod_$runTimestamp.csv"
}
$null = New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force
$null = New-Item -ItemType Directory -Path (Split-Path $CsvPath -Parent) -Force
$script:LogFilePath = $LogPath

$AuthenticationMethodType = @($AuthenticationMethodType | Select-Object -Unique)

Write-ScriptLog -Level Info -Message "=== Remove-EntraGroupAuthenticationMethod started. Group $GroupId, Types [$($AuthenticationMethodType -join ', ')], Force=$($Force.IsPresent), IncludeGuests=$($IncludeGuests.IsPresent). Log: $LogPath | CSV: $CsvPath ==="

Connect-ToGraph -ParameterSetName $PSCmdlet.ParameterSetName -ClientId $ClientId -TenantId $TenantId `
    -ClientSecret $ClientSecret -CertificateThumbprint $CertificateThumbprint `
    -CertificateSubjectName $CertificateSubjectName -Certificate $Certificate | Out-Null

Assert-RequiredGraphPermission

try {
    $group = Get-MgGroup -GroupId $GroupId -Property Id, DisplayName -ErrorAction Stop
}
catch {
    throw "Group '$GroupId' could not be retrieved: $($_.Exception.Message)"
}
Write-ScriptLog -Level Info -Message "Target group: '$($group.DisplayName)' ($($group.Id))."

try {
    $members = @(Get-MgGroupMember -GroupId $GroupId -All -ErrorAction Stop)
}
catch {
    throw "Failed to enumerate members of group '$($group.DisplayName)': $($_.Exception.Message)"
}
Write-ScriptLog -Level Info -Message "Retrieved $($members.Count) direct member object(s)."

$excludedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ExcludeUserPrincipalName, [System.StringComparer]::OrdinalIgnoreCase)
$counters = @{ Processed = 0; Removed = 0; Failed = 0; BlockedByGuard = 0; SkippedNonUser = 0; SkippedGuest = 0; Excluded = 0; NothingToRemove = 0 }
$allResults = [System.Collections.Generic.List[object]]::new()

# ------------------------------------------------------------------------
# Per-user processing
# ------------------------------------------------------------------------

foreach ($member in $members) {

    $memberODataType = $member.AdditionalProperties['@odata.type']
    if ($memberODataType -ne '#microsoft.graph.user') {
        Write-ScriptLog -Level Verbose -Message "Skipping non-user member $($member.Id) ($memberODataType)."
        $counters.SkippedNonUser++
        continue
    }

    try {
        $user = Get-MgUser -UserId $member.Id -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType -ErrorAction Stop
    }
    catch {
        Write-ScriptLog -Level Error -Message "Failed to load user $($member.Id): $($_.Exception.Message)"
        $counters.Failed++
        continue
    }

    if ($excludedSet.Contains($user.UserPrincipalName)) {
        Write-ScriptLog -Level Info -Message "Excluded by -ExcludeUserPrincipalName: $($user.UserPrincipalName)."
        $counters.Excluded++
        continue
    }

    $effectiveUserType = if ([string]::IsNullOrWhiteSpace($user.UserType)) { 'Member' } else { $user.UserType }
    if ($effectiveUserType -eq 'Guest' -and -not $IncludeGuests) {
        Write-ScriptLog -Level Info -Message "Skipped guest account $($user.UserPrincipalName) (pass -IncludeGuests to include guests)."
        $counters.SkippedGuest++
        continue
    }

    $counters.Processed++
    Write-ScriptLog -Level Info -Message "--- Processing $($user.UserPrincipalName) (Id $($user.Id), DisplayName '$($user.DisplayName)', AccountEnabled $($user.AccountEnabled), UserType $effectiveUserType) ---"

    try {
        $inventory = @(Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction Stop)
    }
    catch {
        Write-ScriptLog -Level Error -Message "Failed to enumerate authentication methods for $($user.UserPrincipalName): $($_.Exception.Message)"
        $counters.Failed++
        continue
    }

    $resolved = @(foreach ($m in $inventory) {
        [pscustomobject]@{ Method = $m; TypeName = (Resolve-EntraAuthenticationMethodType -AuthenticationMethod $m); Id = $m.Id }
    })

    $inventorySummary = ($resolved | Group-Object TypeName | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
    Write-ScriptLog -Level Info -Message "Current authentication methods for $($user.UserPrincipalName): $inventorySummary"
    foreach ($r in $resolved) {
        Write-ScriptLog -Level Verbose -Message "  - $($r.TypeName) (Id $($r.Id))"
        New-ResultRow -UserId $user.Id -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
            -AuthenticationMethodType $r.TypeName -AuthenticationMethodId $r.Id -Action 'Inventory' | Out-Null
    }

    $targets = @($resolved | Where-Object { $AuthenticationMethodType -contains $_.TypeName })
    if ($targets.Count -eq 0) {
        Write-ScriptLog -Level Info -Message "No targeted method type(s) present for $($user.UserPrincipalName); nothing to remove."
        $counters.NothingToRemove++
        continue
    }

    $targetIds = [System.Collections.Generic.HashSet[string]]::new([string[]]$targets.Id)
    $remainingAfter = @($resolved | Where-Object { -not $targetIds.Contains($_.Id) })
    $wouldBeTotalLockout = ($remainingAfter.Count -eq 0)
    $remainingHasStrongMethod = [bool]($remainingAfter | Where-Object { $script:StrongMethodTypes -contains $_.TypeName })
    $remainingHasPassword = [bool]($remainingAfter | Where-Object { $_.TypeName -eq 'Password' })
    $wouldDropToPasswordOnly = (-not $remainingHasStrongMethod) -and $remainingHasPassword

    if ($wouldBeTotalLockout -or $wouldDropToPasswordOnly) {
        $reason = if ($wouldBeTotalLockout) { 'would remove ALL remaining authentication methods (total lockout)' } else { 'would remove every strong/MFA-capable method, leaving only a password' }
        if (-not $Force) {
            Write-ScriptLog -Level Warning -Message "LOCKOUT GUARD: skipping ALL $($targets.Count) requested removal(s) for $($user.UserPrincipalName) - $reason. Re-run with -Force to override."
            $counters.BlockedByGuard += $targets.Count
            foreach ($t in $targets) {
                New-ResultRow -UserId $user.Id -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                    -AuthenticationMethodType $t.TypeName -AuthenticationMethodId $t.Id -Action 'BlockedByLockoutGuard' -Detail $reason
            }
            continue
        }
        Write-ScriptLog -Level Warning -Message "LOCKOUT GUARD bypassed by -Force for $($user.UserPrincipalName) - $reason."
    }

    foreach ($t in $targets) {
        $catalogEntry = $script:MethodCatalog[$t.TypeName]
        $target = "$($user.UserPrincipalName) [$($t.TypeName) $($t.Id)]"

        if (-not $PSCmdlet.ShouldProcess($target, 'Remove Entra ID authentication method')) {
            Write-ScriptLog -Level Info -Message "WHATIF: would remove $($t.TypeName) (Id $($t.Id)) from $($user.UserPrincipalName)."
            New-ResultRow -UserId $user.Id -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -AuthenticationMethodType $t.TypeName -AuthenticationMethodId $t.Id -Action 'WhatIf'
            continue
        }

        try {
            $removeParams = @{ UserId = $user.Id; ErrorAction = 'Stop' }
            $removeParams[$catalogEntry.IdParam] = $t.Id
            & $catalogEntry.RemoveCmdlet @removeParams
            Write-ScriptLog -Level Info -Message "REMOVED $($t.TypeName) (Id $($t.Id)) from $($user.UserPrincipalName)."
            $counters.Removed++
            New-ResultRow -UserId $user.Id -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -AuthenticationMethodType $t.TypeName -AuthenticationMethodId $t.Id -Action 'Removed'
        }
        catch {
            $msg = $_.Exception.Message
            Write-ScriptLog -Level Error -Message "FAILED to remove $($t.TypeName) (Id $($t.Id)) from $($user.UserPrincipalName): $msg"
            $counters.Failed++
            New-ResultRow -UserId $user.Id -UserPrincipalName $user.UserPrincipalName -DisplayName $user.DisplayName `
                -AuthenticationMethodType $t.TypeName -AuthenticationMethodId $t.Id -Action 'Failed' -Detail $msg
        }
    }
}

# ------------------------------------------------------------------------
# Summary and export
# ------------------------------------------------------------------------

$allResults | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8

Write-ScriptLog -Level Info -Message ("=== SUMMARY - Members: $($members.Count), Processed: $($counters.Processed), Removed: $($counters.Removed), " +
    "Failed: $($counters.Failed), BlockedByLockoutGuard: $($counters.BlockedByGuard), NothingToRemove: $($counters.NothingToRemove), " +
    "SkippedGuest: $($counters.SkippedGuest), SkippedNonUser: $($counters.SkippedNonUser), Excluded: $($counters.Excluded). " +
    "Log: $LogPath | CSV: $CsvPath ===")
