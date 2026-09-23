#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Reports every Microsoft Entra ID authentication method registered to users
    in the tenant.

.DESCRIPTION
    Emits one object per (user, authentication method) pair on the success
    stream. It writes no files: like Get-EntraInactiveUser.ps1, rendering is the
    caller's job (pipe to Export-Csv, Group-Object, Where-Object, and so on).

    WHY THIS LOOPS PER USER
    Microsoft Graph has no tenant-wide "list every registered authentication
    method" endpoint. The closest thing, the reporting API behind
    reports/authenticationMethods/userRegistrationDetails, is an aggregated
    capability summary per user (isMfaRegistered, isMfaCapable, methodsRegistered
    as a list of type names, ...); it does not return the actual method objects
    - their IDs, phone numbers, device display names - which is what "enumerates
    all Authentication Methods" asks for here. Getting real method instances
    requires Get-MgUserAuthenticationMethod per user, exactly like
    Remove-EntraGroupAuthenticationMethod.ps1 does for a single group, just
    swept across the whole tenant. This is inherently O(number of users) Graph
    calls; -ProgressEveryUsers exists so a multi-thousand-user run still gives
    the operator a heartbeat, and Assert-EntraPermission fails fast rather than
    burning through thousands of calls before discovering a missing scope.

    A USER WITH ZERO METHODS STILL GETS A ROW
    When no -AuthenticationMethodType filter is given, a user who has zero
    registered authentication methods (a broken account, a just-provisioned one
    that never completed registration) still emits exactly one row with
    AuthenticationMethodType 'None', rather than being silently absent from the
    report. An audit report that silently omits accounts is worse than one that
    flags them - the same principle Get-EntraInactiveUser.ps1 applies to
    break-glass accounts (Category 'Excluded' rather than dropped). This
    sentinel row is suppressed when -AuthenticationMethodType narrows the
    report to specific types, because "this user has no Phone method" is not
    the same finding as "this user has no authentication methods at all".

    THE Detail COLUMN
    Authentication method types expose very different properties (a phone
    number, a FIDO2 key's model, a Temporary Access Pass's usability window). A
    hardcoded per-type switch would need updating every time Graph adds a
    property, and would break silently on an SDK version where a property moved
    to AdditionalProperties. Detail instead checks a fixed list of the most
    useful candidate property names generically and joins whichever ones are
    actually present as "Name=Value" pairs - see Get-AuthenticationMethodDetail.

    CONNECTION
    This script does not connect to Microsoft Graph itself. It is read-only and
    fits the "read-only app" role Connect-EntraToolkit's own documentation
    describes (User.Read.All, AuditLog.Read.All, ... - no write scopes). Connect
    first with Connect-EntraToolkit, exactly as Get-EntraInactiveUser.ps1
    expects; scripts are meant to be chained in one session.

.PARAMETER UserType
    Which user types to evaluate. Default Member. Filtering happens locally,
    not via server-side $filter, for the same reason Get-EntraInactiveUser.ps1
    filters locally: userType is null on some accounts, OData null semantics
    would silently drop them from a server-side filter, and a null userType is
    treated as Member (matching how Entra ID treats it) rather than excluded.

.PARAMETER UserPrincipalName
    Scope the report to exactly these UPNs instead of sweeping the tenant (or a
    UserType slice of it). Useful for a targeted spot-check. When supplied,
    -UserType is ignored - an explicit list is exactly what it says.

.PARAMETER AuthenticationMethodType
    Restrict the report to specific method types. Default: every type Graph
    returns, including Password (always present) and PlatformCredential.
    Suppresses the "zero methods" sentinel row (see .DESCRIPTION).

.PARAMETER ExcludeUserPrincipalName
    UPNs to skip entirely (e.g. break-glass accounts), logged as excluded
    rather than silently dropped.

.PARAMETER ProgressEveryUsers
    Log a progress heartbeat every N users evaluated. Default 250.

.EXAMPLE
    Connect-EntraToolkit -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint
    Get-EntraAuthenticationMethodReport.ps1 |
        Export-Csv -Path ./out/auth-methods.csv -NoTypeInformation

.EXAMPLE
    # Only users with no strong (MFA-capable) method - a common compliance question.
    $strong = 'Fido2', 'MicrosoftAuthenticator', 'Phone', 'SoftwareOath', 'WindowsHelloForBusiness'
    $rows = Get-EntraAuthenticationMethodReport.ps1
    $rows | Group-Object UserPrincipalName | Where-Object {
        -not ($_.Group.AuthenticationMethodType | Where-Object { $strong -contains $_ })
    } | ForEach-Object { $_.Group[0].UserPrincipalName }

.EXAMPLE
    Get-EntraAuthenticationMethodReport.ps1 -UserPrincipalName 'alice@contoso.example', 'bob@contoso.example'

.EXAMPLE
    Get-EntraAuthenticationMethodReport.ps1 -AuthenticationMethodType Fido2, WindowsHelloForBusiness -UserType All

.NOTES
    REQUIRED APPLICATION PERMISSIONS (read-only app registration)
      User.Read.All                    - load account details
      UserAuthenticationMethod.Read.All - read authentication methods

    SENSITIVE OUTPUT
      Rows can include phone numbers and device display names. Handle exported
      CSVs as you would any other PII export - the toolkit's own .gitignore
      already keeps out/ and *.csv out of source control for this reason.
#>
[CmdletBinding()]
[OutputType('EntraToolkit.UserAuthenticationMethodReport')]
param(
    [Parameter()]
    [ValidateSet('Member', 'Guest', 'All')]
    [string]$UserType = 'Member',

    [Parameter()]
    [string[]]$UserPrincipalName,

    [Parameter()]
    [ValidateSet('Password', 'Email', 'Fido2', 'MicrosoftAuthenticator', 'Phone', 'SoftwareOath', 'TemporaryAccessPass', 'WindowsHelloForBusiness', 'PlatformCredential')]
    [string[]]$AuthenticationMethodType,

    [Parameter()]
    [string[]]$ExcludeUserPrincipalName = @(),

    [Parameter()]
    [ValidateRange(1, 10000)]
    [int]$ProgressEveryUsers = 250
)

begin {
    $ErrorActionPreference = 'Stop'

    Import-Module (Join-Path $PSScriptRoot '..' 'common' 'EntraToolkit.Common.psd1') -Force -ErrorAction Stop

    # Fail before any per-user work: a missing scope discovered after 3,000
    # Graph calls has wasted the operator's time for nothing.
    Assert-EntraPermission -RequiredScopes @('User.Read.All', 'UserAuthenticationMethod.Read.All')

    function Get-AuthenticationMethodDetail {
        <#
            Best-effort, type-agnostic extraction of whichever of a fixed set of
            useful property names the given method object actually has. See the
            "THE Detail COLUMN" note in the script's own .DESCRIPTION for why
            this is generic rather than a per-type switch.
        #>
        [CmdletBinding()]
        param([Parameter(Mandatory)] $Method)

        $candidateProperties = @(
            'DisplayName', 'PhoneNumber', 'PhoneType', 'EmailAddress', 'Model',
            'AaGuid', 'DeviceTag', 'IsUsable', 'MethodUsabilityReason',
            'CreatedDateTime', 'KeyStrength'
        )
        $parts = foreach ($name in $candidateProperties) {
            $value = $null
            if ($Method.PSObject.Properties.Name -contains $name) {
                $value = $Method.$name
            }
            elseif ($Method.AdditionalProperties -and $Method.AdditionalProperties.ContainsKey($name)) {
                $value = $Method.AdditionalProperties[$name]
            }
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                "$name=$value"
            }
        }
        return ($parts -join '; ')
    }
}

process {
    $evaluatedAtUtc = [DateTime]::UtcNow
    $properties = @('Id', 'UserPrincipalName', 'DisplayName', 'AccountEnabled', 'UserType')

    if ($UserPrincipalName -and $UserPrincipalName.Count -gt 0) {
        Write-EntraLog -Level Info -Message "Resolving $($UserPrincipalName.Count) explicitly named user(s); -UserType is ignored."
        $users = @(
            foreach ($upn in ($UserPrincipalName | Select-Object -Unique)) {
                try {
                    Get-MgUser -UserId $upn -Property $properties -ErrorAction Stop
                }
                catch {
                    Write-EntraLog -Level Warning -Message "Could not retrieve user '$upn': $($_.Exception.Message)"
                }
            }
        )
    }
    else {
        Write-EntraLog -Level Info -Message "Enumerating tenant users (UserType filter: $UserType)."
        $allUsers = @(Get-MgUser -All -Property $properties -PageSize 999 -ErrorAction Stop)

        # Local filtering, not server-side $filter - see .PARAMETER UserType for why
        # (mirrors Get-EntraInactiveUser.ps1's established, already-reasoned convention).
        $users = if ($UserType -eq 'All') {
            $allUsers
        }
        else {
            @($allUsers | Where-Object {
                $effectiveType = if ([string]::IsNullOrWhiteSpace($_.UserType)) { 'Member' } else { $_.UserType }
                $effectiveType -eq $UserType
            })
        }
    }

    Write-EntraLog -Level Info -Message "$($users.Count) user(s) in scope."

    $excludedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$ExcludeUserPrincipalName, [System.StringComparer]::OrdinalIgnoreCase)
    $typeFilterSet = if ($AuthenticationMethodType) {
        [System.Collections.Generic.HashSet[string]]::new([string[]]($AuthenticationMethodType | Select-Object -Unique), [System.StringComparer]::OrdinalIgnoreCase)
    }
    else {
        $null
    }

    $counters = @{ Evaluated = 0; Excluded = 0; Failed = 0; RowsEmitted = 0; UsersWithNoMethods = 0 }

    foreach ($user in $users) {

        if ($excludedSet.Contains($user.UserPrincipalName)) {
            $counters.Excluded++
            Write-EntraLog -Level Verbose -Message "Excluded by -ExcludeUserPrincipalName: $($user.UserPrincipalName)."
            continue
        }

        $counters.Evaluated++
        if ($counters.Evaluated % $ProgressEveryUsers -eq 0) {
            Write-EntraLog -Level Info -Message "Progress: $($counters.Evaluated) / $($users.Count) users evaluated."
        }

        $effectiveUserType = if ([string]::IsNullOrWhiteSpace($user.UserType)) { 'Member' } else { $user.UserType }

        try {
            $methods = @(Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction Stop)
        }
        catch {
            $counters.Failed++
            Write-EntraLog -Level Warning -Message "Failed to enumerate authentication methods for $($user.UserPrincipalName): $($_.Exception.Message)"
            $counters.RowsEmitted++
            [pscustomobject]@{
                PSTypeName               = 'EntraToolkit.UserAuthenticationMethodReport'
                UserId                   = $user.Id
                UserPrincipalName        = $user.UserPrincipalName
                DisplayName              = $user.DisplayName
                AccountEnabled           = $user.AccountEnabled
                UserType                 = $effectiveUserType
                AuthenticationMethodType = 'Error'
                AuthenticationMethodId   = $null
                Detail                   = $_.Exception.Message
                EvaluatedAtUtc           = $evaluatedAtUtc
            }
            continue
        }

        $resolved = @(foreach ($m in $methods) {
            [pscustomobject]@{
                TypeName = Resolve-EntraAuthenticationMethodType -AuthenticationMethod $m
                Id       = $m.Id
                Raw      = $m
            }
        })

        if ($typeFilterSet) {
            $resolved = @($resolved | Where-Object { $typeFilterSet.Contains($_.TypeName) })
        }

        if ($resolved.Count -eq 0) {
            if (-not $typeFilterSet) {
                # Genuinely zero methods with no filter applied - flag it, don't drop it.
                $counters.UsersWithNoMethods++
                $counters.RowsEmitted++
                [pscustomobject]@{
                    PSTypeName               = 'EntraToolkit.UserAuthenticationMethodReport'
                    UserId                   = $user.Id
                    UserPrincipalName        = $user.UserPrincipalName
                    DisplayName              = $user.DisplayName
                    AccountEnabled           = $user.AccountEnabled
                    UserType                 = $effectiveUserType
                    AuthenticationMethodType = 'None'
                    AuthenticationMethodId   = $null
                    Detail                   = $null
                    EvaluatedAtUtc           = $evaluatedAtUtc
                }
            }
            continue
        }

        foreach ($r in $resolved) {
            $counters.RowsEmitted++
            [pscustomobject]@{
                PSTypeName               = 'EntraToolkit.UserAuthenticationMethodReport'
                UserId                   = $user.Id
                UserPrincipalName        = $user.UserPrincipalName
                DisplayName              = $user.DisplayName
                AccountEnabled           = $user.AccountEnabled
                UserType                 = $effectiveUserType
                AuthenticationMethodType = $r.TypeName
                AuthenticationMethodId   = $r.Id
                Detail                   = Get-AuthenticationMethodDetail -Method $r.Raw
                EvaluatedAtUtc           = $evaluatedAtUtc
            }
        }
    }

    Write-EntraLog -Level Info -Message (
        "Complete - Users evaluated: $($counters.Evaluated), Excluded: $($counters.Excluded), " +
        "Failed to enumerate: $($counters.Failed), Users with zero methods: $($counters.UsersWithNoMethods), " +
        "Rows emitted: $($counters.RowsEmitted)."
    )
}
