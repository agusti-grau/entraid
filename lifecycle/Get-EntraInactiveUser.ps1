#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users

<#
.SYNOPSIS
    Reports Microsoft Entra ID user accounts with no interactive sign-in attempt
    since a given cut-off, plus accounts that have never signed in interactively.

.DESCRIPTION
    Emits one object per reported account on the success stream. It writes no
    files: rendering is the job of reporting/ConvertTo-EntraReport.ps1.

    DEFINITION OF "INACTIVE"
    The classification is based on signInActivity.lastSignInDateTime, which is the
    last interactive sign-in ATTEMPT, successful or failed. A failed attempt proves
    someone is still using the credential, which is exactly what matters when
    deciding whether an account is abandoned.

    The other two timestamps are reported but never drive the decision:
      - lastSuccessfulSignInDateTime only exists since December 2023 and was not
        backfilled, so using it as the criterion would mark long-lived accounts as
        inactive purely because of when Microsoft shipped the field.
      - lastNonInteractiveSignInDateTime covers token refreshes and background
        clients. It is surfaced as HasNonInteractiveActivitySinceCutoff so a
        reviewer can see that a "stale" service-style account is in fact in use.

    WHY NOT THE SIGN-IN LOGS
    /auditLogs/signIns is retained for 7 or 30 days depending on licence. At a
    90-day threshold, the absence of a log entry is indistinguishable from
    retention expiry, so the question cannot be answered from logs at all.
    signInActivity lives on the user object and is retained as long as the user.

.PARAMETER InactiveDays
    Number of days without an interactive sign-in attempt before an account is
    classified as Stale. Default 90.

.PARAMETER UserType
    Which user types to evaluate. Default Member.

    Guests are excluded by default not because they are low risk, but because
    remediating a guest is a different process with a different owner (the
    internal sponsor, B2B lifecycle, the partner organisation). Mixing both
    populations into one CSV produces a list nobody can action. Pass -UserType
    Guest to review them as their own campaign.

.PARAMETER ExcludeUserPrincipalName
    UPNs to exclude from classification, typically break-glass accounts.

    Break-glass accounts are designed never to sign in, so they sort to the very
    top of any inactivity report. They are reported with Category 'Excluded'
    rather than dropped: an audit report that silently omits rows is worse than
    one that flags them.

.PARAMETER IncludeActive
    Also emit accounts classified as Active. Off by default.

.PARAMETER UseServerSideFilter
    Push the date comparison to Microsoft Graph instead of filtering locally.

    NOT the default, and the reason is the most important thing in this script.
    In OData, a comparison against null is never true, so
    "signInActivity/lastSignInDateTime le <cutoff>" silently drops every account
    that has no signInActivity at all - accounts that never signed in, or last
    signed in before April 2020. That is the NeverSignedIn population: the oldest
    and most likely abandoned accounts in the tenant. The fast query returns a
    tidy result set and hides the worst findings.

    The same trap rules out the obvious optimisation of pre-filtering on
    createdDateTime: that property is null for users created before June 2018 and
    for on-premises users synced before then, i.e. the oldest accounts again.

    Graph also forbids combining a signInActivity filter with any other filterable
    property, so -UserType would still have to be applied locally regardless.

    At 6.000 users the full enumeration is ~12 requests. Correctness wins at that
    scale; the switch exists for tenants where it does not, and warns about what
    it is hiding.

.EXAMPLE
    Connect-EntraToolkit -ClientId $clientId -TenantId $tenantId -CertificateThumbprint $thumbprint
    ./lifecycle/Get-EntraInactiveUser.ps1 -InactiveDays 90

.EXAMPLE
    ./lifecycle/Get-EntraInactiveUser.ps1 -InactiveDays 180 -ExcludeUserPrincipalName 'break-glass-01@contoso.example','break-glass-02@contoso.example' |
        Sort-Object Category, DaysSinceLastSignIn -Descending |
        Export-Csv -Path ./out/inactive-users.csv -NoTypeInformation

.NOTES
    REQUIRED APPLICATION PERMISSIONS (read-only app registration)
      User.Read.All      - read user objects
      AuditLog.Read.All  - required for signInActivity, even though it is a
                           property of the user object and not a log query

    Directory.Read.All is NOT requested, to keep the read-only app at least
    privilege. Be aware of the documented trade-off: Microsoft states that an app
    holding only AuditLog.Read.All may hit "Neither tenant is B2C or tenant
    doesn't have premium license" INTERMITTENTLY, because Directory.Read.All is
    what allows Entra ID to read tenant licensing information when it is not
    already cached. See the troubleshooting note:
    https://learn.microsoft.com/troubleshoot/entra/entra-id/users-groups-entra-apis/b2c-or-tenant-premium-license-sign-in-activities

    This toolkit accepts that trade-off deliberately: an occasional, loud,
    retryable failure is preferable to granting directory-wide read access to a
    reporting job. If your environment cannot tolerate the intermittency, add
    Directory.Read.All to the read-only app and to RequiredScopes below, and
    record the decision - do not discover it during an incident.

    LICENSING
      signInActivity requires Microsoft Entra ID P1 or P2. Without it the property
      is not populated and this script aborts rather than reporting a dead tenant.

    API BEHAVIOUR AND LIMITS
      - signInActivity must be requested explicitly via $select; it is never
        returned by default.
      - Selecting or filtering signInActivity caps the page size at 500 instead of
        the usual 999, so paging is mandatory at any realistic tenant size.
      - signInActivity supports $filter (eq, ne, not, ge, le) but NOT in
        combination with any other filterable property.
      - Sign-in data surfaces within about 6 hours and the property can take up to
        24 hours to update. Irrelevant at a 90-day threshold; do not reuse this
        script for short windows without accounting for it.
#>
[CmdletBinding()]
[OutputType('EntraToolkit.InactiveUserReport')]
param(
    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [Parameter()]
    [ValidateSet('Member', 'Guest', 'All')]
    [string]$UserType = 'Member',

    [Parameter()]
    [string[]]$ExcludeUserPrincipalName = @(),

    [Parameter()]
    [switch]$IncludeActive,

    [Parameter()]
    [switch]$UseServerSideFilter
)

begin {
    $ErrorActionPreference = 'Stop'

    Import-Module (Join-Path $PSScriptRoot '..' 'common' 'EntraToolkit.Common.psd1') -Force -ErrorAction Stop

    # Fail before doing any work. A missing AuditLog.Read.All does not merely
    # cause an error, it changes the meaning of the result.
    Assert-EntraPermission -RequiredScopes @('User.Read.All', 'AuditLog.Read.All')

    function ConvertTo-UtcDateTime {
        <#
            Graph returns DateTimeOffset values; the SDK surfaces them as DateTime
            whose Kind is not guaranteed. Normalising through DateTimeOffset keeps
            every comparison and every DaysSince value on the same clock. Any local
            /UTC skew is hours at most, which is immaterial against a 90-day
            threshold, but stable output beats output that shifts with the host.
        #>
        param($Value)
        if ($null -eq $Value) { return $null }
        return ([datetimeoffset]$Value).UtcDateTime
    }
}

process {
    $evaluatedAtUtc = [DateTime]::UtcNow
    $cutoffUtc = $evaluatedAtUtc.AddDays(-$InactiveDays)

    Write-EntraLog -Level Info -Message (
        "Evaluating inactivity with a $InactiveDays-day threshold (cut-off $($cutoffUtc.ToString('u')), UserType $UserType).")

    # $select is mandatory here: signInActivity, createdDateTime and
    # onPremisesSyncEnabled are all "requires $select to retrieve" properties.
    # onPremisesSyncEnabled is not cosmetic - it decides WHERE an account gets
    # remediated. A synced account must be disabled in on-premises AD; disabling
    # it in Entra ID is either rejected or silently reverted on the next sync
    # cycle. Disable-EntraLeaver.ps1 consumes this same column.
    $properties = @(
        'id'
        'userPrincipalName'
        'displayName'
        'accountEnabled'
        'userType'
        'createdDateTime'
        'onPremisesSyncEnabled'
        'signInActivity'
    )

    $queryParams = @{
        All         = $true
        Property    = $properties
        ErrorAction = 'Stop'

        # Set explicitly rather than letting the service silently downgrade a
        # larger request: the query then says what it will actually do.
        PageSize    = 500
    }

    if ($UseServerSideFilter) {
        $queryParams['Filter'] = "signInActivity/lastSignInDateTime le $($cutoffUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        Write-EntraLog -Level Warning -Message (
            'Server-side filtering is enabled. Accounts with no signInActivity at all cannot satisfy an ' +
            'OData date comparison, so the NeverSignedIn category will be empty and those accounts - ' +
            'typically the oldest in the tenant - will NOT appear in this report.')
    }

    Write-EntraLog -Level Verbose -Message "Enumerating users: `$select=$($properties -join ',')."

    try {
        $users = @(Get-MgUser @queryParams)
    }
    catch {
        # Two distinct causes produce a failure here, and they need different fixes:
        #
        #  - "Neither tenant is B2C or tenant doesn't have premium license":
        #    either the tenant genuinely has no Entra ID P1/P2, or the app holds
        #    AuditLog.Read.All without Directory.Read.All and Entra ID could not
        #    read cached licensing information. The second case is INTERMITTENT,
        #    so a retry of the same command may well succeed. That is a symptom,
        #    not a fix.
        #
        #  - A plain 403: consent was never granted, or it was granted after the
        #    current token was issued. A cached token never gains permissions.
        $message = $_.Exception.Message
        if ($message -match "premium license|B2C") {
            throw ("Microsoft Graph refused the signInActivity query: $message " +
                   'Either this tenant has no Entra ID P1/P2 licence, or the app holds AuditLog.Read.All without ' +
                   'Directory.Read.All, in which case the error is intermittent by design. See the .NOTES section.')
        }
        throw ("Failed to enumerate users: $message " +
               'Verify that User.Read.All and AuditLog.Read.All are granted to the app registration with admin consent, ' +
               'and reconnect so a new token is issued.')
    }

    Write-EntraLog -Level Info -Message "Retrieved $($users.Count) user object(s) from Microsoft Graph."

    if ($users.Count -eq 0) {
        Write-EntraLog -Level Warning -Message 'No users returned; nothing to classify.'
        return
    }

    # Defence in depth, not the primary control.
    #
    # The documented behaviour for a missing licence or an ineffective
    # AuditLog.Read.All is an HTTP error, which the catch block above already
    # handles. This guard covers the residual case: a 200 response in which the
    # property is absent for every single user.
    #
    # It is kept because the consequence of that state is uniquely bad. Absent
    # signInActivity is indistinguishable, field by field, from "never signed in",
    # so an unguarded run would classify all 6.000 accounts as NeverSignedIn and
    # produce a plausible-looking list of accounts to disable. A report that is
    # confidently wrong is more dangerous than no report, so this refuses to emit.
    #
    # Skipped under -UseServerSideFilter, where every returned user matched a
    # signInActivity comparison by construction.
    if (-not $UseServerSideFilter) {
        $withActivity = @($users | Where-Object { $null -ne $_.SignInActivity }).Count
        if ($withActivity -eq 0) {
            throw ('Microsoft Graph returned ' + $users.Count + ' users and none of them carry signInActivity data. ' +
                   'This is an environmental problem - licensing or permissions - not a tenant in which nobody has ' +
                   'ever signed in. Aborting instead of reporting every account as never signed in.')
        }
        Write-EntraLog -Level Verbose -Message "$withActivity of $($users.Count) users have signInActivity data."
    }

    # Ordinal, case-insensitive: a UPN is an identifier, and Entra ID treats it
    # case-insensitively. Culture-aware comparison would be wrong here (the
    # Turkish dotless-i problem is the classic example).
    $excluded = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$ExcludeUserPrincipalName, [System.StringComparer]::OrdinalIgnoreCase)

    $counters = @{ Stale = 0; NeverSignedIn = 0; Active = 0; Excluded = 0; Skipped = 0 }

    foreach ($user in $users) {

        # userType is filtered locally. It does support $filter server-side, but
        # the value is null on some accounts and OData null semantics would drop
        # them; filtering for nulls as well requires advanced query parameters
        # (ConsistencyLevel: eventual plus $count), which interacts badly enough
        # with a signInActivity $select to not be worth the risk for 6.000 objects.
        # Null userType is treated as Member, which is how Entra ID treats it.
        $effectiveType = if ([string]::IsNullOrWhiteSpace($user.UserType)) { 'Member' } else { $user.UserType }
        if ($UserType -ne 'All' -and $effectiveType -ne $UserType) {
            $counters.Skipped++
            continue
        }

        $activity           = $user.SignInActivity
        $lastInteractive    = ConvertTo-UtcDateTime $activity.LastSignInDateTime
        $lastNonInteractive = ConvertTo-UtcDateTime $activity.LastNonInteractiveSignInDateTime
        $lastSuccessful     = ConvertTo-UtcDateTime $activity.LastSuccessfulSignInDateTime
        $createdUtc         = ConvertTo-UtcDateTime $user.CreatedDateTime

        # Null when createdDateTime is null - never 0. Zero would read as
        # "created today" and invert the meaning of the oldest accounts.
        $accountAgeDays = if ($null -ne $createdUtc) { [int][Math]::Floor(($evaluatedAtUtc - $createdUtc).TotalDays) } else { $null }
        $daysSince      = if ($null -ne $lastInteractive) { [int][Math]::Floor(($evaluatedAtUtc - $lastInteractive).TotalDays) } else { $null }

        # Note the case where signInActivity EXISTS but lastSignInDateTime is null:
        # an account with only non-interactive activity, e.g. a service-style
        # account that only ever refreshes tokens. Under the chosen definition it
        # is NeverSignedIn, and HasNonInteractiveActivitySinceCutoff is what stops
        # a reviewer from disabling something that is demonstrably in use.
        $category = if ($excluded.Contains($user.UserPrincipalName)) { 'Excluded' }
                    elseif ($null -eq $lastInteractive)              { 'NeverSignedIn' }
                    elseif ($lastInteractive -le $cutoffUtc)         { 'Stale' }
                    else                                            { 'Active' }

        $counters[$category]++

        if ($category -eq 'Active' -and -not $IncludeActive) { continue }

        [pscustomobject]@{
            PSTypeName                           = 'EntraToolkit.InactiveUserReport'
            UserPrincipalName                    = $user.UserPrincipalName
            DisplayName                          = $user.DisplayName
            Category                             = $category
            AccountEnabled                       = $user.AccountEnabled
            UserType                             = $effectiveType
            OnPremisesSyncEnabled                = [bool]$user.OnPremisesSyncEnabled
            DaysSinceLastSignIn                  = $daysSince
            LastSignInDateTime                   = $lastInteractive
            LastNonInteractiveSignInDateTime     = $lastNonInteractive
            LastSuccessfulSignInDateTime         = $lastSuccessful
            HasNonInteractiveActivitySinceCutoff = ($null -ne $lastNonInteractive -and $lastNonInteractive -gt $cutoffUtc)
            CreatedDateTime                      = $createdUtc
            AccountAgeDays                       = $accountAgeDays
            Id                                   = $user.Id

            # Carried on every row on purpose. This CSV ends up attached to a
            # ticket; months later, a row without its threshold and evaluation
            # time is an unsourced assertion.
            CutoffUtc                            = $cutoffUtc
            EvaluatedAtUtc                       = $evaluatedAtUtc
        }
    }

    # Summary goes to the information stream. On the success stream it would
    # become a row in the caller's CSV.
    Write-EntraLog -Level Info -Message (
        "Classification complete - Stale: $($counters.Stale), NeverSignedIn: $($counters.NeverSignedIn), " +
        "Active: $($counters.Active), Excluded: $($counters.Excluded), SkippedByUserType: $($counters.Skipped).")
}
