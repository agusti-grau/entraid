function Assert-EntraPermission {
    <#
    .SYNOPSIS
        Verifies that the current Graph context is app-only and carries the
        application permissions a script requires.

    .DESCRIPTION
        Fails fast, with an actionable message, before a script does any work.

        The point is to fail at the top of the script rather than halfway through
        it. A script that enumerates 6.000 users and only then discovers it cannot
        read the property it needs has wasted the operator's time and left a
        partial result on screen that looks like output.

        It is a cheap check, not a guarantee: the authoritative answer always
        comes from Graph rejecting the call. Scripts still validate their own
        results - see the signInActivity guard in Get-EntraInactiveUser.ps1.

        Note on scope verification: for an app-only context, Get-MgContext exposes
        the app roles carried by the token. If that collection is empty (which can
        happen depending on SDK version and how the context was established), this
        function warns rather than throws. Throwing would block legitimate runs on
        a condition we cannot actually confirm; Graph will still reject the call
        with a 403 if the permission is genuinely absent. An unverifiable state is
        reported as unverifiable, not as failure.

    .PARAMETER RequiredScopes
        Application permissions that must all be present, e.g.
        @('User.Read.All','AuditLog.Read.All').

    .PARAMETER Source
        Name of the calling script, used in messages.

    .EXAMPLE
        Assert-EntraPermission -RequiredScopes @('User.Read.All','AuditLog.Read.All')

    .OUTPUTS
        None. Throws on failure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredScopes,

        [Parameter()]
        [string]$Source
    )

    if (-not $PSBoundParameters.ContainsKey('Source')) {
        $caller = (Get-PSCallStack)[1]
        $Source = if ($caller -and $caller.Command) { [System.IO.Path]::GetFileNameWithoutExtension($caller.Command) } else { 'EntraToolkit' }
    }

    $context = Get-MgContext
    if (-not $context) {
        throw ("$Source requires an active Microsoft Graph connection. " +
               'Run Connect-EntraToolkit first (see docs/authentication.md).')
    }

    if ($context.AuthType -ne 'AppOnly') {
        throw ("$Source requires an app-only connection but the current context is '$($context.AuthType)'. " +
               'Delegated permissions depend on the signed-in user and are not reproducible in automation.')
    }

    $granted = @($context.Scopes)

    if ($granted.Count -eq 0) {
        Write-EntraLog -Level Warning -Source $Source -Message (
            'The current context reports no application permissions, so the required scopes (' +
            ($RequiredScopes -join ', ') + ') could not be verified locally. ' +
            'Proceeding; Microsoft Graph will reject the request if a permission is missing.')
        return
    }

    # Ordinal, case-insensitive: Graph scope names are fixed identifiers, not
    # culture-sensitive text.
    $grantedSet = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$granted, [System.StringComparer]::OrdinalIgnoreCase)

    $missing = @($RequiredScopes | Where-Object { -not $grantedSet.Contains($_) })

    if ($missing.Count -gt 0) {
        throw ("$Source is missing required application permission(s): $($missing -join ', '). " +
               "Granted: $($granted -join ', '). " +
               'Add the permission to the app registration and grant admin consent, then reconnect. ' +
               'A cached token does not pick up newly granted permissions.')
    }

    Write-EntraLog -Level Verbose -Source $Source -Message "Permission check passed: $($RequiredScopes -join ', ')."
}
