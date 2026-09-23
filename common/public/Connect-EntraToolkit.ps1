function Connect-EntraToolkit {
    <#
    .SYNOPSIS
        Establishes an app-only Microsoft Graph connection for the toolkit.

    .DESCRIPTION
        Wraps Connect-MgGraph with the only two authentication models this toolkit
        supports: a confidential client using a certificate, or a managed identity.

        There is deliberately NO client-secret parameter. A secret is a bearer
        string: anyone who reads it (from a script, a pipeline variable, a CI log,
        a crash dump, a screen share) can replay it from anywhere in the world. A
        certificate requires possession of the private key, the assertion is signed
        per request, and on a properly configured host the private key is
        non-exportable. If a caller wants secret-based auth, they must call
        Connect-MgGraph themselves and own that decision explicitly.

        Two app registrations are expected (see docs/permissions.md):
          - a read-only app  (User.Read.All, AuditLog.Read.All, Policy.Read.All, ...)
          - a read-write app (User.ReadWrite.All, Group.ReadWrite.All, ...)
        Report and audit scripts must be run with the read-only app. This function
        does not enforce which app you pass; Assert-EntraPermission enforces that
        the token actually carries the scopes a given script needs, which is the
        check that matters at runtime.

    .PARAMETER ClientId
        Application (client) ID of the app registration. For a user-assigned
        managed identity, the client ID of that identity.

    .PARAMETER TenantId
        Directory (tenant) ID or verified domain name.

    .PARAMETER CertificateThumbprint
        Thumbprint of a certificate present in the local certificate store.

    .PARAMETER CertificateSubjectName
        Subject name of a certificate present in the local certificate store.

    .PARAMETER Certificate
        An already-loaded X509Certificate2 object that carries a private key.

        This is the practical option on Linux and macOS, where the PowerShell
        Cert: provider is not a real certificate store. How the object is
        obtained (Key Vault, a PFX on disk, a PKCS#11 device) is the caller's
        responsibility: the toolkit never handles a certificate password.

    .PARAMETER Identity
        Authenticate with the managed identity of the host (Azure Automation,
        an Azure VM, a container). Combine with -ClientId for a user-assigned
        identity; omit -ClientId for the system-assigned one.

    .PARAMETER Force
        Reconnect even if an equivalent app-only context is already active.

    .EXAMPLE
        Connect-EntraToolkit -ClientId '00000000-0000-0000-0000-000000000000' `
                             -TenantId '11111111-1111-1111-1111-111111111111' `
                             -CertificateThumbprint 'A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4'

    .EXAMPLE
        # Linux/macOS: load the certificate yourself, then pass the object.
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('/secure/path/toolkit.pfx', $pwd)
        Connect-EntraToolkit -ClientId $clientId -TenantId $tenantId -Certificate $cert

    .EXAMPLE
        # Inside Azure Automation with a system-assigned managed identity.
        Connect-EntraToolkit -Identity

    .OUTPUTS
        Microsoft.Graph.PowerShell.Authentication.AuthContext
    #>
    [CmdletBinding(DefaultParameterSetName = 'CertificateThumbprint')]
    [OutputType([Microsoft.Graph.PowerShell.Authentication.AuthContext])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
        [Parameter(ParameterSetName = 'ManagedIdentity')]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
        [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = 'CertificateThumbprint')]
        [ValidatePattern('^[0-9A-Fa-f]{40}$', ErrorMessage = 'A certificate thumbprint must be 40 hexadecimal characters (SHA-1).')]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = 'CertificateSubject')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateSubjectName,

        [Parameter(Mandatory, ParameterSetName = 'CertificateObject')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')]
        [switch]$Identity,

        [Parameter()]
        [switch]$Force
    )

    # Reuse an existing, equivalent connection. Scripts are meant to be chained
    # (inventory -> review -> report) in one session; reconnecting per script
    # burns time and produces a fresh token for no reason.
    $existing = Get-MgContext
    if ($existing -and -not $Force) {
        $sameApp    = (-not $ClientId) -or ($existing.ClientId -eq $ClientId)
        $sameTenant = (-not $TenantId) -or ($existing.TenantId -eq $TenantId)
        if ($existing.AuthType -eq 'AppOnly' -and $sameApp -and $sameTenant) {
            Write-EntraLog -Message "Reusing existing app-only context (ClientId $($existing.ClientId))." -Level Verbose
            return $existing
        }
    }

    $connectParams = @{
        NoWelcome    = $true
        ErrorAction  = 'Stop'

        # Keep the token cache in this process only. The default would otherwise
        # allow a token acquired by a scheduled job to be picked up by whatever
        # runs next in the same user profile.
        ContextScope = 'Process'
    }

    switch ($PSCmdlet.ParameterSetName) {
        'ManagedIdentity' {
            # Pass the switch value through rather than a literal $true: the
            # parameter is the caller's stated intent, not a constant.
            $connectParams['Identity'] = $Identity.IsPresent
            if ($ClientId) { $connectParams['ClientId'] = $ClientId }
            Write-EntraLog -Message 'Authenticating with managed identity.' -Level Verbose
        }
        default {
            $connectParams['ClientId'] = $ClientId
            $connectParams['TenantId'] = $TenantId

            switch ($PSCmdlet.ParameterSetName) {
                'CertificateThumbprint' {
                    Assert-LocalCertificateStoreUsable -Hint "thumbprint $CertificateThumbprint"
                    $connectParams['CertificateThumbprint'] = $CertificateThumbprint
                }
                'CertificateSubject' {
                    Assert-LocalCertificateStoreUsable -Hint "subject '$CertificateSubjectName'"
                    $connectParams['CertificateSubjectName'] = $CertificateSubjectName
                }
                'CertificateObject' {
                    if (-not $Certificate.HasPrivateKey) {
                        throw 'The supplied certificate has no private key. Client assertions cannot be signed with a public certificate.'
                    }
                    if ($Certificate.NotAfter -lt [DateTime]::UtcNow) {
                        throw "The supplied certificate expired on $($Certificate.NotAfter.ToString('u'))."
                    }
                    $connectParams['Certificate'] = $Certificate
                }
            }
            Write-EntraLog -Message "Authenticating app $ClientId against tenant $TenantId with a certificate." -Level Verbose
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

    # Guard against a delegated context sneaking in. Every script in this toolkit
    # assumes app-only semantics: no signed-in user, no consent prompts, and
    # permissions that do not depend on who is at the keyboard.
    if ($context.AuthType -ne 'AppOnly') {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        throw "Expected an app-only context but got '$($context.AuthType)'. The toolkit does not support delegated authentication."
    }

    Write-EntraLog -Message "Connected app-only to tenant $($context.TenantId) as app $($context.ClientId)." -Level Info
    return $context
}

function Assert-LocalCertificateStoreUsable {
    <#
        Private helper. On Linux and macOS the Cert: provider exists but is not
        backed by a usable personal store, so -CertificateThumbprint and
        -CertificateSubjectName fail with an error that does not explain why.
        Catch it here with an actionable message instead.
    #>
    [CmdletBinding()]
    param([string]$Hint)

    if ($IsWindows) { return }

    $storePath = 'Cert:\CurrentUser\My'
    $hasCerts = $false
    try {
        $hasCerts = [bool](Get-ChildItem -Path $storePath -ErrorAction Stop | Select-Object -First 1)
    }
    catch {
        $hasCerts = $false
    }

    if (-not $hasCerts) {
        throw ("Cannot look up a certificate by $Hint on this platform: '$storePath' is empty or unavailable. " +
               'On Linux/macOS, load the certificate yourself and pass it with -Certificate.')
    }
}
