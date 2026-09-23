function Resolve-EntraAuthenticationMethodType {
    <#
    .SYNOPSIS
        Resolves a Microsoft Graph authenticationMethod object to a stable,
        human-readable type name.

    .DESCRIPTION
        authenticationMethod objects deserialize to different .NET representations
        depending on the Microsoft.Graph SDK version and module (v1.0 vs beta): a
        concrete typed class in some cases (e.g. MicrosoftGraphFido2Authentication
        Method), a generic object with the odata short name tucked into
        AdditionalProperties['@odata.type'] in others. Every script in this toolkit
        that enumerates authentication methods needs the same answer to "what type
        is this", so that resolution lives here once instead of drifting across
        multiple copies.

        Resolution order:
          1. AdditionalProperties['@odata.type'], when present - the most direct
             signal, used when the SDK did not have a concrete class for the type.
          2. The .NET type name, with the 'MicrosoftGraph' prefix stripped and the
             first letter lower-cased (e.g. 'MicrosoftGraphFido2Authentication
             Method' -> 'fido2AuthenticationMethod'), which reconstructs the exact
             odata short name because that is how the SDK names its generated
             classes.

        A method type Microsoft adds to Graph in the future, which this function
        does not yet recognize, resolves to an explicit "Unknown (<odata short
        name>)" value instead of throwing - callers should treat that as a signal
        to update this function, not as an error to suppress.

    .PARAMETER AuthenticationMethod
        An object returned by Get-MgUserAuthenticationMethod or one of the
        type-specific Get-MgUserAuthentication*Method cmdlets. Accepts pipeline
        input so a caller can do `$methods | Resolve-EntraAuthenticationMethodType`.

    .EXAMPLE
        Get-MgUserAuthenticationMethod -UserId $userId -All |
            ForEach-Object {
                [pscustomobject]@{
                    Type = Resolve-EntraAuthenticationMethodType -AuthenticationMethod $_
                    Id   = $_.Id
                }
            }

    .OUTPUTS
        System.String - one of: Password, Email, Fido2, MicrosoftAuthenticator,
        Phone, SoftwareOath, TemporaryAccessPass, WindowsHelloForBusiness,
        PlatformCredential, or "Unknown (<odata short name>)".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$AuthenticationMethod
    )

    process {
        # Keys are the canonical names every consumer in this toolkit uses; values
        # are the exact odata short name (no '#microsoft.graph.' prefix) Microsoft
        # Graph uses for that type. Add a future method type here, not per-caller.
        $knownTypes = [ordered]@{
            Password                = 'passwordAuthenticationMethod'
            Email                   = 'emailAuthenticationMethod'
            Fido2                   = 'fido2AuthenticationMethod'
            MicrosoftAuthenticator  = 'microsoftAuthenticatorAuthenticationMethod'
            Phone                   = 'phoneAuthenticationMethod'
            SoftwareOath            = 'softwareOathAuthenticationMethod'
            TemporaryAccessPass     = 'temporaryAccessPassAuthenticationMethod'
            WindowsHelloForBusiness = 'windowsHelloForBusinessAuthenticationMethod'
            PlatformCredential      = 'platformCredentialAuthenticationMethod'
        }

        $odataType = $null
        if ($AuthenticationMethod.AdditionalProperties -and $AuthenticationMethod.AdditionalProperties.ContainsKey('@odata.type')) {
            $odataType = ($AuthenticationMethod.AdditionalProperties['@odata.type'] -as [string]) -replace '^#microsoft\.graph\.', ''
        }
        if (-not $odataType) {
            $typeName = $AuthenticationMethod.GetType().Name -replace '^MicrosoftGraph', ''
            if ($typeName.Length -gt 0) {
                $odataType = [char]::ToLowerInvariant($typeName[0]) + $typeName.Substring(1)
            }
        }

        foreach ($name in $knownTypes.Keys) {
            if ($knownTypes[$name] -eq $odataType) { return $name }
        }
        return "Unknown ($odataType)"
    }
}
