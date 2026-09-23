@{
    RootModule        = 'EntraToolkit.Common.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '1dca47ee-f108-4785-a6ad-7ecc9c290d00'
    Author            = 'entra-identity-toolkit contributors'
    CompanyName       = ''
    Copyright         = ''
    Description       = 'Shared authentication, permission validation and logging primitives for the Entra Identity Toolkit.'

    PowerShellVersion = '7.4'

    # Only the authentication module is a hard dependency of this module.
    # Workload modules (Microsoft.Graph.Users, .Groups, .Identity.SignIns, ...) are
    # declared by the individual scripts that need them, via #Requires. Importing the
    # whole Microsoft.Graph meta-module would pull in ~40 sub-modules and add tens of
    # seconds to every run for no benefit.
    RequiredModules   = @('Microsoft.Graph.Authentication')

    FunctionsToExport = @(
        'Connect-EntraToolkit'
        'Assert-EntraPermission'
        'Write-EntraLog'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags       = @('Entra', 'EntraID', 'MicrosoftGraph', 'IAM', 'Identity')
            LicenseUri = ''
            ProjectUri = ''
        }
    }
}
