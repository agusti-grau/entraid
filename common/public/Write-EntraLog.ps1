function Write-EntraLog {
    <#
    .SYNOPSIS
        Writes an operator-facing log line to the appropriate PowerShell stream.

    .DESCRIPTION
        Every toolkit script emits objects on the success stream (stream 1) and
        nothing else. Diagnostics, progress and summaries go through this function
        so they land on a stream that can be redirected or captured independently.

        Why this matters: a script that writes a summary line to the success stream
        corrupts every downstream consumer. 'Get-EntraInactiveUser.ps1 | Export-Csv'
        would produce a CSV whose columns are derived from a string.

        Stream mapping:
          Info    -> Information (stream 6), forced visible (see note below)
          Warning -> Warning     (stream 3), honours $WarningPreference
          Error   -> Error       (stream 2), non-terminating
          Verbose -> Verbose     (stream 4), honours -Verbose

        'Info' uses -InformationAction Continue deliberately. These lines are
        explicit, low-volume operator output (record counts, cut-off dates) that an
        operator is expected to see; leaving them at the default SilentlyContinue
        would make a 12-page enumeration look like a hung prompt. They remain on
        stream 6, so '6>$null' or '6>log.txt' still work.

    .PARAMETER Message
        The text to log.

    .PARAMETER Level
        Severity. Determines the target stream. Defaults to Info.

    .PARAMETER Source
        Name of the calling script or function. Defaults to the caller's name.

    .EXAMPLE
        Write-EntraLog -Message 'Retrieved 6000 users.' -Level Info

    .EXAMPLE
        Write-EntraLog -Message 'Server-side filter active.' -Level Warning -Source 'Get-EntraInactiveUser'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('Info', 'Warning', 'Error', 'Verbose')]
        [string]$Level = 'Info',

        [Parameter()]
        [string]$Source
    )

    if (-not $PSBoundParameters.ContainsKey('Source')) {
        # (Get-PSCallStack)[1] is the immediate caller. Falls back to '<script>'
        # when invoked from an interactive prompt, where Command is a file path.
        $caller = (Get-PSCallStack)[1]
        $Source = if ($caller -and $caller.Command) { [System.IO.Path]::GetFileNameWithoutExtension($caller.Command) } else { 'EntraToolkit' }
    }

    # ISO 8601 UTC. Reports and logs from this toolkit are expected to be attached
    # to tickets and correlated with Entra sign-in logs, which are also UTC.
    $timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $line = '[{0}] [{1,-7}] [{2}] {3}' -f $timestamp, $Level.ToUpperInvariant(), $Source, $Message

    switch ($Level) {
        'Info'    { Write-Information -MessageData $line -InformationAction Continue }
        'Warning' { Write-Warning     -Message     $line }
        'Error'   { Write-Error       -Message     $line -ErrorAction Continue }
        'Verbose' { Write-Verbose     -Message     $line }
    }
}
