<#
.SYNOPSIS
Exports external accounts found in Microsoft Teams Unified Audit Log events.
.DESCRIPTION
Searches Microsoft Purview Unified Audit Log for Microsoft Teams events.
The script:

* Searches a configurable number of days.
* Splits the period into smaller time windows.
* Uses ReturnLargeSet pagination.
* Handles HTTP 429 and TooManyRequests responses.
* Detects throttling returned as either a warning or an exception.
* Uses exponential backoff with random jitter.
* detects and ignores duplicate records.
* Excludes configured internal domains.
* Avoids recursive parsing of AuditData.
* Produces detailed, user-summary, and domain-summary CSV files.

IMPORTANT:
UserId identifies the account that generated the audited Teams action.
This report is therefore an inventory of external accounts observed
generating Teams audit events during the selected period.
.REQUIREMENTS

* ExchangeOnlineManagement module
* Connection to Exchange Online
* Permission to run Search-UnifiedAuditLog

.EXAMPLE
.\Export-TeamsExternalUsers.ps1
.EXAMPLE
.\Export-TeamsExternalUsers.ps1 -Days 30 -WindowHours 6
.EXAMPLE
.\Export-TeamsExternalUsers.ps1 `
    -Days 30 `
    -InternalDomains @(
        "hotelbeds.com",
        "hbxgroup.com",
        "hotelbeds365.onmicrosoft.com"
    )
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$Days = 30,
    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$WindowHours = 6,
    [Parameter()]
    [ValidateRange(100, 5000)]
    [int]$ResultSize = 5000,
    [Parameter()]
    [ValidateRange(1, 20)]
    [int]$MaxThrottleRetries = 12,
    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$BaseRetrySeconds = 15,
    [Parameter()]
    [ValidateRange(30, 900)]
    [int]$MaximumRetrySeconds = 300,
    [Parameter()]
    [ValidateRange(0, 60)]
    [int]$DelayBetweenRequestsSeconds = 3,
    [Parameter()]
    [string[]]$InternalDomains = @(
        "hotelbeds.com",
        "hbxgroup.com",
        "hotelbeds365.onmicrosoft.com"
    ),
    [Parameter()]
    [string]$OutputDirectory = "."
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
#region Helper functions
function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter()]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO" {
            Write-Host "[$Timestamp] [INFO] $Message" -ForegroundColor Cyan
        }
        "SUCCESS" {
            Write-Host "[$Timestamp] [SUCCESS] $Message" -ForegroundColor Green
        }
        "WARNING" {
            Write-Host "[$Timestamp] [WARNING] $Message" -ForegroundColor Yellow
        }
        "ERROR" {
            Write-Host "[$Timestamp] [ERROR] $Message" -ForegroundColor Red
        }
    }
}
function Get-RetryDelay {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RetryNumber,
        [Parameter(Mandatory)]
        [int]$BaseSeconds,
        [Parameter(Mandatory)]
        [int]$MaximumSeconds
    )
    $ExponentialDelay = [math]::Pow(2, ($RetryNumber - 1)) * $BaseSeconds
    $BoundedDelay = [math]::Min($ExponentialDelay, $MaximumSeconds)
    $JitterMaximum = [math]::Max(2, [math]::Floor($BoundedDelay * 0.20))
    $Jitter = Get-Random -Minimum 1 -Maximum ($JitterMaximum + 1)
    return [math]::Min(
        ($BoundedDelay + $Jitter),
        $MaximumSeconds
    )
}
function Test-IsThrottleMessage {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Message
    )
    if ([string]::IsNullOrWhiteSpace($Message)) {
        return $false
    }
    $ThrottlePatterns = @(
        "TooManyRequests",
        "Too Many Requests",
        "HTTP 429",
        "status code 429",
        "throttl",
        "temporarily unavailable",
        "server busy"
    )
    foreach ($Pattern in $ThrottlePatterns) {
        if ($Message -match $Pattern) {
            return $true
        }
    }
    return $false
}
function Get-AuditRecordIdentifier {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditRecord
    )
    if (
        $AuditRecord.PSObject.Properties.Name -contains "Identity" -and
        -not [string]::IsNullOrWhiteSpace([string]$AuditRecord.Identity)
    ) {
        return [string]$AuditRecord.Identity
    }
    try {
        $AuditData = $AuditRecord.AuditData | ConvertFrom-Json -ErrorAction Stop
        if (
            $AuditData.PSObject.Properties.Name -contains "Id" -and
            -not [string]::IsNullOrWhiteSpace([string]$AuditData.Id)
        ) {
            return [string]$AuditData.Id
        }
    }
    catch {
        # The calling code will separately record JSON parsing failures.
    }
    return (
        "{0}|{1}|{2}|{3}" -f
        $AuditRecord.CreationDate,
        $AuditRecord.UserIds,
        $AuditRecord.Operations,
        $AuditRecord.AuditData.GetHashCode()
    )
}
function Get-UnifiedAuditLogWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [datetime]$StartDate,
        [Parameter(Mandatory)]
        [datetime]$EndDate,
        [Parameter(Mandatory)]
        [int]$PageSize,
        [Parameter(Mandatory)]
        [int]$MaximumThrottleRetries,
        [Parameter(Mandatory)]
        [int]$InitialRetrySeconds,
        [Parameter(Mandatory)]
        [int]$MaximumRetryDelaySeconds,
        [Parameter(Mandatory)]
        [int]$RequestDelaySeconds
    )
    $SessionId = [guid]::NewGuid().ToString()
    $WindowRecords = [System.Collections.Generic.List[object]]::new()
    $SeenRecordIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $ThrottleRetry = 0
    $PageNumber = 0
    $ConsecutiveDuplicatePages = 0
    while ($true) {
        $BatchWarnings = @()
        $Batch = $null
        $RequestSucceeded = $false
        try {
            $Batch = @(
                Search-UnifiedAuditLog `
                    -StartDate $StartDate `
                    -EndDate $EndDate `
                    -RecordType MicrosoftTeams `
                    -SessionId $SessionId `
                    -SessionCommand ReturnLargeSet `
                    -ResultSize $PageSize `
                    -WarningVariable BatchWarnings `
                    -WarningAction Continue `
                    -ErrorAction Stop
            )
            $WarningText = ($BatchWarnings | ForEach-Object {
                $_.ToString()
            }) -join " | "
            if (Test-IsThrottleMessage -Message $WarningText) {
                throw [System.Net.Http.HttpRequestException]::new(
                    "Purview throttling warning detected: $WarningText"
                )
            }
            $RequestSucceeded = $true
        }
        catch {
            $ExceptionMessage = $_.Exception.Message
            if (Test-IsThrottleMessage -Message $ExceptionMessage) {
                $ThrottleRetry++
                if ($ThrottleRetry -gt $MaximumThrottleRetries) {
                    throw (
                        "Purview remained throttled after {0} retries for window " +
                        "{1:u} to {2:u}. Last error: {3}"
                    ) -f (
                        $MaximumThrottleRetries,
                        $StartDate,
                        $EndDate,
                        $ExceptionMessage
                    )
                }
                $RetryDelay = Get-RetryDelay `
                    -RetryNumber $ThrottleRetry `
                    -BaseSeconds $InitialRetrySeconds `
                    -MaximumSeconds $MaximumRetryDelaySeconds
                Write-Status `
                    -Level "WARNING" `
                    -Message (
                        ("Purview throttled the request for {0:u} to {1:u}. " +
                        "Retry {2}/{3} after {4} seconds.") -f
                        $StartDate,
                        $EndDate,
                        $ThrottleRetry,
                        $MaximumThrottleRetries,
                        $RetryDelay
                    )
                Start-Sleep -Seconds $RetryDelay
                continue
            }
            throw
        }
        if (-not $RequestSucceeded) {
            continue
        }
        $ThrottleRetry = 0
        if ($Batch.Count -eq 0) {
            Write-Status -Message (
                "Window complete. No additional records returned for {0:u} to {1:u}." -f
                $StartDate,
                $EndDate
            )
            break
        }
        $PageNumber++
        $NewRecordsOnPage = 0
        foreach ($Record in $Batch) {
            $RecordId = Get-AuditRecordIdentifier -AuditRecord $Record
            if ($SeenRecordIds.Add($RecordId)) {
                $WindowRecords.Add($Record)
                $NewRecordsOnPage++
            }
        }
        Write-Status -Message (
            ("Window {0:u} to {1:u}, page {2}: received {3:N0}, " +
            "new {4:N0}, window total {5:N0}.") -f
            $StartDate,
            $EndDate,
            $PageNumber,
            $Batch.Count,
            $NewRecordsOnPage,
            $WindowRecords.Count
        )
        if ($NewRecordsOnPage -eq 0) {
            $ConsecutiveDuplicatePages++
            Write-Status `
                -Level "WARNING" `
                -Message (
                    ("The current page contained no new records. " +
                    "Duplicate page count: {0}/2.") -f $ConsecutiveDuplicatePages
                )
            if ($ConsecutiveDuplicatePages -ge 2) {
                Write-Status `
                    -Level "WARNING" `
                    -Message (
                        "Stopping this window after two consecutive duplicate pages " +
                        "to prevent an infinite loop."
                    )
                break
            }
        }
        else {
            $ConsecutiveDuplicatePages = 0
        }
        if ($Batch.Count -lt $PageSize) {
            Write-Status -Message (
                "Window complete. Final page contained fewer than {0:N0} records." -f $PageSize
            )
            break
        }
        if ($RequestDelaySeconds -gt 0) {
            Start-Sleep -Seconds $RequestDelaySeconds
        }
    }
    return $WindowRecords.ToArray()
}
#endregion Helper functions
#region Validation and preparation
$SearchCommand = Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue
if ($null -eq $SearchCommand) {
    throw @"
Search-UnifiedAuditLog is not available.
Install or import the ExchangeOnlineManagement module and connect first:
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline
Then run this script again.
"@
}
if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = New-Item `
        -Path $OutputDirectory `
        -ItemType Directory `
        -Force
}
$ResolvedOutputDirectory = (
    Resolve-Path -LiteralPath $OutputDirectory
).Path
$NormalizedInternalDomains = @(
    $InternalDomains |
    ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_)) {
            $_.Trim().TrimStart("@").ToLowerInvariant()
        }
    } |
    Sort-Object -Unique
)
if ($NormalizedInternalDomains.Count -eq 0) {
    throw "At least one internal domain must be configured."
}
$ExecutionTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$DetailedCsvPath = Join-Path `
    -Path $ResolvedOutputDirectory `
    -ChildPath "TeamsExternalEvents_${Days}Days_$ExecutionTimestamp.csv"
$UserCsvPath = Join-Path `
    -Path $ResolvedOutputDirectory `
    -ChildPath "TeamsExternalUsers_${Days}Days_$ExecutionTimestamp.csv"
$DomainCsvPath = Join-Path `
    -Path $ResolvedOutputDirectory `
    -ChildPath "TeamsExternalDomains_${Days}Days_$ExecutionTimestamp.csv"
$ErrorCsvPath = Join-Path `
    -Path $ResolvedOutputDirectory `
    -ChildPath "TeamsAuditParseErrors_${Days}Days_$ExecutionTimestamp.csv"
$RunStartDate = (Get-Date).AddDays(-$Days)
$RunEndDate = Get-Date
$ExternalEvents = [System.Collections.Generic.List[object]]::new()
$ParseErrors = [System.Collections.Generic.List[object]]::new()
Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host " Microsoft Teams external-account audit report" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Status -Message "Search start: $($RunStartDate.ToString('u'))"
Write-Status -Message "Search end: $($RunEndDate.ToString('u'))"
Write-Status -Message "Window size: $WindowHours hour(s)"
Write-Status -Message "Page size: $ResultSize"
Write-Status -Message (
    "Internal domains: {0}" -f ($NormalizedInternalDomains -join ", ")
)
#endregion Validation and preparation
#region Search and process each time window
$CurrentWindowStart = $RunStartDate
$WindowNumber = 0
$TotalAuditRecordsProcessed = 0
while ($CurrentWindowStart -lt $RunEndDate) {
    $WindowNumber++
    $CurrentWindowEnd = $CurrentWindowStart.AddHours($WindowHours)
    if ($CurrentWindowEnd -gt $RunEndDate) {
        $CurrentWindowEnd = $RunEndDate
    }
    Write-Host ""
    Write-Status -Message (
        "Starting window {0}: {1:u} to {2:u}" -f
        $WindowNumber,
        $CurrentWindowStart,
        $CurrentWindowEnd
    )
    $WindowAuditRecords = @(
        Get-UnifiedAuditLogWindow `
            -StartDate $CurrentWindowStart `
            -EndDate $CurrentWindowEnd `
            -PageSize $ResultSize `
            -MaximumThrottleRetries $MaxThrottleRetries `
            -InitialRetrySeconds $BaseRetrySeconds `
            -MaximumRetryDelaySeconds $MaximumRetrySeconds `
            -RequestDelaySeconds $DelayBetweenRequestsSeconds
    )
    $TotalAuditRecordsProcessed += $WindowAuditRecords.Count
    foreach ($Log in $WindowAuditRecords) {
        try {
            $Data = $Log.AuditData | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $ParseErrors.Add(
                [PSCustomObject]@{
                    CreationDate = $Log.CreationDate
                    Identity     = $Log.Identity
                    Error        = $_.Exception.Message
                }
            )
            continue
        }
        $UserId = [string]$Data.UserId
        if ([string]::IsNullOrWhiteSpace($UserId)) {
            continue
        }
        $UserId = $UserId.Trim()
        if ($UserId -notmatch "^[^@\s]+@[^@\s]+$") {
            continue
        }
        $Domain = ($UserId -split "@", 2)[1].Trim().ToLowerInvariant()
        if ($NormalizedInternalDomains -contains $Domain) {
            continue
        }
        $CreationDate = $null
        if ($Data.PSObject.Properties.Name -contains "CreationTime") {
            $CreationDate = $Data.CreationTime
        }
        elseif ($Log.PSObject.Properties.Name -contains "CreationDate") {
            $CreationDate = $Log.CreationDate
        }
        $Operation = $null
        if ($Data.PSObject.Properties.Name -contains "Operation") {
            $Operation = [string]$Data.Operation
        }
        elseif ($Log.PSObject.Properties.Name -contains "Operations") {
            $Operation = [string]$Log.Operations
        }
        $CommunicationType = $null
        if ($Data.PSObject.Properties.Name -contains "CommunicationType") {
            $CommunicationType = [string]$Data.CommunicationType
        }
        $ResourceTenantId = $null
        if ($Data.PSObject.Properties.Name -contains "ResourceTenantId") {
            $ResourceTenantId = [string]$Data.ResourceTenantId
        }
        $ChatThreadId = $null
        if ($Data.PSObject.Properties.Name -contains "ChatThreadId") {
            $ChatThreadId = [string]$Data.ChatThreadId
        }
        $AuditRecordId = $null
        if ($Data.PSObject.Properties.Name -contains "Id") {
            $AuditRecordId = [string]$Data.Id
        }
        elseif ($Log.PSObject.Properties.Name -contains "Identity") {
            $AuditRecordId = [string]$Log.Identity
        }
        $ExternalEvents.Add(
            [PSCustomObject]@{
                CreationDate      = $CreationDate
                ExternalUser      = $UserId.ToLowerInvariant()
                ExternalDomain    = $Domain
                Operation         = $Operation
                CommunicationType = $CommunicationType
                ResourceTenantId  = $ResourceTenantId
                ChatThreadId      = $ChatThreadId
                AuditRecordId     = $AuditRecordId
            }
        )
    }
    Write-Status -Message (
        ("Window {0} processed. Audit records: {1:N0}. " +
        "External events accumulated: {2:N0}.") -f
        $WindowNumber,
        $WindowAuditRecords.Count,
        $ExternalEvents.Count
    )
    $WindowAuditRecords = $null
    $CurrentWindowStart = $CurrentWindowEnd
    if (
        $CurrentWindowStart -lt $RunEndDate -and
        $DelayBetweenRequestsSeconds -gt 0
    ) {
        Start-Sleep -Seconds $DelayBetweenRequestsSeconds
    }
}
#endregion Search and process each time window
#region Deduplicate and summarize
Write-Host ""
Write-Status -Message "Deduplicating external audit events."
$UniqueExternalEvents = @(
    $ExternalEvents |
    Sort-Object `
        AuditRecordId,
        CreationDate,
        ExternalUser,
        Operation `
        -Unique
)
Write-Status -Message (
    "Unique external events after deduplication: {0:N0}" -f $UniqueExternalEvents.Count
)
$UserSummary = @(
    $UniqueExternalEvents |
    Group-Object -Property ExternalUser |
    ForEach-Object {
        $UserEvents = @(
            $_.Group |
            Sort-Object -Property CreationDate
        )
        $Operations = @(
            $UserEvents.Operation |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
        )
        $CommunicationTypes = @(
            $UserEvents.CommunicationType |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
        )
        [PSCustomObject]@{
            ExternalUser       = $_.Name
            ExternalDomain     = $UserEvents[0].ExternalDomain
            ActivityCount      = $UserEvents.Count
            FirstSeen          = $UserEvents[0].CreationDate
            LastSeen           = $UserEvents[-1].CreationDate
            Operations         = $Operations -join "; "
            CommunicationTypes = $CommunicationTypes -join "; "
        }
    } |
    Sort-Object `
        @{ Expression = "ActivityCount"; Descending = $true },
        @{ Expression = "ExternalUser"; Descending = $false }
)
$DomainSummary = @(
    $UserSummary |
    Group-Object -Property ExternalDomain |
    ForEach-Object {
        $ActivityTotal = (
            $_.Group.ActivityCount |
            Measure-Object -Sum
        ).Sum
        $FirstSeen = (
            $_.Group.FirstSeen |
            Measure-Object -Minimum
        ).Minimum
        $LastSeen = (
            $_.Group.LastSeen |
            Measure-Object -Maximum
        ).Maximum
        [PSCustomObject]@{
            ExternalDomain = $_.Name
            ExternalUsers  = $_.Count
            ActivityCount  = $ActivityTotal
            FirstSeen      = $FirstSeen
            LastSeen       = $LastSeen
        }
    } |
    Sort-Object `
        @{ Expression = "ActivityCount"; Descending = $true },
        @{ Expression = "ExternalDomain"; Descending = $false }
)
#endregion Deduplicate and summarize
#region Export results
$UniqueExternalEvents |
Export-Csv `
    -LiteralPath $DetailedCsvPath `
    -NoTypeInformation `
    -Encoding UTF8
$UserSummary |
Export-Csv `
    -LiteralPath $UserCsvPath `
    -NoTypeInformation `
    -Encoding UTF8
$DomainSummary |
Export-Csv `
    -LiteralPath $DomainCsvPath `
    -NoTypeInformation `
    -Encoding UTF8
if ($ParseErrors.Count -gt 0) {
    $ParseErrors |
    Export-Csv `
        -LiteralPath $ErrorCsvPath `
        -NoTypeInformation `
        -Encoding UTF8
}
#endregion Export results
#region Final status
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Report completed" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Status `
    -Level "SUCCESS" `
    -Message ("Audit records processed: {0:N0}" -f $TotalAuditRecordsProcessed)
Write-Status `
    -Level "SUCCESS" `
    -Message ("Unique external events: {0:N0}" -f $UniqueExternalEvents.Count)
Write-Status `
    -Level "SUCCESS" `
    -Message ("Unique external users: {0:N0}" -f $UserSummary.Count)
Write-Status `
    -Level "SUCCESS" `
    -Message ("Unique external domains: {0:N0}" -f $DomainSummary.Count)
Write-Host ""
Write-Host "Detailed events : $DetailedCsvPath"
Write-Host "User summary    : $UserCsvPath"
Write-Host "Domain summary  : $DomainCsvPath"
if ($ParseErrors.Count -gt 0) {
    Write-Host "Parsing errors  : $ErrorCsvPath"
    Write-Status `
        -Level "WARNING" `
        -Message ("{0:N0} record(s) could not be parsed. Review the parsing-error CSV." -f $ParseErrors.Count)
}
else {
    Write-Status `
        -Level "SUCCESS" `
        -Message "No AuditData parsing errors were detected."
}
#endregion Final status
