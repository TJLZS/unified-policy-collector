[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()
$OutputEncoding = [Text.UTF8Encoding]::new()

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$gpoDirectory = Join-Path $OutputDirectory 'System-Audit'
$updateDirectory = Join-Path $OutputDirectory 'Protect-Update'
New-Item -ItemType Directory -Path $gpoDirectory, $updateDirectory -Force | Out-Null

$collectors = @(
    @{ Name = 'Get-BitLockerStatus'; Relative = 'Encryption\Get-BitLockerStatus.ps1'; Arguments = @() },
    @{ Name = 'Get-CertificateStores'; Relative = 'Encryption\Get-CertificateStores.ps1'; Arguments = @() },
    @{ Name = 'Get-LAPSOperationalLogs'; Relative = 'Encryption\Get-LAPSOperationalLogs.ps1'; Arguments = @('-Count', 50) },
    @{ Name = 'Get-LAPSSettings'; Relative = 'Encryption\Get-LAPSSettings.ps1'; Arguments = @() },
    @{ Name = 'Get-EventsLog-Application'; Relative = 'Log\Get-EventsLog.ps1'; Arguments = @('-LogName', 'Application', '-Count', 100) },
    @{ Name = 'Get-EventsLog-System'; Relative = 'Log\Get-EventsLog.ps1'; Arguments = @('-LogName', 'System', '-Count', 100) },
    @{ Name = 'Get-EventsLog-Security'; Relative = 'Log\Get-EventsLog.ps1'; Arguments = @('-LogName', 'Security', '-Count', 100) },
    @{ Name = 'Get-FirewallRules'; Relative = 'Protect-Update\Get-FirewallRules.ps1'; Arguments = @() },
    @{ Name = 'Get-InstalledPatches'; Relative = 'Protect-Update\Get-InstalledPatches.ps1'; Arguments = @() },
    @{ Name = 'Get-UpdateLog'; Relative = 'Protect-Update\Get-UpdateLog.ps1'; Arguments = @('-OutputPath', (Join-Path $updateDirectory 'WindowsUpdate.log')) },
    @{ Name = 'Get-WindowsDefenderStatus'; Relative = 'Protect-Update\Get-WindowsDefenderStatus.ps1'; Arguments = @() },
    @{ Name = 'Get-WindowsUpdateRegistry'; Relative = 'Protect-Update\Get-WindowsUpdateRegistry.ps1'; Arguments = @() },
    @{ Name = 'Get-AuditPolicy'; Relative = 'System-Audit\Get-AuditPolicy.ps1'; Arguments = @() },
    @{ Name = 'Get-GPOs'; Relative = 'System-Audit\Get-GPOs.ps1'; Arguments = @(
        '-GpoReportPath', (Join-Path $gpoDirectory 'AllGPOs.html'),
        '-GpResultHtmlPath', (Join-Path $gpoDirectory 'GpResult.html')
    ) },
    @{ Name = 'Get-ServicesSecurity'; Relative = 'System-Audit\Get-ServicesSecurity.ps1'; Arguments = @() },
    @{ Name = 'Get-ACLonPath'; Relative = 'Users-Permissions\Get-ACLonPath.ps1'; Arguments = @('-Path', 'C:\') },
    @{ Name = 'Get-LocalUserAccounts'; Relative = 'Users-Permissions\Get-LocalUserAccounts.ps1'; Arguments = @() },
    @{ Name = 'Get-PasswordPolicy-Local'; Relative = 'Users-Permissions\Get-PasswordPolicy.ps1'; Arguments = @('-Scope', 'Local') },
    @{ Name = 'Get-PasswordPolicy-Domain'; Relative = 'Users-Permissions\Get-PasswordPolicy.ps1'; Arguments = @('-Scope', 'Domain') },
    @{ Name = 'Get-UACSettings'; Relative = 'Users-Permissions\Get-UACSettings.ps1'; Arguments = @() }
)

$results = [System.Collections.Generic.List[object]]::new()

foreach ($collector in $collectors) {
    $scriptPath = Join-Path $PSScriptRoot $collector.Relative
    $category = Split-Path $collector.Relative -Parent
    $categoryDirectory = Join-Path $OutputDirectory $category
    New-Item -ItemType Directory -Path $categoryDirectory -Force | Out-Null
    $outputPath = Join-Path $categoryDirectory ($collector.Name + '.txt')

    $started = Get-Date
    $returnCode = 1
    $message = ''
    try {
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            throw "采集脚本不存在: $scriptPath"
        }
        $global:LASTEXITCODE = 0
        $scriptArguments = @($collector.Arguments)
        $captured = @(& $scriptPath @scriptArguments 2>&1)
        $captured | Out-File -LiteralPath $outputPath -Encoding utf8 -Width 4096

        $returnLine = $captured |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -match '^RETURN_CODE=-?\d+\s*$' } |
            Select-Object -Last 1
        if ($returnLine -match '^RETURN_CODE=(-?\d+)') {
            $returnCode = [int]$Matches[1]
        }
        elseif ($LASTEXITCODE -is [int]) {
            $returnCode = [int]$LASTEXITCODE
        }
        else {
            $returnCode = 0
        }
        if ($returnCode -ne 0) {
            $message = "脚本返回非零状态码 $returnCode"
        }
    }
    catch {
        $returnCode = 1
        $message = $_.Exception.Message
        ("[WRAPPER_ERROR] " + $message) |
            Out-File -LiteralPath $outputPath -Encoding utf8 -Append
    }

    $results.Add([ordered]@{
        name = $collector.Name
        success = ($returnCode -eq 0)
        return_code = $returnCode
        message = $message
        duration_seconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 3)
        output_file = $outputPath.Substring($OutputDirectory.Length).TrimStart('\')
    })
}

$manifestPath = Join-Path $OutputDirectory 'collection_manifest.json'
ConvertTo-Json -InputObject @($results) -Depth 4 |
    Out-File -LiteralPath $manifestPath -Encoding utf8 -Width 4096

$failed = @($results | Where-Object { -not $_.success }).Count
Write-Output ("采集完成：成功 {0}，失败 {1}" -f ($results.Count - $failed), $failed)
exit 0
