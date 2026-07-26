<#
Get-WinEventLogs.ps1
获取 Application / System / Security 日志中最新的指定条数。
极简风格：原样输出、不抛异常、末尾 RETURN_CODE。

Return codes:
  0 = 成功获取日志并输出
  1 = Get-EventLog 成功但无结果
  2 = Get-EventLog 执行失败
#>
#调用方法：.\Get-EventsLog.ps1 logname count
#输出参考：
# PS C:\Users\Administrator\Desktop> Get-EventLog -LogName Security -Newest 5

#    Index Time          EntryType   Source                 InstanceID Message
#    ----- ----          ---------   ------                 ---------- -------
#    30863 10月 17 19:13 SuccessA... Microsoft-Windows...         4798 已枚举用户的本地组成员身份。...
#    30862 10月 17 19:13 SuccessA... Microsoft-Windows...         4798 已枚举用户的本地组成员身份。...
#    30861 10月 17 19:13 SuccessA... Microsoft-Windows...         4798 已枚举用户的本地组成员身份。...
#    30860 10月 17 19:12 SuccessA... Microsoft-Windows...         4799 已枚举启用了安全机制的本地组成员身份。...
#    30859 10月 17 19:12 SuccessA... Microsoft-Windows...         4799 已枚举启用了安全机制的本地组成员身份。...


# PS C:\Users\Administrator\Desktop> Get-EventLog -LogName application -Newest 5

#    Index Time          EntryType   Source                 InstanceID Message
#    ----- ----          ---------   ------                 ---------- -------
#     5022 10月 17 19:04 Information Software Protecti...   1073758208 安排软件保护服务在 2025-10-17T13:55:58Z 时重新启动成功。原因: RulesEngine。
#     5021 10月 17 19:04 Information Software Protecti...   3221241866 脱机下级迁移成功。
#     5020 10月 17 18:48 Information Software Protecti...   1073758208 安排软件保护服务在 2025-10-17T13:55:45Z 时重新启动成功。原因: RulesEngine。
#     5019 10月 17 18:48 Information Software Protecti...   3221241866 脱机下级迁移成功。
#     5018 10月 17 18:35 Information Software Protecti...   1073758208 安排软件保护服务在 2025-10-17T13:55:59Z 时重新启动成功。原因: RulesEngine。

[CmdletBinding()]
param(
    # 日志类型：Application / System / Security
    [Parameter(Mandatory = $true)]
    # [ValidateSet("Application", "System", "Security")]
    [string]$LogName,

    # 获取的最新日志条数
    [Parameter(Mandatory = $true)]
    [int]$Count
)

$ErrorActionPreference = 'Continue'
$overall = 0

Write-Output ("Run at: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Output ("---Run: Get-EventLog -LogName {0} -Newest {1}---" -f $LogName, $Count)

try {
    $logs = Get-EventLog -LogName $LogName -Newest $Count 
    if ($null -ne $logs -and ($logs | Measure-Object).Count -gt 0) {
        $logs | Select-Object TimeGenerated, EntryType, Source, EventID, Message |
        Format-Table -AutoSize | Out-String | Write-Output
        $overall = 0
    } else {
        Write-Output ("[WARN] No logs found for {0}." -f $LogName)
        $overall = 1
    }
}
catch {
    Write-Output ("[ERROR] Get-EventLog failed: {0}" -f $_.Exception.Message)
    $overall = 2
}

$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
