<#
Get-ServicesStatus.ps1
逐个输出服务与状态；极简：原样输出、不抛异常、末尾 RETURN_CODE

Return codes:
  0 = 至少一条来源成功逐项输出
  1 = Get-CimInstance 返回空
  2 = Get-CimInstance 失败
#>
#调用方法：Get-ServicesSecurity.ps1
#输出参考：
# === SERVICE (CIM): XboxNetApiSvc ===


# Name                    : XboxNetApiSvc
# DisplayName             : Xbox Live 网络服务
# State                   : Stopped
# Status                  : OK
# Started                 : False
# StartMode               : Manual
# StartName               : LocalSystem
# ProcessId               : 0
# ServiceType             : Share Process
# ExitCode                : 1077
# ServiceSpecificExitCode : 0
# PathName                : C:\Windows\system32\svchost.exe -k netsvcs -p
# Description             : 此服务支持 Windows.Networking.XboxLive 应用程序编程接口。
#
# RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall   = 0


try {
    Write-Output '---Attempt: Get-CimInstance Win32_Service---'
    $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

    if ($null -ne $svcs -and ($svcs | Measure-Object).Count -gt 0) {
        foreach ($s in $svcs | Sort-Object -Property Name) {
            Write-Output ("=== SERVICE (CIM): {0} ===" -f $s.Name)
            $s | Select-Object `
                Name, DisplayName, State, Status, Started, StartMode, `
                StartName, ProcessId, ServiceType, `
                ExitCode, ServiceSpecificExitCode, `
                PathName, Description |
            Format-List * | Out-String | Write-Output
        }
        $overall = 0
    } else {
        Write-Output '[WARN] Win32_Service returned no items.'
        if ($overall -eq 0) { $overall = 1 }
    }
}
catch {
    Write-Output ("[ERROR] Get-CimInstance Win32_Service failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 2) { $overall = 2 }
}


# ===== 结束：不抛异常，设置 LASTEXITCODE 并输出 RETURN_CODE =====
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
