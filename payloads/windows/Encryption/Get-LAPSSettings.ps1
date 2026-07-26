<#
Get-LAPSSettings.ps1
通过注册表读取 LAPS（Windows LAPS 与旧版 AdmPwd LAPS）策略。
不抛异常、不停止；末尾输出 RETURN_CODE 并同步 $global:LASTEXITCODE。

Return codes:
  0 = 至少读取到一个 LAPS 策略键并输出
  1 = 未找到任何 LAPS 策略注册表键
  2 = 读取注册表过程中发生错误（且未有任何成功输出）
#>
#调用方法：.\Get-LAPSSettings.ps1



[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0
$anySuccess = $false



# 需要检查的注册表键（先新后旧）
$keys = @(
    'HKLM\Software\Microsoft\Policies\LAPS',
    'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS',#组策略。
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS\Config',           # Windows LAPS（2023+）
    'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'         # 旧版 LAPS (AdmPwd)
)

foreach ($k in $keys) {
    try {
        if (Test-Path -LiteralPath $k) {
            Write-Output ("---LAPS Policy Key Found: {0}---" -f $k)
            # 输出该键及其所有值（以文本形式原样展开）
            $item = Get-ItemProperty -Path $k -ErrorAction Stop
            $item | Format-List * | Out-String | Write-Output
            $anySuccess = $true
        } else {
            Write-Output ("[INFO] LAPS policy key not found: {0}" -f $k)
        }
    }
    catch {
        Write-Output ("[ERROR] Failed reading registry key {0}: {1}" -f $k, $_.Exception.Message)
        if (-not $anySuccess -and $overall -lt 2) { $overall = 2 }
    }
}

if (-not $anySuccess -and $overall -eq 0) {
    # 两个键都不存在且无任何成功输出
    $overall = 1
}

$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
