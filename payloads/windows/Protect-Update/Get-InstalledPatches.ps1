<#
Get-InstalledPatches.ps1
极简：原样输出、不抛异常、末尾 RETURN_CODE
Return codes:
  0 - 至少有一个来源成功输出结果
  1 - Get-HotFix 无记录
  2 - Get-HotFix 失败
  3 - 在前一步未成功时，DISM 失败或无结果
  4 - 三者均失败/无结果（WMIC 也未能提供结果）
#> 
#调用方法：.\Get-InstalledPatches.ps1
#输出参考：
# ---Attempt: Get-HotFix---


# PSComputerName      : WIN10-BOOK-2
# InstalledOn         : 2023/6/7 0:00:00
# __PATH              : \\WIN10-BOOK-2\root\cimv2:Win32_QuickFixEngineering.HotFixID="KB5015684",ServicePackInEffect=""
# Status              :
# __GENUS             : 2
# __CLASS             : Win32_QuickFixEngineering
# __SUPERCLASS        : CIM_LogicalElement
# __DYNASTY           : CIM_ManagedSystemElement
# __RELPATH           : Win32_QuickFixEngineering.HotFixID="KB5015684",ServicePackInEffect=""
# __PROPERTY_COUNT    : 11
# __DERIVATION        : {CIM_LogicalElement, CIM_ManagedSystemElement}
# __SERVER            : WIN10-BOOK-2
# __NAMESPACE         : root\cimv2
# Caption             : https://support.microsoft.com/help/5015684
# CSName              : WIN10-BOOK-2
# Description         : Update
# FixComments         :
# HotFixID            : KB5015684
# InstallDate         :
# InstalledBy         : NT AUTHORITY\SYSTEM
# Name                :
# ServicePackInEffect :
# Scope               : System.Management.ManagementScope
# Path                : \\WIN10-BOOK-2\root\cimv2:Win32_QuickFixEngineering.HotFixID="KB5015684",ServicePackInEffect=""
# Options             : System.Management.ObjectGetOptions
# ClassPath           : \\WIN10-BOOK-2\root\cimv2:Win32_QuickFixEngineering
# Properties          : {Caption, CSName, Description, FixComments...}
# SystemProperties    : {__GENUS, __CLASS, __SUPERCLASS, __DYNASTY...}
# Qualifiers          : {dynamic, Locale, provider, UUID}
# Site                :
# Container           :
#
#RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0
$gotResults = $false


# 1) Get-HotFix
try {
    Write-Output '---Attempt: Get-HotFix---'
    $hf = Get-HotFix -ErrorAction Stop
    if ($null -ne $hf -and ($hf | Measure-Object).Count -gt 0) {
        # 原样展开输出
        $hf | Sort-Object InstalledOn -Descending | Format-List * | Out-String | Write-Output
        $gotResults = $true
        $overall = 0
    } else {
        Write-Output '[WARN] Get-HotFix returned no records.'
        if ($overall -eq 0) { $overall = 1 }
    }
}
catch {
    Write-Output ("[ERROR] Get-HotFix failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 2) { $overall = 2 }
}

# 2) DISM（仅当尚未获得结果时）
if (-not $gotResults) {
    Write-Output '---Fallback: DISM /Online /Get-Packages---'
    $dismOut = & cmd /c 'dism /online /get-packages' 2>&1
    $dismCode = $LASTEXITCODE

    if ($dismOut -and ($dismOut -join [Environment]::NewLine).Trim() -ne '') {
        $dismOut -join [Environment]::NewLine | Write-Output
        if ($dismCode -eq 0) {
            $gotResults = $true
            $overall = 0
        } else {
            # DISM 输出了东西但返回码非0，仍视为可用；保留最小错误码标记
            if ($overall -lt 3) { $overall = 3 }
        }
    } else {
        Write-Output ("[WARN] DISM returned empty output (ExitCode={0})." -f $dismCode)
        if ($overall -lt 3) { $overall = 3 }
    }
}

# 3) WMIC QFE（仅当仍未获得结果时；注意：WMIC 在新系统已弃用，但仍可做兜底）
if (-not $gotResults) {
    Write-Output '---Fallback: WMIC QFE LIST FULL---'
    $wmicOut = & cmd /c 'wmic qfe list full' 2>&1
    $wmicCode = $LASTEXITCODE

    if ($wmicOut -and ($wmicOut -join [Environment]::NewLine).Trim() -ne '') {
        $wmicOut -join [Environment]::NewLine | Write-Output
        if ($wmicCode -eq 0) {
            $gotResults = $true
            $overall = 0
        } else {
            if ($overall -lt 4) { $overall = 4 }
        }
    } else {
        Write-Output ("[WARN] WMIC returned empty output (ExitCode={0})." -f $wmicCode)
        if ($overall -lt 4) { $overall = 4 }
    }
}

# 结束：不抛异常，设置 LASTEXITCODE 并输出 RETURN_CODE
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
