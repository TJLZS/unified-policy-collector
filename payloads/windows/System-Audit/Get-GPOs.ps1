<#
Get-GPOs.ps1
极简：原样输出、不抛异常、末尾 RETURN_CODE
Return codes:
  0 - 所有已请求步骤成功
  1 - Get-GPO 返回空结果
  2 - Get-GPO 执行失败
  3 - Get-GPOReport 失败或文件未生成（当传入 GpoReportPath 才可能）
  4 - gpresult 失败或文件未生成（当传入 GpResultHtmlPath 才可能）
  1048 - 域成员信息获取失败
#>
#调用方法：.\Get-GPOs.ps1 [-GpoReportPath <path>]  [-GpResultHtmlPath <path>]
#说明，该脚本路径需要是绝对路径。
#输出参考：
# PS C:\Users\Administrator.RD\desktop> .\Get-GPOs.ps1 -GpoReportPath "C:\AllGPOs1.html" -GpResultHtmlPath "C:\GpResult.ht
# ml"
# ---Attempt: Get-GPO -All (GroupPolicy module)---


# Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
# DisplayName      : Default Domain Policy
# Path             : cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=rd,DC=com
# Owner            : RD\Domain Admins
# DomainName       : rd.com
# CreationTime     : 2024/11/23 14:30:07
# ModificationTime : 2024/11/29 23:03:52
# User             : Microsoft.GroupPolicy.UserConfiguration
# Computer         : Microsoft.GroupPolicy.ComputerConfiguration
# GpoStatus        : AllSettingsEnabled
# WmiFilter        :
# Description      :

# Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
# DisplayName      : Default Domain Controllers Policy
# Path             : cn={6AC1786C-016F-11D2-945F-00C04fB984F9},cn=policies,cn=system,DC=rd,DC=com
# Owner            : RD\Domain Admins
# DomainName       : rd.com
# CreationTime     : 2024/11/23 14:30:07
# ModificationTime : 2024/11/23 14:36:44
# User             : Microsoft.GroupPolicy.UserConfiguration
# Computer         : Microsoft.GroupPolicy.ComputerConfiguration
# GpoStatus        : AllSettingsEnabled
# WmiFilter        :
# Description      :




# ---Get-GPOReport -All -ReportType Html -Path "C:\AllGPOs1.html"---
# [INFO] GPO HTML report generated: C:\AllGPOs1.html
# ---gpresult /h "C:\GpResult.html" /f---
# [INFO] gpresult HTML generated: C:\GpResult.html
# RETURN_CODE=0

[CmdletBinding()]
param(
    # 组策略对象整体报告（Get-GPOReport）的 HTML 路径；不传则跳过
    [string]$GpoReportPath,

    # gpresult 的 HTML 输出路径；不传则跳过
    [string]$GpResultHtmlPath
)

$ErrorActionPreference = 'Continue'
$overall = 0

# ========== 0) 域成员信息 ==========
try {
    Write-Output '---Domain Membership (Get-ComputerInfo)---'
    $ci = Get-ComputerInfo -ErrorAction Stop | Select-Object CsPartOfDomain, CsDomain, CsDomainRole
    if ($ci) {
        $ci | Format-List * | Out-String | Write-Output
    } else {
        Write-Output '[WARN] Get-ComputerInfo returned no data.'
        $overall = 1048
        #若失败状态码是1048
    }
}
catch {
    Write-Output ("[WARN] Get-ComputerInfo failed: {0}" -f $_.Exception.Message)
}

# 1) 概览：Get-GPO -All
try {
    Write-Output '---Attempt: Get-GPO -All (GroupPolicy module)---'
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Output '[INFO] GroupPolicy module not preloaded; trying to import...'
    }
    Import-Module GroupPolicy -ErrorAction Stop

    $gpos = Get-GPO -All -ErrorAction Stop
    if ($null -ne $gpos -and ($gpos | Measure-Object).Count -gt 0) {
        $gpos | Format-List * | Out-String | Write-Output
    } else {
        Write-Output '[WARN] Get-GPO returned no items.'
        if ($overall -eq 0) { $overall = 1 }
    }
}
catch {
    Write-Output ("[ERROR] Get-GPO failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 2) { $overall = 2 }
}

# 2) GPO整体报告：Get-GPOReport -All -ReportType Html -Path <GpoReportPath>
if ($GpoReportPath -and $GpoReportPath.Trim()) {
    try {
        Write-Output ("---Get-GPOReport -All -ReportType Html -Path `"{0}`"---" -f $GpoReportPath)
        $dir = Split-Path -Path $GpoReportPath -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        Get-GPOReport -All -ReportType Html -Path $GpoReportPath -ErrorAction Stop

        if (Test-Path -LiteralPath $GpoReportPath) {
            Write-Output ("[INFO] GPO HTML report generated: {0}" -f $GpoReportPath)
        } else {
            Write-Output "[WARN] Get-GPOReport executed but file not found."
            if ($overall -lt 3) { $overall = 3 }
        }
    }
    catch {
        Write-Output ("[ERROR] Get-GPOReport failed: {0}" -f $_.Exception.Message)
        if ($overall -lt 3) { $overall = 3 }
    }
} else {
    Write-Output '[INFO] GpoReportPath not provided; skip Get-GPOReport.'
}

# 3) 详细应用报告：gpresult /h <GpResultHtmlPath> /f
if ($GpResultHtmlPath -and $GpResultHtmlPath.Trim()) {
    try {
        Write-Output ("---gpresult /h `"{0}`" /f---" -f $GpResultHtmlPath)
        $rdir = Split-Path -Path $GpResultHtmlPath -Parent
        if ($rdir -and -not (Test-Path -LiteralPath $rdir)) {
            New-Item -ItemType Directory -Path $rdir -Force | Out-Null
        }

        $gpOut = & cmd /c ("gpresult /h `"{0}`" /f" -f $GpResultHtmlPath) 2>&1
        $gpCode = $LASTEXITCODE

        if ($gpOut) { $gpOut -join [Environment]::NewLine | Write-Output }

        if ($gpCode -eq 0 -and (Test-Path -LiteralPath $GpResultHtmlPath)) {
            Write-Output ("[INFO] gpresult HTML generated: {0}" -f $GpResultHtmlPath)
        } else {
            Write-Output ("[WARN] gpresult exit code={0} or file not created." -f $gpCode)
            if ($overall -lt 4) { $overall = 4 }
        }
    }
    catch {
        Write-Output ("[ERROR] gpresult failed: {0}" -f $_.Exception.Message)
        if ($overall -lt 4) { $overall = 4 }
    }
} else {
    Write-Output '[INFO] GpResultHtmlPath not provided; skip gpresult.'
}

# 结束：不抛异常，设置 LASTEXITCODE 并输出 RETURN_CODE
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
