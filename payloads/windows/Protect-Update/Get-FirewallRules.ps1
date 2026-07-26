<#
Get-FirewallRules.ps1
极简风格：原样输出、防止抛异常、最后返回 RETURN_CODE
返回码说明:
  0 - 成功
  1 - 无规则 / 无结果
  2 - Get-NetFirewallRule 失败（并且未成功回退）
  3 - Get-NetFirewallRule 失败且 netsh 回退也失败（两者都失败）
#>
#调用方法：.\Get-FirewallRules.ps1
#输出参考：
#---Attempt: Get-NetFirewallRule (PowerShell NetSecurity)---
# Name                          : {2FC027AF-A403-4FC0-A7E7-D8DB0BE253A8}
# ID                            : {2FC027AF-A403-4FC0-A7E7-D8DB0BE253A8}
# DisplayName                   : 电影和电视
# Group                         : @{Microsoft.ZuneVideo_10.24081.10111.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.ZuneV
#                                 ideo/resources/IDS_MANIFEST_VIDEO_APP_NAME}
# Enabled                       : True
# Profile                       : Domain, Private
# Platform                      : {6.2+}
# Direction                     : Inbound
# Action                        : Allow
# EdgeTraversalPolicy           : Block
# LSM                           : False
# PrimaryStatus                 : OK
# Status                        : 已从存储区成功分析规则。 (65536)
# EnforcementStatus             : NotApplicable
# PolicyStoreSourceType         : Local
# Caption                       :
# Description                   : 电影和电视
# ElementName                   : @{Microsoft.ZuneVideo_10.24081.10111.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.ZuneV
#                                 ideo/resources/IDS_MANIFEST_VIDEO_APP_NAME}
# InstanceID                    : {2FC027AF-A403-4FC0-A7E7-D8DB0BE253A8}
# CommonName                    :
# PolicyKeywords                :
# PolicyDecisionStrategy        : 2
# PolicyRoles                   :
# ConditionListType             : 3
# CreationClassName             : MSFT|FW|FirewallRule|{2FC027AF-A403-4FC0-A7E7-D8DB0BE253A8}
# ExecutionStrategy             : 2
# Mandatory                     :
# PolicyRuleName                :
# Priority                      :
# RuleUsage                     :
# SequencedActions              : 3
# SystemCreationClassName       :
# SystemName                    :
# DisplayGroup                  : 电影和电视
# LocalOnlyMapping              : False
# LooseSourceMapping            : False
# Owner                         : S-1-5-21-3438909164-4223864119-2367268561-1107
# Platforms                     : {6.2+}
# PolicyAppId                   :
# PolicyStoreSource             : PersistentStore
# Profiles                      : 3
# RemoteDynamicKeywordAddresses :
# RuleGroup                     : @{Microsoft.ZuneVideo_10.24081.10111.0_x64__8wekyb3d8bbwe?ms-resource://Microsoft.ZuneV
#                                 ideo/resources/IDS_MANIFEST_VIDEO_APP_NAME}
# StatusCode                    : 65536
# PSComputerName                :
# CimClass                      : root/standardcimv2:MSFT_NetFirewallRule
# CimInstanceProperties         : {Caption, Description, ElementName, InstanceID...}
# CimSystemProperties           : Microsoft.Management.Infrastructure.CimSystemProperties
#
#RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0
$gotResults = $false

# Write-Output ("Run at: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# 1) 尝试使用 Get-NetFirewallRule（模块: NetSecurity）
try {
    Write-Output '---Attempt: Get-NetFirewallRule (PowerShell NetSecurity)---'
    $rules = Get-NetFirewallRule -ErrorAction Stop

    if ($null -ne $rules -and ($rules | Measure-Object).Count -gt 0) {
        # 原样输出：展开全部属性，便于日志/上游解析
        $rules | Format-List * | Out-String | Write-Output
        $gotResults = $true
        $overall = 0
    } else {
        Write-Output '[WARN] Get-NetFirewallRule returned no rules.'
        $overall = 1
    }
}
catch {
    Write-Output ("[ERROR] Get-NetFirewallRule failed: {0}" -f $_.Exception.Message)
    # 标记为失败，准备回退到 netsh
    $overall = 2
}

# 2) 如果没有结果或上一步失败，回退使用 netsh
if (-not $gotResults) {
    try {
        Write-Output '---Fallback: netsh advfirewall firewall show rule name=all---'
        $netshOut = & cmd /c 'netsh advfirewall firewall show rule name=all' 2>&1
        $netshCode = $LASTEXITCODE

        if ($netshOut -and ($netshOut -join [Environment]::NewLine).Trim() -ne '') {
            $netshOut -join [Environment]::NewLine | Write-Output
            # 如果之前 Get-NetFirewallRule 报错，但 netsh 有输出，则视为成功（返回 0）
            $gotResults = $true
            $overall = 0
        }
        else {
            Write-Output '[WARN] netsh returned empty output.'
            # 保持原有 overall（可能是 1 或 2），若 netsh 有错误码则采用它
            if ($netshCode -ne 0) { $overall = 3 } elseif ($overall -eq 0) { $overall = 1 }
        }
    }
    catch {
        Write-Output ("[ERROR] netsh fallback failed: {0}" -f $_.Exception.Message)
        # 两者都失败
        $overall = 3
    }
}

# 3) 结束：不抛异常，设置 LASTEXITCODE 并输出 RETURN_CODE
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
