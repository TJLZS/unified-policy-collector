<#
Get-WindowsDefenderStatus.ps1
极简风格：逐项输出 Windows Defender 相关策略/状态、不抛异常、末尾 RETURN_CODE

Return code convention (script-internal, 最终返回值见最后):
  0 - 至少一项成功
  1 - Get-MpComputerStatus 失败或无结果
  2 - Get-MpPreference 失败或无结果
  3 - Windows Defender 服务 (WinDefend) 查询失败或无结果
  4 - 注册表策略读取失败或无结果
  5 - 以上全部步骤均失败
#>
#调用方法：.\Get-WindowsDefenderStatus.ps1
#输出参考：
# ---Attempt: Get-MpComputerStatus (Protection Status)---


# AMEngineVersion                  : 1.1.25090.3001
# AMProductVersion                 : 4.18.25080.5
# AMRunningMode                    : Normal
# AMServiceEnabled                 : True
# AMServiceVersion                 : 4.18.25080.5
# AntispywareEnabled               : True
# AntispywareSignatureAge          : 0
# AntispywareSignatureLastUpdated  : 2025/10/16 15:07:35
# AntispywareSignatureVersion      : 1.439.218.0
# AntivirusEnabled                 : True
# AntivirusSignatureAge            : 0
# AntivirusSignatureLastUpdated    : 2025/10/16 15:07:36
# AntivirusSignatureVersion        : 1.439.218.0
# BehaviorMonitorEnabled           : False
# ComputerID                       : BC064DAE-5AC5-4FD2-B808-BB26866249B5
# ComputerState                    : 0
# DefenderSignaturesOutOfDate      : False
# DeviceControlDefaultEnforcement  :
# DeviceControlPoliciesLastUpdated : 2023/6/6 15:36:11
# DeviceControlState               : Disabled
# FullScanAge                      : 4294967295
# FullScanEndTime                  :
# FullScanOverdue                  : False
# FullScanRequired                 : False
# FullScanSignatureVersion         :
# FullScanStartTime                :
# InitializationProgress           : ServiceStartedSuccessfully
# IoavProtectionEnabled            : False
# IsTamperProtected                : False
# IsVirtualMachine                 : False
# LastFullScanSource               : 0
# LastQuickScanSource              : 2
# NISEnabled                       : False
# NISEngineVersion                 : 0.0.0.0
# NISSignatureAge                  : 65535
# NISSignatureLastUpdated          :
# NISSignatureVersion              :
# OnAccessProtectionEnabled        : False
# ProductStatus                    : 524288
# QuickScanAge                     : 0
# QuickScanEndTime                 : 2025/10/16 18:55:31
# QuickScanOverdue                 : False
# QuickScanSignatureVersion        : 1.439.216.0
# QuickScanStartTime               : 2025/10/16 18:55:06
# RealTimeProtectionEnabled        : False
# RealTimeScanDirection            : 0
# RebootRequired                   : False
# SmartAppControlExpiration        :
# SmartAppControlState             : Off
# TamperProtectionSource           : UI
# TDTCapable                       : N/A
# TDTMode                          : N/A
# TDTSiloType                      : N/A
# TDTStatus                        : N/A
# TDTTelemetry                     : N/A
# TroubleShootingDailyMaxQuota     :
# TroubleShootingDailyQuotaLeft    :
# TroubleShootingEndTime           :
# TroubleShootingExpirationLeft    :
# TroubleShootingMode              :
# TroubleShootingModeSource        :
# TroubleShootingQuotaResetTime    :
# TroubleShootingStartTime         :
# PSComputerName                   :
# CimClass                         : ROOT/Microsoft/Windows/Defender:MSFT_MpComputerStatus
# CimInstanceProperties            : {AMEngineVersion, AMProductVersion, AMRunningMode, AMServiceEnabled...}
# CimSystemProperties              : Microsoft.Management.Infrastructure.CimSystemProperties




# ---Attempt: Get-MpPreference (Preferences / Policy)---


# AllowDatagramProcessingOnWinServer                    : False
# AllowNetworkProtectionDownLevel                       : False
# AllowNetworkProtectionOnWinServer                     : False
# AllowSwitchToAsyncInspection                          : True
# ApplyDisableNetworkScanningToIOAV                     : False
# AttackSurfaceReductionOnlyExclusions                  :
# AttackSurfaceReductionRules_Actions                   :
# AttackSurfaceReductionRules_Ids                       :
# AttackSurfaceReductionRules_RuleSpecificExclusions    :
# AttackSurfaceReductionRules_RuleSpecificExclusions_Id :
# BruteForceProtectionAggressiveness                    : 0
# BruteForceProtectionConfiguredState                   : 0
# BruteForceProtectionExclusions                        :
# BruteForceProtectionLocalNetworkBlocking              : False
# BruteForceProtectionMaxBlockTime                      : 0
# BruteForceProtectionSkipLearningPeriod                : False
# CheckForSignaturesBeforeRunningScan                   : False
# CloudBlockLevel                                       : 0
# CloudExtendedTimeout                                  : 0
# ComputerID                                            : BC064DAE-5AC5-4FD2-B808-BB26866249B5
# ControlledFolderAccessAllowedApplications             :
# ControlledFolderAccessDefaultProtectedFolders         : {N/A: Controlled Folder Access is disabled}
# ControlledFolderAccessProtectedFolders                :
# DefinitionUpdatesChannel                              : 0
# DisableArchiveScanning                                : False
# DisableAutoExclusions                                 : False
# DisableBehaviorMonitoring                             : False
# DisableBlockAtFirstSeen                               : False
# DisableCacheMaintenance                               : False
# DisableCatchupFullScan                                : True
# DisableCatchupQuickScan                               : True
# DisableCoreServiceECSIntegration                      : False
# DisableCoreServiceTelemetry                           : False
# DisableCpuThrottleOnIdleScans                         : True
# DisableDatagramProcessing                             : False
# DisableDnsOverTcpParsing                              : False
# DisableDnsParsing                                     : False
# DisableEmailScanning                                  : True
# DisableFtpParsing                                     : False
# DisableGradualRelease                                 : False
# DisableHttpParsing                                    : False
# DisableInboundConnectionFiltering                     : False
# DisableIOAVProtection                                 : False
# DisableNetworkProtectionPerfTelemetry                 : False
# DisablePrivacyMode                                    : False
# DisableQuicParsing                                    : True
# DisableRdpParsing                                     : False
# DisableRealtimeMonitoring                             : True
# DisableRemovableDriveScanning                         : True
# DisableRestorePoint                                   : True
# DisableScanningMappedNetworkDrivesForFullScan         : True
# DisableScanningNetworkFiles                           : False
# DisableScriptScanning                                 : False
# DisableSmtpParsing                                    : False
# DisableSshParsing                                     : False
# DisableTamperProtection                               : True
# DisableTlsParsing                                     : False
# EnableControlledFolderAccess                          : 0
# EnableConvertWarnToBlock                              : False
# EnableDnsSinkhole                                     : True
# EnableFileHashComputation                             : False
# EnableFullScanOnBatteryPower                          : False
# EnableLowCpuPriority                                  : False
# EnableNetworkProtection                               : 0
# EnableUdpReceiveOffload                               : False
# EnableUdpSegmentationOffload                          : False
# EngineUpdatesChannel                                  : 0
# ExclusionExtension                                    :
# ExclusionIpAddress                                    :
# ExclusionPath                                         : {C:\Tools}
# ExclusionProcess                                      :
# ForceUseProxyOnly                                     : False
# HideExclusionsFromLocalUsers                          : True
# HighThreatDefaultAction                               : 0
# IntelTDTEnabled                                       :
# LowThreatDefaultAction                                : 0
# MAPSReporting                                         : 0
# MeteredConnectionUpdates                              : False
# ModerateThreatDefaultAction                           : 0
# NetworkProtectionReputationMode                       : 0
# OobeEnableRtpAndSigUpdate                             : False
# PerformanceModeStatus                                 : 1
# PlatformUpdatesChannel                                : 0
# ProxyBypass                                           :
# ProxyPacUrl                                           :
# ProxyServer                                           :
# PUAProtection                                         : 0
# QuarantinePurgeItemsAfterDelay                        : 90
# QuickScanIncludeExclusions                            : 0
# RandomizeScheduleTaskTimes                            : True
# RealTimeScanDirection                                 : 0
# RemediationScheduleDay                                : 0
# RemediationScheduleTime                               : 02:00:00
# RemoteEncryptionProtectionAggressiveness              : 0
# RemoteEncryptionProtectionConfiguredState             : 0
# RemoteEncryptionProtectionExclusions                  :
# RemoteEncryptionProtectionMaxBlockTime                : 0
# RemoveScanningThreadPoolCap                           : False
# ReportDynamicSignatureDroppedEvent                    : False
# ReportingAdditionalActionTimeOut                      : 10080
# ReportingCriticalFailureTimeOut                       : 10080
# ReportingNonCriticalTimeOut                           : 1440
# ScanAvgCPULoadFactor                                  : 50
# ScanOnlyIfIdleEnabled                                 : True
# ScanParameters                                        : 1
# ScanPurgeItemsAfterDelay                              : 15
# ScanScheduleDay                                       : 0
# ScanScheduleOffset                                    : 120
# ScanScheduleQuickScanTime                             : 00:00:00
# ScanScheduleTime                                      : 02:00:00
# SchedulerRandomizationTime                            : 4
# ServiceHealthReportInterval                           : 60
# SevereThreatDefaultAction                             : 0
# SharedSignaturesPath                                  :
# SharedSignaturesPathUpdateAtScheduledTimeOnly         : False
# SignatureAuGracePeriod                                : 0
# SignatureBlobFileSharesSources                        :
# SignatureBlobUpdateInterval                           : 60
# SignatureDefinitionUpdateFileSharesSources            :
# SignatureDisableUpdateOnStartupWithoutEngine          : False
# SignatureFallbackOrder                                : MicrosoftUpdateServer|MMPC
# SignatureFirstAuGracePeriod                           : 120
# SignatureScheduleDay                                  : 8
# SignatureScheduleTime                                 : 01:45:00
# SignatureUpdateCatchupInterval                        : 1
# SignatureUpdateInterval                               : 0
# SubmitSamplesConsent                                  : 0
# ThreatIDDefaultAction_Actions                         :
# ThreatIDDefaultAction_Ids                             :
# ThrottleForScheduledScanOnly                          : True
# TrustLabelProtectionStatus                            : 0
# UILockdown                                            : False
# UnknownThreatDefaultAction                            : 0
# PSComputerName                                        :
# CimClass                                              : root/Microsoft/Windows/Defender:MSFT_MpPreference
# CimInstanceProperties                                 : {AllowDatagramProcessingOnWinServer, AllowNetworkProtectionDownLevel, AllowNetworkProtectionOnWinServer,
#                                                         AllowSwitchToAsyncInspection...}
# CimSystemProperties                                   : Microsoft.Management.Infrastructure.CimSystemProperties




# ---Attempt: Registry read HKLM:\SOFTWARE\Microsoft\Windows Defender ---
# [REG] HKLM:\SOFTWARE\Microsoft\Windows Defender:


# ProductAppDataPath                   : C:\ProgramData\Microsoft\Windows Defender
# ProductIcon                          : @C:\Program Files\Windows Defender\EppManifest.dll,-100
# ProductLocalizedName                 : @C:\Program Files\Windows Defender\EppManifest.dll,-1000
# RemediationExe                       : windowsdefender://
# ProductType                          : 2
# InstallTime                          : {129, 24, 113, 192...}
# InstallLocation                      : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25080.5-0\
# ManagedDefenderProductType           : 0
# OOBEInstallTime                      : {108, 140, 47, 232...}
# ProductStatus                        : 0
# HybridModeEnabled                    : 0
# VerifiedAndReputableTrustModeEnabled : 0
# DisableAntiSpyware                   : 0
# DisableAntiVirus                     : 0
# PUAProtection                        : 0
# BackupLocation                       : C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0
# ServiceStartStates                   : 1
# UUPFlags                             : 0
# IsServiceRunning                     : 1
# SAC_ClientWaitForRpc                 : 0
# PSPath                               : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender
# PSParentPath                         : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft
# PSChildName                          : Windows Defender
# PSDrive                              : HKLM
# PSProvider                           : Microsoft.PowerShell.Core\Registry
#
# RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0
$anySuccess = $false


# 1) Get-MpComputerStatus - 防护状态（首选）
try {
    Write-Output '---Attempt: Get-MpComputerStatus (Protection Status)---'
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($null -ne $mpStatus -and ($mpStatus | Measure-Object).Count -gt 0) {
        $mpStatus | Format-List * | Out-String | Write-Output
        $anySuccess = $true
    } else {
        Write-Output '[WARN] Get-MpComputerStatus returned no result.'
        if ($overall -lt 1) { $overall = 1 }
    }
}
catch {
    Write-Output ("[ERROR] Get-MpComputerStatus failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 1) { $overall = 1 }
}

# 2) Get-MpPreference - Defender 配置/策略项
try {
    Write-Output '---Attempt: Get-MpPreference (Preferences / Policy)---'
    $mpPref = Get-MpPreference -ErrorAction Stop
    if ($null -ne $mpPref -and ($mpPref | Measure-Object).Count -gt 0) {
        $mpPref | Format-List * | Out-String | Write-Output
        $anySuccess = $true
    } else {
        Write-Output '[WARN] Get-MpPreference returned no result.'
        if ($overall -lt 2) { $overall = 2 }
    }
}
catch {
    Write-Output ("[ERROR] Get-MpPreference failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 2) { $overall = 2 }
}

# 4) 注册表策略（本地/组策略覆盖）
try {
    Write-Output '---Attempt: Registry read HKLM:\SOFTWARE\Microsoft\Windows Defender ---'
    $rk1 = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    if (Test-Path -LiteralPath $rk1) {
        $vals1 = Get-ItemProperty -Path $rk1 -ErrorAction Stop
        Write-Output ("[REG] {0}:" -f $rk1)
        $vals1 | Format-List * | Out-String | Write-Output
        $anySuccess = $true
    } else {
        Write-Output ("[WARN] Registry key not found: {0}" -f $rk1)
        if ($overall -lt 4) { $overall = 4 }
    }
}
catch {
    Write-Output ("[ERROR] Reading registry {0} failed: {1}" -f $rk1, $_.Exception.Message)
    if ($overall -lt 4) { $overall = 4 }
}


# 计算最终返回码
if ($anySuccess) {
    $final = 0
} else {
    # 若没有任何成功输出，采用上面记录的最大错误等级（>=1）
    # 若 overall 未被设置过（仍为0）则置为 5（全部失败）
    if ($overall -eq 0) { $final = 5 } else { $final = $overall }
}

$global:LASTEXITCODE = $final
Write-Output ("RETURN_CODE={0}" -f $final)
