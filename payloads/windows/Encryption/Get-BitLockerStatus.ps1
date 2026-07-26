#调用方法：Get-BitLockerStatus.ps1 [A-Z:]
#输出参考：
#实例1
# ---Get-BitLockerVolume -MountPoint C:---


# ComputerName         : WIN10-BOOK-2
# MountPoint           : C:
# EncryptionMethod     : None
# AutoUnlockEnabled    :
# AutoUnlockKeyStored  :
# MetadataVersion      : 0
# VolumeStatus         : FullyDecrypted
# ProtectionStatus     : Off
# LockStatus           : Unlocked
# EncryptionPercentage : 0
# WipePercentage       : 0
# VolumeType           : OperatingSystem
# CapacityGB           : 69.40213
# KeyProtector         : {}
#
# RETURN_CODE=0
#实例2
# PS C:\Users\Administrator\Desktop> .\Get-BitLockerStatus.ps1 D:
# ---Get-BitLockerVolume -MountPoint D:---
# [ERROR] Get-BitLockerVolume failed: 找不到元素。 (异常来自 HRESULT:0x80070490)
# ---Fallback: manage-bde -status "D:"---
# BitLocker 驱动器加密: 配置工具版本 10.0.19041
# 版权所有 (C) 2013 Microsoft Corporation。保留所有权利。

# 错误: BitLocker 无法打开卷 D:。
# 这可能是由于该卷不存在，或者它并非有效
# BitLocker 卷。
# RETURN_CODE=-1

[CmdletBinding()]
param(
    # 可选：指定盘符/挂载点，如 "C:"；不指定则查询全部
    [string]$MountPoint
)

$ErrorActionPreference = 'Continue'
$overall = 0
$fallbackUsed = $false

function Write-Section {
    param([string]$title)
    Write-Output ("---{0}---" -f $title)
}

# 1) 优先使用 Get-BitLockerVolume
$gbvOk = $false
try {
    if ([string]::IsNullOrWhiteSpace($MountPoint)) {
        Write-Section "Get-BitLockerVolume (all)"
        $gbv = Get-BitLockerVolume -ErrorAction Stop
    } else {
        Write-Section ("Get-BitLockerVolume -MountPoint {0}" -f $MountPoint)
        $gbv = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
    }

    if ($null -ne $gbv -and ($gbv | Measure-Object).Count -gt 0) {
        # 原样输出；为保证可读性用 Format-List * 展开为文本
        $gbv | Format-List * | Out-String | Write-Output
        $gbvOk = $true
        $overall = 0
    } else {
        Write-Output "[WARN] Get-BitLockerVolume returned no result."
    }
}
catch {
    Write-Output ("[ERROR] Get-BitLockerVolume failed: {0}" -f $_.Exception.Message)
}

# 2) 回退到 manage-bde -status（仅当上一步失败时）
if (-not $gbvOk) {
    $fallbackUsed = $true
    if ([string]::IsNullOrWhiteSpace($MountPoint)) {
        $cmd = 'manage-bde -status'
        Write-Section "Fallback: manage-bde -status"
    } else {
        $cmd = "manage-bde -status `"$MountPoint`""
        Write-Section ("Fallback: {0}" -f $cmd)
    }

    $mOut = & cmd /c $cmd 2>&1
    $mCode = $LASTEXITCODE

    if ($mOut) {
        $mOut -join [Environment]::NewLine | Write-Output
    }

    if ($mCode -ne 0) {
        # 两者都失败：返回 manage-bde 的错误码（优先）
        $overall = $mCode
    } else {
        $overall = 0
    }
}

if ($fallbackUsed -and $overall -eq 0) {
    Write-Output "[INFO] Fallback succeeded with manage-bde."
}

$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
