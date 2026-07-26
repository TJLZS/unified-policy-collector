#调用方法：.\Get-WindowsUpdateRegistry.ps1
#输出参考：
# ---Attempt: Registry read HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate ---
# [REG] HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:


# SetAutoRestartNotificationConfig : 0
# PSPath                           : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
# PSParentPath                     : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows
# PSChildName                      : WindowsUpdate
# PSDrive                          : HKLM
# PSProvider                       : Microsoft.PowerShell.Core\Registry

# [REG] HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU

# NoAutoUpdate       : 1
# NoAUShutdownOption : 1
# PSPath             : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
# PSParentPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
# PSChildName        : AU
# PSProvider         : Microsoft.PowerShell.Core\Registry

# ---Attempt: Registry read HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU ---
# [REG] HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:


# NoAutoUpdate       : 1
# NoAUShutdownOption : 1
# PSPath             : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
# PSParentPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
# PSChildName        : AU
# PSDrive            : HKLM
# PSProvider         : Microsoft.PowerShell.Core\Registry

# ---Attempt: Registry read HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update ---
# [REG] HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update:

# [REG] HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\CommitRequired

# [REG] HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\LastOnlineScanTimeForAppCategory

# [REG] HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Power


# Firmware-Final                  : 30
# OfferInstallAtShutdown-Final    : 40
# ContinueInstallAtShutdown-Final : 10
# FirmwareForcedInstall-Final     : 35
# PSPath                          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Powe
#                                   r
# PSParentPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update
# PSChildName                     : Power
# PSProvider                      : Microsoft.PowerShell.Core\Registry

# [REG] HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RequestedAppCategories


# Name                           Value
# ----                           -----
# HKLM:\SOFTWARE\Microsoft\Wi... {}
# HKLM:\SOFTWARE\Policies\Mic... {NoAutoUpdate, NoAUShutdownOption}
# HKLM:\SOFTWARE\Microsoft\Wi... {}
# HKLM:\SOFTWARE\Microsoft\Wi... {OfferInstallAtShutdown-Final, Firmware-Final, FirmwareForcedInstall-Final, ContinueInstallAtShutdown-Final}
# HKLM:\SOFTWARE\Microsoft\Wi... {}
# HKLM:\SOFTWARE\Policies\Mic... {NoAutoUpdate, NoAUShutdownOption}
# HKLM:\SOFTWARE\Microsoft\Wi... {}
# HKLM:\SOFTWARE\Policies\Mic... {SetAutoRestartNotificationConfig}

param()

$ErrorActionPreference = 'Continue'
$anySuccess = $false
$out = @{}

$keys = @(
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
)

$meta = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')

foreach($k in $keys) {
  Write-Output ("---Attempt: Registry read {0} ---" -f $k)
  try {
    if(Test-Path -LiteralPath $k) {
      $vals = Get-ItemProperty -Path $k -ErrorAction Stop
      Write-Output ("[REG] {0}:" -f $k)
      $vals | Format-List * | Out-String | Write-Output
      $anySuccess = $true

      # 记录到 JSON 输出对象（过滤元属性）
      $pairs = @{}
      $names = ($vals.PSObject.Properties.Name | Where-Object { $_ -notin $meta })
      foreach($n in $names) { $pairs[$n] = $vals.$n }
      $out[$k] = $pairs

      # 子键
      $children = Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue
      foreach($child in $children) {
        try {
          $cvals = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction Stop
          $clean = ($child.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::','')
          Write-Output ("[REG] {0}:{1}" -f $k, $clean)
          $cvals | Format-List * | Out-String | Write-Output
          # 记录子键到输出对象
          $cpairs = @{}
          $cnames = ($cvals.PSObject.Properties.Name | Where-Object { $_ -notin $meta })
          foreach($cn in $cnames) { $cpairs[$cn] = $cvals.$cn }
          $out["$k\$clean"] = $cpairs
        } catch {
          Write-Output ("[ERROR] Read subkey failed: {0}" -f $_.Exception.Message)
          if(-not $anySuccess) { $anySuccess = $false }
        }
      }
    } else {
      Write-Output ("[WARN] Registry key not found: {0}" -f $k)
      $out[$k] = $null
    }
  } catch {
    Write-Output ("[ERROR] Reading key {0} failed: {1}" -f $k, $_.Exception.Message)
    $out[$k] = $null
  }
}


if($anySuccess) { $final = 0 } else { $final = 1 }

$global:LASTEXITCODE = $final
$out
Write-Output ("RETURN_CODE={0}" -f $final)


