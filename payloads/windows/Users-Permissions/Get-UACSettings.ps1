#调用方法：.\Get-UACSettings.ps1
#输出参考：
# PS C:\Users\Administrator\Desktop> .\Get-UACSettings.ps1

# Name                           Value
# ----                           -----
# ConsentPromptBehaviorAdmin     5
# EnableInstallerDetection       1
# ConsentPromptBehaviorUser      3
# EnableSecureUIAPaths           1
# EnableLUA                      1
# ValidateAdminCodeSignatures    0
# EnableVirtualization           1
# PromptOnSecureDesktop          1
# EnableUIADesktopToggle         0

# RETURN_CODE=0



$reg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$out = @{}
$exitCode = 0
if(Test-Path $reg) {
  $props = Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue
  $pick = "EnableUIADesktopToggle","FilterAdministratorToken","ConsentPromptBehaviorAdmin","ConsentPromptBehaviorUser",
  "EnableInstallerDetection","ValidateAdminCodeSignatures","EnableSecureUIAPaths","EnableLUA",
  "PromptOnSecureDesktop","EnableVirtualization","InteractiveLogonFirst"
  foreach($p in $pick) {
    $value = (Get-ItemProperty -Path $reg -Name $p -ErrorAction SilentlyContinue).$p
    if ($null -ne $value) {
      $out[$p] = $value
    }
  }
} else {
  $exitCode = 1
}

$out
Write-Output("")
Write-Output ("RETURN_CODE={0}" -f $exitCode)