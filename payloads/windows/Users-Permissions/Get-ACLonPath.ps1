# 调用方法：.\Get-ACLonPath.ps1 -Path filename/path
# 输出参考：
# PS C:\Users\Administrator.RD\desktop> .\Get-ACLonPath.ps1 -Path 1.txt
# ---ICACLS DACL---
# 1.txt NT AUTHORITY\SYSTEM:(F)
#       BUILTIN\Administrators:(F)
#       RD\Administrator:(F)

# 已成功处理 1 个文件; 处理 0 个文件时失败
# ---ICACLS SACL (/audit)---


# Audit : {System.Security.AccessControl.FileSystemAuditRule}
# Sddl  : O:BAG:DUD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LA)S:AI(AU;SA;CCSWWPLORC;;;LA)


[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Continue'
$overall = 0

# 先检测路径是否存在（不中断，只影响返回码和提示）
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output ("[WARN] Path not found: {0}" -f $Path)
    # 保持行为一致，仍尝试 icacls，最终以返回码为准
}

# DACL：icacls <path>
Write-Output '---ICACLS DACL---'
$daclOut  = & cmd /c "icacls `"$Path`"" 2>&1
$daclCode = $LASTEXITCODE
if ($daclOut) { $daclOut -join [Environment]::NewLine | Write-Output }

# SACL：icacls <path> /audit（需要管理员 + SeSecurityPrivilege，否则可能报错或拒绝访问）
Write-Output '---ICACLS SACL (/audit)---'
try {
  Get-Acl $Path -Audit | Format-List Audit,Sddl
  $saclCode = 0
} catch {
  Write-Output ("[ERROR] Failed to retrieve SACL: {0}" -f $_.Exception.Message)
  $saclCode = 1
}

# 组合返回码：若任一失败则返回非零；优先返回 SACL 的错误码（更严格）
if ($daclCode -ne 0 -or $saclCode -ne 0) {
    $overall = if ($saclCode -ne 0) { $saclCode } else { $daclCode }
} else {
    $overall = 0
}

$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
