<#
Get-LocalUsers.ps1
逐个列出本地用户账户详情；极简风格：原样输出、不抛异常、末尾 RETURN_CODE
Return codes:
  0 = 成功
  1 = Get-LocalUser 返回空
  2 = Get-LocalUser 执行失败
  3 = net user 回退失败或无用户
  4 = ADSI 兜底失败或无结果
#>
#调用方法：.\Get-LocalUserAccounts.ps1
#输出参考：
# ---Attempt: Get-LocalUser (Microsoft.PowerShell.LocalAccounts)---


# Name                  : Administrator
# SID                   : S-1-5-21-86141825-4198905565-3109298994-500
# Enabled               : True
# Description           : 管理计算机(域)的内置帐户
# PasswordRequired      : True
# PasswordNeverExpires  :
# UserMayChangePassword : True
# LastLogon             : 2025/10/16 14:55:30
# PasswordLastSet       : 2025/10/14 17:16:53
# AccountExpires        :
# PrincipalSource       : Local
# ObjectClass           : 用户
#
#RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0
$gotResults = $false


# ===== 1) 首选：Get-LocalUser =====
try {
    Write-Output '---Attempt: Get-LocalUser (Microsoft.PowerShell.LocalAccounts)---'
    $users = Get-LocalUser -ErrorAction Stop

    if ($null -ne $users -and ($users | Measure-Object).Count -gt 0) {
        foreach ($u in $users) {
            $u | Select-Object `
                Name, SID, Enabled, Description, `
                PasswordRequired, PasswordNeverExpires, UserMayChangePassword, `
                LastLogon, PasswordLastSet, AccountExpires, `
                PrincipalSource, ObjectClass |
            Format-List * | Out-String | Write-Output
        }
        $gotResults = $true
        $overall = 0
    } else {
        Write-Output '[WARN] Get-LocalUser returned no users.'
        if ($overall -eq 0) { $overall = 1 }
    }
}
catch {
    Write-Output ("[ERROR] Get-LocalUser failed: {0}" -f $_.Exception.Message)
    if ($overall -lt 2) { $overall = 2 }
}

# ===== 2) 回退：net user =====
if (-not $gotResults) {
    Write-Output '---Fallback: net user (list & per-user details)---'
    $listOut = & cmd /c 'net user' 2>&1
    $listCode = $LASTEXITCODE

    if ($listOut -and $listCode -eq 0) {
        # 粗略解析用户名：去掉标题/分隔/结尾提示行，并把剩余行按空白拆分为用户名
        $names = @()
        foreach ($line in $listOut) {
            $t = $line.Trim()
            if ($t -eq '') { continue }
            if ($t -like 'User accounts for*') { continue }
            if ($t -like 'The command completed successfully.*') { continue }
            if ($t -match '^-+$') { continue }
            # 其余行包含用户名，以空白分隔
            $t.Split(" `t".ToCharArray(), [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object {
                $names += $_
            }
        }

        $names = $names | Where-Object { $_ -and $_ -ne '' } | Select-Object -Unique

        if ($names.Count -gt 0) {
            foreach ($n in $names) {
                Write-Output ("=== LOCAL USER (net user): {0} ===" -f $n)
                $detail = & cmd /c ("net user `"{0}`"" -f $n) 2>&1
                if ($detail) { $detail -join [Environment]::NewLine | Write-Output }
            }
            $gotResults = $true
            $overall = 0
        } else {
            Write-Output '[WARN] net user returned empty user list.'
            if ($overall -lt 3) { $overall = 3 }
        }
    } else {
        Write-Output ("[ERROR] net user failed or no output (ExitCode={0})." -f $listCode)
        if ($overall -lt 3) { $overall = 3 }
    }
}



# ===== 结束：不抛异常，设置 LASTEXITCODE 并输出 RETURN_CODE =====
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
