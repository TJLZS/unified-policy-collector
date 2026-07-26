# 调用方法：.\Get-PasswordPolicy.ps1 -Scope Local/Domain
#输出参考：
# PS C:\Users\Administrator.RD\desktop> .\Get-PasswordPolicy.ps1 Domain
# 强制用户在时间到期之后多久必须注销?:     从不
# 密码最短使用期限(天):                    1
# 密码最长使用期限(天):                    42
# 密码长度最小值:                          7
# 保持的密码历史记录长度:                  24
# 锁定阈值:                                从不
# 锁定持续时间(分):                        30
# 锁定观测窗口(分):                        30
# 计算机角色:                              BACKUP
# 命令成功完成。

# RETURN_CODE=0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Domain','Local')]
    [string]$Scope
)

$ErrorActionPreference = 'Continue'
$overall = 0

switch ($Scope) {
    'Domain' {
        # 域策略：只输出 net accounts /domain 的原始控制台输出
        $out = & cmd /c 'net accounts /domain' 2>&1
        $overall = $LASTEXITCODE
        if ($out) { $out -join [Environment]::NewLine | Write-Output }
    }

    'Local' {
        # 本地策略：输出 net accounts 的原文 + secedit 导出过程的原文 + 导出的 INF 文件内容
        Write-Output '---NET ACCOUNTS (LOCAL)---'
        $netOut = & cmd /c 'net accounts' 2>&1
        $netCode = $LASTEXITCODE
        if ($netOut) { $netOut -join [Environment]::NewLine | Write-Output }

        $tmp = Join-Path $env:TEMP ("secpol_{0:yyyyMMddHHmmssfff}.inf" -f (Get-Date))
        Write-Output '---SECEDIT EXPORT STDOUT---'
        $secOut = & cmd /c "secedit /export  /cfg `"$tmp`"" 2>&1
        $secCode = $LASTEXITCODE
        if ($secOut) { $secOut -join [Environment]::NewLine | Write-Output }

        if (Test-Path -LiteralPath $tmp) {
            Write-Output '---SECEDIT INF CONTENT---'
            Get-Content -LiteralPath $tmp | Write-Output
        }

        # 组合返回码：两者都成功则 0，否则优先返回 secedit 的错误码，否则返回 net 的错误码
        if ($netCode -ne 0 -or $secCode -ne 0) {
            $overall = if ($secCode -ne 0) { $secCode } else { $netCode }
        } else {
            $overall = 0
        }
    }
}

# 不中断；只回传错误码。既打印一行，也同步到 $LASTEXITCODE 便于上游判断。
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
