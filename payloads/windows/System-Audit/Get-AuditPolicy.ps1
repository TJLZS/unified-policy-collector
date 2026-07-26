#调用方法：.\Get-AuditPolicy.ps1
#输出参考：
# 系统审核策略

# 类别/子类别                                    设置
# 系统
#   安全系统扩展                                  无审核
#
#   系统完整性                                   成功和失败
#
#   IPsec 驱动程序                              无审核
#
#   其他系统事件                                  成功和失败
#
#   安全状态更改                                  成功
#                         ........
#RETURN_CODE=0
$exitCode = 0
$ErrorActionPreference = 'Continue'
$out  = & cmd /c auditpol /get /category:* 2>&1
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0) {
    $out
} 
Write-Output ("RETURN_CODE={0}" -f $exitCode)