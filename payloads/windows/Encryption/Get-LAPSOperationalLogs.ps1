#调用方法：.\Get-LAPSOperationalLogs.ps1
#输出参考：
# PS C:\Users\Administrator\Desktop> .\Get-LAPSOperationalLogs.ps1 5
# ---Run: wevtutil qe "Microsoft-Windows-LAPS/Operational" /c:5 /rd:true /f:text---
# Event[0]:
#   Log Name: Microsoft-Windows-LAPS/Operational
#   Source: Microsoft-Windows-LAPS
#   Date: 2025-11-12T15:49:43.5630000Z
#   Event ID: 10004
#   Task: N/A
#   Level: 信息
#   Opcode: 信息
#   Keyword: N/A
#   User: S-1-5-18
#   User Name: NT AUTHORITY\SYSTEM
#   Computer: Win10-Book-2.rd.com
#   Description:
# LAPS 策略处理成功。

#  有关详细信息，请参阅https://go.microsoft.com/fwlink/?linkid=2220550。

# Event[1]:
#   Log Name: Microsoft-Windows-LAPS/Operational
#   Source: Microsoft-Windows-LAPS
#   Date: 2025-11-12T15:49:43.5630000Z
#   Event ID: 10024
#   Task: N/A
#   Level: 信息
#   Opcode: 信息
#   Keyword: N/A
#   User: S-1-5-18
#   User Name: NT AUTHORITY\SYSTEM
#   Computer: Win10-Book-2.rd.com
#   Description:
# LAPS 策略已配置为禁用。

#  有关详细信息，请参阅https://go.microsoft.com/fwlink/?linkid=2220550。

# Event[2]:
#   Log Name: Microsoft-Windows-LAPS/Operational
#   Source: Microsoft-Windows-LAPS
#   Date: 2025-11-12T15:49:43.5560000Z
#   Event ID: 10003
#   Task: N/A
#   Level: 信息
#   Opcode: 信息
#   Keyword: N/A
#   User: S-1-5-18
#   User Name: NT AUTHORITY\SYSTEM
#   Computer: Win10-Book-2.rd.com
#   Description:
# LAPS 策略处理现在正在启动。

#  有关详细信息，请参阅https://go.microsoft.com/fwlink/?linkid=2220550。

# Event[3]:
#   Log Name: Microsoft-Windows-LAPS/Operational
#   Source: Microsoft-Windows-LAPS
#   Date: 2025-11-12T15:45:45.5120000Z
#   Event ID: 10004
#   Task: N/A
#   Level: 信息
#   Opcode: 信息
#   Keyword: N/A
#   User: S-1-5-18
#   User Name: NT AUTHORITY\SYSTEM
#   Computer: Win10-Book-2.rd.com
#   Description:
# LAPS 策略处理成功。

#  有关详细信息，请参阅https://go.microsoft.com/fwlink/?linkid=2220550。

# Event[4]:
#   Log Name: Microsoft-Windows-LAPS/Operational
#   Source: Microsoft-Windows-LAPS
#   Date: 2025-11-12T15:45:45.5120000Z
#   Event ID: 10024
#   Task: N/A
#   Level: 信息
#   Opcode: 信息
#   Keyword: N/A
#   User: S-1-5-18
#   User Name: NT AUTHORITY\SYSTEM
#   Computer: Win10-Book-2.rd.com
#   Description:
# LAPS 策略已配置为禁用。

#  有关详细信息，请参阅https://go.microsoft.com/fwlink/?linkid=2220550。

# RETURN_CODE=0

[CmdletBinding()]
param(
    # 要获取的最新日志条数，默认 50
    [int]$Count = 50
)

$ErrorActionPreference = 'Continue'
$overall = 0


# 构造并运行 wevtutil 命令
$wevtCmd = "wevtutil qe `"Microsoft-Windows-LAPS/Operational`" /c:$Count /rd:true /f:text"
Write-Output ("---Run: {0}---" -f $wevtCmd)

# 使用 cmd /c 调用以获得原始文本输出，并捕获 exit code
$out = & cmd /c $wevtCmd 2>&1
$code = $LASTEXITCODE

# 打印原始输出（若有）
if ($out -and $out.Count -gt 0) {
    $out -join [Environment]::NewLine | Write-Output
}

# 决定返回码
if ($code -ne 0) {
    Write-Output ("[ERROR] wevtutil exited with code {0}." -f $code)
    $overall = 2
} else {
    if (-not $out -or $out.Count -eq 0 -or ($out -join '').Trim() -eq '') {
        Write-Output "[INFO] wevtutil returned no events."
        $overall = 1
    } else {
        $overall = 0
    }
}

# 不抛异常；同步 LASTEXITCODE 并输出最终 RETURN_CODE
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
