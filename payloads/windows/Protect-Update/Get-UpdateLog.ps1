<#
Get-WindowsUpdateLog.ps1
极简：使用 Get-WindowsUpdateLog 获取 Windows 更新日志；
出错时输出错误码，不中断。

Return codes:
  0 = 成功
  1 = Get-WindowsUpdateLog 无输出或文件未生成
  2 = Get-WindowsUpdateLog 执行失败
#>
#调用方法：.\Get-UpdateLog.ps1 [path\filename]
#输出参考：
# 2025/10/16 18:39:46.9576211 6536  6560  Shared          InitializeSus
# 2025/10/16 18:39:46.9589771 6536  6560  IdleTimer       Non-AoAc machine.  Aoac operations will be ignored.
# 2025/10/16 18:39:46.9594277 6536  6560  Agent           WU client version 10.0.19041.2913
# 2025/10/16 18:39:46.9602586 6536  6560  Agent           SleepStudyTracker: Machine is non-AOAC. Sleep study tracker disabled.
# 2025/10/16 18:39:46.9604206 6536  6560  Agent           Base directory: C:\Windows\SoftwareDistribution
# 2025/10/16 18:39:46.9619007 6536  6560  Agent           Datastore directory: C:\Windows\SoftwareDistribution\DataStore\DataStore.edb
# 2025/10/16 18:39:46.9637478 6536  6560  DataStore       JetEnableMultiInstance succeeded - applicable param count: 5, applied param count: 5
# 2025/10/16 18:39:47.0571960 6536  6560  Shared          UpdateNetworkState Ipv6, cNetworkInterfaces = 0.
# 2025/10/16 18:39:47.0574888 6536  6560  Shared          UpdateNetworkState Ipv4, cNetworkInterfaces = 1.
# 2025/10/16 18:39:47.0596676 6536  6560  Shared          Network state: Connected
# 2025/10/16 18:39:47.2286022 6536  6560  Shared          UpdateNetworkState Ipv6, cNetworkInterfaces = 0.
# 2025/10/16 18:39:47.2286432 6536  6560  Shared          UpdateNetworkState Ipv4, cNetworkInterfaces = 1.
# 2025/10/16 18:39:47.2286835 6536  6560  Shared          Power status changed
# 2025/10/16 18:39:47.2519957 6536  6560  Agent           Initializing global settings cache
# 2025/10/16 18:39:47.2520119 6536  6560  Agent           WSUS server: (null)
# 2025/10/16 18:39:47.2520169 6536  6560  Agent           WSUS status server: (null)
# 2025/10/16 18:39:47.2520278 6536  6560  Agent           Alternate Download Server: (null)
# 2025/10/16 18:39:47.2520532 6536  6560  Agent           Fill Empty Content Urls: No
# 2025/10/16 18:39:47.2520580 6536  6560  Agent           Target group: (Unassigned Computers)
# 2025/10/16 18:39:47.2520619 6536  6560  Agent           Windows Update access disabled: No
# 2025/10/16 18:39:47.2520689 6536  6560  Agent           Do not connect to Windows Update Internet locations: No
# 2025/10/16 18:39:47.2551785 6536  6560  Agent               Timer: 29A863E7-8609-4D1E-B7CD-5668F857F1DB, Expires 2024-11-30 03:34:00, not idle-only, not network-only
# 2025/10/16 18:39:47.2632633 6536  6560  Agent           Initializing Windows Update Agent
# 2025/10/16 18:39:47.2636214 6536  6560  DownloadManager Download manager restoring 0 downloads
# 2025/10/16 18:39:47.2638849 6536  6560  Agent           CPersistentTimeoutScheduler | GetTimer, returned hr = 0x00000000
# 2025/10/16 18:39:47.2640044 6536  6560  Agent           Adding timer: 
# 2025/10/16 18:39:47.2640226 6536  6560  Agent               Timer: 29A863E7-8609-4D1E-B7CD-5668F857F1DB, Expires 2025-10-16 10:39:49, not idle-only, not network-only
# 2025/10/16 18:39:47.2660346 6536  6560  IdleTimer       IdleTimer::NetworkStateChanged. Network connected? Yes
# 2025/10/16 18:39:47.2670568 6536  6628  IdleTimer       WU operation (CDiscoveryCall::Init ID 1) started; operation # 4; does use network; is not at background priority
# 2025/10/16 18:39:47.2676270 6424  6520  ComApi          *QUEUED* SLS Discovery
# 2025/10/16 18:39:47.2821906 6536  6644  SLS             Get response for service 2B81F1BF-356C-4FA1-90F1-7581A62C6764 - forceExpire[False] asyncRefreshOnExpiry[True]
# 2025/10/16 18:39:47.2822146 6536  6644  SLS             path used for cache lookup: /SLS/{2B81F1BF-356C-4FA1-90F1-7581A62C6764}/x64/10.0.19045.2965/0?CH=641&L=zh-CN&P=&PT=0x30&WUA=10.0.19041.2913&MK=Red+Hat&MD=KVM
# 2025/10/16 18:39:47.2863777 6536  6640  DownloadManager HandleScavengeSandboxTask: Cleaning up sandboxes.
# 2025/10/16 18:39:47.2897376 6456  6564  ComApi          * START *   Federated Search ClientId = Windows Defender (cV: sF3vtbMuJE60gBgl.1.0)
# 2025/10/16 18:39:47.2906629 6536  6592  IdleTimer       WU operation (SR.Windows Defender ID 2) started; operation # 9; does use network; is not at background priority
# 2025/10/16 18:39:47.2930662 6536  6676  Agent           Processing auto/pending service registrations and recovery (cV: sF3vtbMuJE60gBgl.1.0.0.0)
# 2025/10/16 18:39:47.3483649 6536  6644  SLS             Revision Check is on with Environment ID [StoreFrontsRS5] Revision [2]...
# 2025/10/16 18:39:47.3483749 6536  6644  SLS             Retrieving SLS response from server using ETAG QVZBLw7SCzNwdXLhJgNGj9GETIn2aqqVCfVbLc5UDHI=_43199"..."
# 2025/10/16 18:39:47.3498804 6536  6644  Misc            *FAILED* [800703F0] Failed to get proxy settings token, not impersonating user
# 2025/10/16 18:39:47.3667887 6536  6644  SLS             Making request with URL HTTPS://slscr.update.microsoft.com/SLS/{2B81F1BF-356C-4FA1-90F1-7581A62C6764}/x64/10.0.19045.2965/0?CH=641&L=zh-CN&P=&PT=0x30&WUA=10.0.19041.2913&MK=Red+Hat&MD=KVM and send SLS events.
# 2025/10/16 18:39:47.8234543 6536  6640  DownloadManager PurgeExpiredFiles::Found 9 expired files to delete.
# 2025/10/16 18:39:47.8234596 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\283e8289b5f0c4d9a34cf7a410b9599729d34a44.
# 2025/10/16 18:39:47.8249565 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\ef8a3cb55db581dc1bcf416af6863762cf94d73d.
# 2025/10/16 18:39:47.8260653 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\5cf102cd92797452e94271faa0ceb7e9e63c1e43.
# 2025/10/16 18:39:47.8270416 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\6103d9f6bf95c772c8b7ee89aee370cdca4642f8.
# 2025/10/16 18:39:47.8276004 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\d3f6f8300855e56b8ed00da6dac55a3c4cbf8c20.
# 2025/10/16 18:39:47.8355321 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\166b2361c50f918717f65fca3bebbb3f6f714115.
# 2025/10/16 18:39:47.8416251 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\c323b1cee75af8afab07b5321224869f4c08ba73.
# 2025/10/16 18:39:47.8421757 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\fb9fcdb1a54df84169242763b22f164b9a28a415.
# 2025/10/16 18:39:47.8424006 6536  6640  DownloadManager PurgeExpiredFiles::Deleting expired file at C:\Windows\SoftwareDistribution\Download\121cbe480aaf800d325df633875a3bbba3edc47b.
# 2025/10/16 18:39:47.9735656 6536  6640  DownloadManager PurgeExpiredUpdates: Found 0 non expired updates.
# 2025/10/16 18:39:47.9738938 6536  6640  DownloadManager PurgeExpiredUpdates: Found 221 expired updates.
#......

[CmdletBinding()]
param(
    # 可选：输出日志文件路径；未指定则默认存放到当前目录下的 WindowsUpdate.log
    [string]$OutputPath = "$(Get-Location)\WindowsUpdate.log"
)

$ErrorActionPreference = 'Continue'
$overall = 0



try {
    Write-Output ("---Attempt: Get-WindowsUpdateLog -LogPath `"{0}`"---" -f $OutputPath)

    # 确保目录存在
    $dir = Split-Path -Path $OutputPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    # 运行 Get-WindowsUpdateLog
    $out = Get-WindowsUpdateLog -LogPath $OutputPath -ErrorAction Stop

    if ((Test-Path -LiteralPath $OutputPath) -and ((Get-Item $OutputPath).Length -gt 0)) {
        Write-Output ("[INFO] Windows Update log generated successfully: {0}" -f $OutputPath)
        
        # 读取并输出日志内容，供 main.py 捕获
        Write-Output "---Windows Update Log Content---"
        Get-Content -Path $OutputPath -Encoding UTF8 | ForEach-Object { Write-Output $_ }
        Write-Output "---End of Windows Update Log---"
        
        # 删除临时日志文件
        Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
        
        $overall = 0
    } else {
        Write-Output ("[WARN] Get-WindowsUpdateLog executed but file not found or empty: {0}" -f $OutputPath)
        $overall = 1
    }
}
catch {
    Write-Output ("[ERROR] Get-WindowsUpdateLog failed: {0}" -f $_.Exception.Message)
    $overall = 2
}

$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
