#调用方法：.\Get-CertificateStores.ps1
#输出参考：
# ---Run: Get-ChildItem Cert:\LocalMachine\Root | Select Subject, Thumbprint, NotAfter---

# Subject
# -------
# CN=Microsoft Root Certificate Authority, DC=microsoft, DC=com
# CN=Thawte Timestamping CA, OU=Thawte Certification, O=Thawte, L=Durbanville, S=Western Cape, C=ZA
# CN=Microsoft Root Authority, OU=Microsoft Corporation, OU=Copyright (c) 1997 Microsoft Corp.
# CN=Symantec Enterprise Mobile Root for Microsoft, O=Symantec Corporation, C=US
# CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
# CN=Microsoft Authenticode(tm) Root Authority, O=MSFT, C=US
# CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
# CN=Microsoft ECC TS Root Certificate Authority 2018, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
# OU=Copyright (c) 1997 Microsoft Corp., OU=Microsoft Time Stamping Service Root, OU=Microsoft Corporation, O=Microsoft Trust Network
# OU="NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.", OU=VeriSign Time Stamping Service Root, OU="VeriSign, Inc.", O=VeriSign Trust Network
# CN=Microsoft ECC Product Root Certificate Authority 2018, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
# CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=Microsoft Time Stamp Root Certificate Authority 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
# CN=DigiCert Global Root G2, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=DigiCert Trusted Root G4, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=DST Root CA X3, O=Digital Signature Trust Co.
# CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R3
# CN=Baltimore CyberTrust Root, OU=CyberTrust, O=Baltimore, C=IE
# CN=AAA Certificate Services, O=Comodo CA Limited, L=Salford, S=Greater Manchester, C=GB
# CN=ISRG Root X1, O=Internet Security Research Group, C=US
# CN=GlobalSign Root CA, OU=Root CA, O=GlobalSign nv-sa, C=BE
# OU=Starfield Class 2 Certification Authority, O="Starfield Technologies, Inc.", C=US
# CN=DigiCert Global Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=DigiCert Global Root G3, OU=www.digicert.com, O=DigiCert Inc, C=US
# OU=Class 3 Public Primary Certification Authority, O="VeriSign, Inc.", C=US
# CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
# CN=Hotspot 2.0 Trust Root CA - 03, O=WFA Hotspot 2.0, C=US
# CN=VeriSign Class 3 Public Primary Certification Authority - G5, OU="(c) 2006 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSig...
# CN=VeriSign Universal Root Certification Authority, OU="(c) 2008 VeriSign, Inc. - For authorized use only", OU=VeriSign Trust Network, O="VeriSign, Inc.", C=US
# CN=GlobalSign, O=GlobalSign, OU=GlobalSign ECC Root CA - R5
# CN=DigiCert Assured ID Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US

# RETURN_CODE=0

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$overall = 0


try {
    Write-Output '---Run: Get-ChildItem Cert:\LocalMachine\Root | Select Subject, Thumbprint, NotAfter---'
    $certs = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction Stop | Select-Object Subject, Thumbprint, NotAfter

    if ($null -ne $certs -and ($certs | Measure-Object).Count -gt 0) {
        # 原样输出（表格形式更易读）
        $certs | Format-Table -AutoSize | Out-String | Write-Output
        $overall = 0
    } else {
        Write-Output '[WARN] No certificates found in Cert:\LocalMachine\Root or the result is empty.'
        $overall = 1
    }
}
catch {
    Write-Output ("[ERROR] Command failed: {0}" -f $_.Exception.Message)
    $overall = 2
}

# 同步到 LASTEXITCODE，便于上层脚本判断
$global:LASTEXITCODE = $overall
Write-Output ("RETURN_CODE={0}" -f $overall)
