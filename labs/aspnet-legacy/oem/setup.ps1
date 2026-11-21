$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\Windows\Temp\proofcms-aspnet-setup.log -Force

Write-Host "== IIS features =="
Import-Module ServerManager
Add-WindowsFeature Web-Server, Web-Common-Http, Web-Static-Content, Web-Default-Doc, `
    Web-Http-Errors, Web-App-Dev, Web-Asp-Net, Web-Net-Ext, Web-ISAPI-Ext, `
    Web-ISAPI-Filter, Web-Mgmt-Console | Out-Null

Write-Host "== Register ASP.NET 4.0 =="
$regiis = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe"
if (Test-Path $regiis) {
    & $regiis -i 2>&1 | Out-Null
    Write-Host "aspnet_regiis -i completed"
} else {
    Write-Host "ERROR: .NET 4.0 is not installed"
}

Write-Host "== App pool =="
$appcmd = "$env:windir\system32\inetsrv\appcmd.exe"
& $appcmd set apppool /apppool.name:DefaultAppPool /managedRuntimeVersion:v4.0 2>&1 | Out-Null
& $appcmd set app "Default Web Site/" /applicationPool:DefaultAppPool 2>&1 | Out-Null

Write-Host "== Copy apps =="
foreach ($name in 'proofcms-3332', 'proofcms-3416') {
    $dest = "C:\inetpub\wwwroot\$name"
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item "C:\OEM\apps\$name\*" $dest -Recurse -Force
}

Write-Host "== IIS applications =="
& $appcmd add app /site.name:"Default Web Site" /path:/proofcms-3332 /physicalPath:C:\inetpub\wwwroot\proofcms-3332 2>&1 | Out-Null
& $appcmd add app /site.name:"Default Web Site" /path:/proofcms-3416 /physicalPath:C:\inetpub\wwwroot\proofcms-3416 2>&1 | Out-Null
& $appcmd set app "Default Web Site/proofcms-3332" /applicationPool:DefaultAppPool 2>&1 | Out-Null
& $appcmd set app "Default Web Site/proofcms-3416" /applicationPool:DefaultAppPool 2>&1 | Out-Null

Write-Host "== Lab firewall =="
netsh advfirewall set allprofiles state off 2>&1 | Out-Null

Write-Host "== Ready marker =="
Set-Content -Path C:\inetpub\wwwroot\proofcms-aspnet-ready.txt -Value 'PROOFCMS_ASPNET_READY' -Encoding ASCII

Write-Host "== Restart IIS =="
iisreset /restart 2>&1 | Out-Null
Start-Sleep -Seconds 2

Write-Host "== Check =="
foreach ($url in 'http://127.0.0.1/proofcms-3332/default.aspx', 'http://127.0.0.1/proofcms-3416/login.aspx') {
    try {
        $client = New-Object System.Net.WebClient
        $body = $client.DownloadString($url)
        Write-Output ("$url OK len=" + $body.Length)
    } catch {
        Write-Output ("$url ERR: " + $_.Exception.Message)
    }
}

Stop-Transcript
