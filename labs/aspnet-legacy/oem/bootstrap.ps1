$ErrorActionPreference = 'Continue'
Start-Transcript -Path C:\Windows\Temp\proofcms-aspnet-bootstrap.log -Force

$clr = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\clr.dll"
if (Test-Path $clr) {
    Write-Host "== .NET 4.0 already installed =="
    Stop-Transcript
    & "$PSScriptRoot\setup.ps1"
} else {
    Write-Host "== Installing .NET Framework 4.0 RTM =="
    $installer = $null
    foreach ($root in @('Z:\', '\\host.lan\Data\')) {
        if ($root -and (Test-Path (Join-Path $root 'dotNetFx40_Full_x86_x64.exe'))) {
            $installer = Join-Path $root 'dotNetFx40_Full_x86_x64.exe'
            break
        }
    }
    if (-not $installer) {
        throw 'dotNetFx40_Full_x86_x64.exe not found in Z:\ or \\host.lan\Data'
    }
    $process = Start-Process -FilePath $installer -ArgumentList '/q', '/norestart' -PassThru
    $process | Wait-Process -Timeout 600 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' `
        -Name 'ProofCMSAspnetSetup' `
        -Value 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\setup.ps1' -Force
    Write-Host "== Rebooting to finish the .NET install =="
    Stop-Transcript
    shutdown /r /t 10 /f
}
