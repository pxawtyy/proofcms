@echo off
setlocal
echo [ProofCMS] ASP.NET legacy OEM setup starting
powershell -NoProfile -ExecutionPolicy Bypass -File C:\OEM\bootstrap.ps1
echo [ProofCMS] OEM bootstrap finished.
endlocal
