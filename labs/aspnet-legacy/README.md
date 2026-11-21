# ASP.NET legacy lab harness (CVE-2010-3332 / CVE-2011-3416)

Windows Server 2008 R2 SP1 VM with **.NET Framework 4.0 RTM** and two IIS
applications:

- `/proofcms-3332/` - Web Forms page with a `ScriptResource.axd` token.
- `/proofcms-3416/` - Forms Authentication login and a protected page.

> **Status: used for the CONFIRMED 2026-11-21 runs.** .NET 4.0 RTM is the
> vulnerable build; the .NET 4.5 in-place update is the patched control.

## Why .NET 4.0 RTM

Server 2008 R2 SP1's built-in .NET 3.5.1 feature already includes MS10-070, so
the lab installs the original .NET 4.0 RTM build (4.0.30319.1, April 2010).
That build predates MS10-070 (September 2010) and MS11-100 (December 2011).

## Prerequisites

- Docker Desktop with `/dev/kvm`, 6 GB WSL2 memory, 2 GB free for the VM.
- `windows/dotNetFx40_Full_x86_x64.exe` and
  `windows/dotnetfx45_full_x86_x64.exe` in
  `D:/ProofCMS-Labs/archives/windows/`.
- Run **one** VM at a time.

## Bring-up

```powershell
docker compose -f labs/aspnet-legacy/compose.yml --profile windows up -d
```

The OEM bootstrap installs .NET 4.0, reboots, and a RunOnce entry runs
`setup.ps1`, which enables IIS/ASP.NET, creates both IIS applications, disables
the lab firewall, and writes the ready marker. Poll
`http://127.0.0.1:8183/proofcms-aspnet-ready.txt`.

| Endpoint | Host port |
|---|---|
| Web viewer | 8009 |
| RDP | 3392 |
| HTTP | 8183 |

Default VM credentials: `proofcms` / `proofcms-lab-password`.

## Apps

- **3332**: a `ScriptManager` with `MicrosoftAjax.js` plus a
  `RequiredFieldValidator` emits `ScriptResource.axd?d=...&t=...`.
- **3416**: `login.aspx` calls
  `FormsAuthentication.SetAuthCookie(Request.Form["user"], false)` for the lab
  password; `protected.aspx` prints `User.Identity.Name`.

Both directories are registered as IIS applications (the Forms Authentication
section cannot live in a plain virtual directory).

## Control

Install the .NET 4.5 in-place update and reboot:

```powershell
C:\Windows\Temp\dotnetfx45_full_x86_x64.exe /q /norestart
```

Then re-run `labs/cve-2010-3332/verify.py` and
`labs/cve-2011-3416/verify.py`; both must return `NOT_CONFIRMED`.

## Pitfalls

- Use `ADAPTER: "rtl8139"` in the compose. The 2008 R2 image has no virtio-net
  driver, so the default adapter leaves the guest without a working NIC.
- `Add-WindowsFeature` is the native IIS installer on 2008 R2; the DISM
  `IIS-*` feature names silently did nothing on this image.
- `Invoke-WebRequest` does not exist in PowerShell 2.0; use `WebClient`.
- `httpRuntime targetFramework` is a .NET 4.5 attribute and breaks a 4.0 app.
