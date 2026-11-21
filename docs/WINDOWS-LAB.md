# Windows / IIS lab assessment

## Current host

The local Docker Desktop daemon is in **Linux container mode**:

```text
OSType=linux
contexts: default, desktop-linux
```

Windows containers are not available in this mode. Switching requires
Docker Desktop → **Switch to Windows containers** (Windows 10/11 Pro or
Enterprise, Hyper-V, administrator rights), which restarts the daemon and
temporarily removes Linux-container support. That is a host-level change and
is not something the scanner can do by itself.

## Why a Windows container is not enough for MS10-070 / MS11-100

Even after switching to Windows containers, a **vulnerable** .NET Framework
2.0 runtime is not available from public images:

- `mcr.microsoft.com/windows/servercore:ltsc2019` can enable the NetFx3
  feature, but that build is fully patched (MS10-070 and MS11-100 are from
  2010/2011).
- There is no official unpatched .NET 2.0/3.5 container image.
- A true vulnerable lab needs an old Windows Server 2008 R2/2012 VM with
  .NET 2.0 SP2 (or 3.5 SP1) installed **before** the MS10-070/MS11-100
  patches, or the original .NET 4.0 RTM build on Server 2008 R2 SP1 (the
  approach used below).

Consequently, CVE-2010-3332 and CVE-2011-3416 were validated on a Server 2008
R2 SP1 VM with the original .NET 4.0 RTM build (see below); the SP1 .NET 3.5.1
feature is already patched for MS10-070.

## What can still be validated

- Detector behavior (version header, response path, GeneXus markers) against
  a patched IIS/.NET 3.5 container, if Windows container mode is enabled.
- Surface gating: a patched lab with no `.axd`/`__ASPXAUTH` must return
  `INCONCLUSIVE`/`NOT_AFFECTED`, not `LIKELY_VULNERABLE`.
- PHP-on-Windows CVEs: CVE-2024-4577 is now CONFIRMED on the
  `dockur/windows` VM (see below); CVE-2024-5585 still needs a fixture.

## ASP.NET legacy (CVE-2010-3332 / CVE-2011-3416)

- Validated on a `dockur/windows` **Server 2008 R2 SP1** VM with **.NET Framework
  4.0 RTM** (4.0.30319.1). The SP1 image already includes MS10-070 in its
  .NET 3.5.1 feature, so the lab installs the original 4.0 RTM build instead.
- 2010-3332: the module's safe `ScriptResource.axd?d=` control/tamper
  differential returns 200/500 on 4.0 RTM and no differential on 4.5.
- 2011-3416: a login that calls `FormsAuthentication.SetAuthCookie` with
  `admin\x00proofcms` yields a ticket for `admin` on 4.0 RTM; .NET 4.5 returns
  a 500 ("Value does not fall within the expected range").
- Harness: `labs/aspnet-legacy` (compose, OEM, apps); proofs:
  `labs/cve-2010-3332/verify.py`, `labs/cve-2011-3416/verify.py`.
- Use `ADAPTER: "rtl8139"`: the 2008 R2 image has no virtio-net driver.

## PHP-CGI (CVE-2024-4577)

- Validated on a `dockur/windows` Server 2019 VM with Apache 2.4.71
  `mod_cgi` and PHP 8.2.19 NTS x64 (control 8.2.20). The `%AD` payload needs
  the system ANSI code page 936 (or 950/932); IIS CGI passes the query string
  percent-encoded in `argv` and does not reproduce.
- `display_errors=Off` is required on PHP 8.2 because the `allow_url_include`
  deprecation is printed before the CGI headers and Apache returns 500.
- See `labs/cve-2024-4577` for the compose, OEM setup, and verifier.

## Web Deploy (CVE-2025-53772)

- Requires Windows Server + IIS + Web Deploy 4.0 **10.0.2000** (fixed in
  **10.0.2001**) and valid credentials. The flaw is a BinaryFormatter
  deserialization of the GZip+Base64 `MSDeploy.SyncOptions` header on
  `msdeploy.axd` / `msdeployagentservice`.
- The module is passive: it checks `/msdeploy.axd` and sends a header-only
  probe **without** `MSDeploy.SyncOptions`. It never sends a serialized
  object.
- The active proof was validated on a `dockur/windows` Server 2019 VM with Web
  Deploy 10.0.2000: the repo `trigger.py` (public TypeConfuseDelegate template)
  wrote `C:\Windows\Temp\pwned.txt` through the NTLM Agent Service. Upgrading
  the same VM to 10.0.2001 stopped the payload. See `labs/VALIDATED.md`.

## Optional Windows VM: dockur/windows

The host has `/dev/kvm` exposed to Docker, so `dockur/windows` can run a real
Windows Server VM inside a Linux container (no Windows-container mode switch).

- `labs/cve-2025-53772` provides the optional profiles `windows` (vulnerable
  Web Deploy 10.0.2000) and `windows-control` (patched 10.0.2001).
- `labs/cve-2024-4577` uses the same image with its own volume
  (`proofcms-4577-storage`): web viewer `8008`, RDP `3391`, Apache `8182`.
- Web viewer: `http://127.0.0.1:8006` (vuln) / `8007` (control); RDP: `3389` /
  `3390`; Web Deploy: `8180`/`8172` (vuln) and `8181`/`8173` (control).
- The VM uses 2 GB RAM and a 40 GB disk in the Docker named volumes
  `proofcms-53772-vuln-storage` / `proofcms-53772-control-storage`; run one VM
  at a time on this host.
  Docker Desktop's WSL2 limit must be at least 4 GB (6 GB recommended):
  `%UserProfile%\.wslconfig` → `memory=6GB`, then `wsl --shutdown` and restart
  Docker Desktop. The default 3 GB limit is not enough for Server 2019.
- **Both MSIs are archived:** `windows/WebDeploy_10.0.2000.msi` (vulnerable,
  SHA-256 `2befd8da31817d96875815ef1d0c30e11bd26838f7b65da6fd7ea80b041b3489`)
  and `windows/WebDeploy_10.0.2001.msi` (patched control). The OEM scripts
  install only their own version. The module itself stays passive.

## Options

1. Provide a Windows VM with an old .NET 2.0/3.5 snapshot (best for CONFIRMED).
2. Enable Windows containers and accept a **surface-only** patched lab (not a
   CVE confirmation).
3. Keep the Windows-only modules `BLOCKED_EXTERNAL` and focus active work on
   the Linux labs.

The Linux-based labs remain the default; nothing in the repository requires
Windows mode to run the test suite or the Linux labs.
