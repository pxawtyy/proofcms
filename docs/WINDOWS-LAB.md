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
  patches, or a prebuilt vulnerable VM snapshot.

Consequently, CVE-2010-3332 and CVE-2011-3416 stay `BLOCKED_EXTERNAL` in
`labs/VALIDATED.md`; the modules are surface-gated and will only promote to
`LIKELY_VULNERABLE` when the relevant surface is observed.

## What can still be validated

- Detector behavior (version header, response path, GeneXus markers) against
  a patched IIS/.NET 3.5 container, if Windows container mode is enabled.
- Surface gating: a patched lab with no `.axd`/`__ASPXAUTH` must return
  `INCONCLUSIVE`/`NOT_AFFECTED`, not `LIKELY_VULNERABLE`.
- PHP-on-Windows CVEs (CVE-2024-4577, CVE-2024-5585) need a Windows container
  plus a vulnerable PHP build; the same Windows-mode prerequisite applies.

## Options

1. Provide a Windows VM with an old .NET 2.0/3.5 snapshot (best for CONFIRMED).
2. Enable Windows containers and accept a **surface-only** patched lab (not a
   CVE confirmation).
3. Keep the Windows-only modules `BLOCKED_EXTERNAL` and focus active work on
   the Linux labs.

The Linux-based labs remain the default; nothing in the repository requires
Windows mode to run the test suite or the Linux labs.
