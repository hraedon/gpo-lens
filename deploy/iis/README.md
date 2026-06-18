# Hosting gpo-lens on IIS

gpo-lens runs as a normal ASGI app (uvicorn). On Windows the supported pattern
is **IIS + HttpPlatformHandler**: IIS terminates TLS and reverse-proxies to a
uvicorn process it launches and supervises. This mirrors the cert-watch
deployment so the two tools install and run the same way — gpo-lens just takes
its own port (default **8443**) since cert-watch typically owns 443.

## Prerequisites

- Windows Server with IIS.
- [HttpPlatformHandler](https://www.iis.net/downloads/microsoft/httpplatformhandler)
  (Microsoft-signed module — the only third-party prerequisite).
- Python 3.12+ available to the installer (the Python Install Manager runtime is
  fine; see *Why a shared Python install* below).
- A TLS certificate in `LocalMachine\My` (you can reuse the machine certificate).

## Quick start

From an **elevated** PowerShell, in a checkout of this repo:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 `
    -ConfigureIIS `
    -Port 8443 `
    -HostName host.example.com `
    -TlsCertThumbprint "<thumbprint from LocalMachine\My>"
```

That single command:

1. Resolves a usable Python and (if it is user-scoped) copies it to a shared
   location the app pool can read.
2. Creates `C:\ProgramData\gpo-lens` (data dir + logs) and a venv, and
   `pip install`s `gpo-lens[web]` into it.
3. Lays down `web.config` in `C:\inetpub\gpo-lens` (paths rewritten to your
   `-InstallDir`).
4. Creates the `gpo-lens` app pool (No Managed Code, AlwaysRunning) and IIS site
   bound to `https://*:<Port>`, grants the pool identity the ACLs it needs,
   binds the TLS cert for that port, opens the firewall, and starts the pool.

Re-running is safe and idempotent: the estate database and an existing
`web.config` are preserved; use it for upgrades too (it stops the pool, refreshes
the venv, restarts).

The estate starts **empty**. Open the site and use **Ingest** to upload a
collector export, or drop an existing `gpo-lens.sqlite3` into the data dir.

## Access control — read this

**gpo-lens has no per-user login.** Behind IIS every request arrives from
`127.0.0.1`, so the app treats *all* callers as the trusted local analyst
(view + ingest + narrate — including replacing the estate). This is by design
for a local-first tool, but it means the IIS site is as open as the network in
front of it.

Do **not** rely on `GPO_LENS_AUTH_TOKEN` to fix this: it requires a `Bearer`
header that a browser cannot send, which only breaks the UI. Instead, restrict
access at the IIS layer:

- **Pass `-WindowsAuth` to the installer** (recommended). It installs the
  `Web-Windows-Auth` role service if missing, enables Windows Authentication
  on the site, and disables anonymous access — so only authenticated domain
  users reach gpo-lens. Unauthenticated requests get 401; browsers prompt for
  credentials automatically. The role service must be installed for the module
  to load; the installer handles this.
  **Note:** Windows Auth is sticky — once enabled, re-running the installer
  without `-WindowsAuth` does *not* re-enable anonymous access (a
  security-positive default). To revert, re-enable anonymous auth in IIS
  Manager or `Set-WebConfigurationProperty … anonymousAuthentication -Name
  enabled -Value $true`.
- An **IP allow-list** (IIS "IP Address and Domain Restrictions").
- Or keep the site on an **isolated/management network**.

## Why a shared Python install

The Python Install Manager installs runtimes per-user (under
`%LocalAppData%\Python`). The IIS app pool identity (`IIS AppPool\gpo-lens`)
cannot read another user's profile, so the installer copies the runtime to
`C:\ProgramData\gpo-lens\python` and points the venv at that. If you install
Python machine-wide (e.g. under `C:\Program Files`), this copy is skipped.

## Running alongside cert-watch

cert-watch binds the catch-all certificate on `0.0.0.0:443`. gpo-lens uses its
own port (default 8443) with a separate `netsh` SSL binding on
`0.0.0.0:<Port>`, so the two never collide. Both can reuse the same machine
certificate. Browse to `https://host.example.com:8443/`.

### Sharing port 443 via SNI

If you would rather not use a separate port, gpo-lens can share **443** with
cert-watch via SNI (Server Name Indication). Add `-Sni` (and `-HostName`) to
the installer:

```powershell
.\scripts\install-windows.ps1 -ConfigureIIS -Port 443 `
    -HostName gpo-lens.example.com -TlsCertThumbprint "<thumb>" -Sni
```

With `-Sni` the installer:

- Sets `sslFlags=1` (SNI) on the IIS binding so http.sys routes by hostname.
- Binds the certificate via `netsh http add sslcert hostnameport=…` (per-host),
  **not** the catch-all `ipport=0.0.0.0:443` — so cert-watch's binding is
  untouched.
- Requires IIS 8+ (Windows Server 2012+) and a `-HostName` (SNI selects a cert
  by hostname; there is no SNI without one).

The ordering matters: `sslFlags=1` must be on the IIS binding *before* the
`hostnameport` sslcert add, or http.sys rejects it with error 87. The installer
handles this; if you bind by hand, set the binding flags first.

cert-watch keeps the catch-all `0.0.0.0:443` binding (non-SNI), so it serves
any request whose SNI hostname does not match `gpo-lens.example.com`. This is
the desired fallback. Browse to `https://gpo-lens.example.com/` (no port).

## Files

| File | Purpose |
|------|---------|
| `web.config` | HttpPlatformHandler config: launches `python -m gpo_lens --db <data>\gpo-lens.sqlite3 serve` and proxies to it. Copy into the site path. |
| `web.config.reverse-proxy` | *(not provided)* — gpo-lens supports `--root-path` if you front it with a path-based reverse proxy instead. |

## Troubleshooting

- **HTTP 503**: the app pool is stopped or the process failed to start. Check
  `C:\ProgramData\gpo-lens\logs\stdout*.log`.
- **HTTPS refused / cert errors**: verify the binding with
  `netsh http show sslcert ipport=0.0.0.0:8443` and that the thumbprint exists in
  `LocalMachine\My` with a private key. Verify reachability with an **external**
  client (`curl https://host:8443/`), not in-box .NET, which can mask binding
  issues.
- **Port blocked**: confirm the firewall rule `gpo-lens HTTPS <Port>` exists
  (the installer adds it).

## Backup and restore

The estate lives in `C:\ProgramData\gpo-lens\gpo-lens.sqlite3`. It holds the
full ingested estate (GPOs, SOMs, settings, delegation), snapshot history,
and the audit log (`audit.log` alongside it). Back it up regularly.

### Online backup (preferred — no downtime)

SQLite supports hot backups via the `.backup` command. The app pool can stay
running — WAL mode handles concurrent readers:

```powershell
$py = "C:\ProgramData\gpo-lens\venv\Scripts\python.exe"
& $py -c "import sqlite3; src=sqlite3.connect(r'C:\ProgramData\gpo-lens\gpo-lens.sqlite3'); dst=sqlite3.connect(r'C:\Backup\gpo-lens-$(Get-Date -Format yyyyMMdd).sqlite3'); src.backup(dst); dst.close(); src.close()"
```

Schedule this via Task Scheduler (daily or before each ingest). Copy the
`audit.log` alongside it if you need the audit trail preserved.

### Offline backup (simpler, brief downtime)

Stop the app pool, copy the file, restart:

```powershell
Stop-WebAppPool gpo-lens
Copy-Item C:\ProgramData\gpo-lens\gpo-lens.sqlite3 C:\Backup\gpo-lens-backup.sqlite3
Start-WebAppPool gpo-lens
```

### Restore

Stop the app pool, replace the file, restart:

```powershell
Stop-WebAppPool gpo-lens
Copy-Item C:\Backup\gpo-lens-backup.sqlite3 C:\ProgramData\gpo-lens\gpo-lens.sqlite3 -Force
Start-WebAppPool gpo-lens
```

The schema is additive-migrated on open (`_migrate_schema`), so a DB from an
older gpo-lens version can be restored into a newer install without manual
steps. The reverse (newer DB into older gpo-lens) is not guaranteed.
