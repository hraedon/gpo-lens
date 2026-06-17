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

- **IIS Windows Authentication** on the site (Negotiate/NTLM) so only
  authenticated domain users reach the app — the closest parity with
  cert-watch's app-level login.
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
