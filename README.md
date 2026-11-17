# TriageKit

**Read-only Windows security triage and PC health check.** TriageKit looks for signs of malware, stolen sessions
and weak settings, explains every finding in plain language and tells you exactly how to fix it yourself.
It never changes, deletes or uploads anything.

Free for everyone. No account, no payments, no telemetry.

- Website: https://triagekit-web.paradisiac.workers.dev
- Licence: [GPL-3.0-only](LICENSE) (see [NOTICE](NOTICE) for the WebView2 linking permission)

## What it checks
| Area | Examples |
|---|---|
| **Safe Start** | Check a download (file, folder, ZIP/RAR/7z/TAR, nested) before running it; Install Watch compares a before/after snapshot of an install |
| Antivirus & protection | Defender switched off, exclusions you didn't add, protection history |
| Startup & persistence | Run keys, services, scheduled tasks, WMI subscriptions, Winlogon, IFEO, replaced accessibility tools |
| Files & malware | Built-in signed YARA-compatible rules, archives and Office macros, shortcuts, Run-box "verify you're human" commands, reputation lookups (hash only, opt-in) |
| Accounts & sessions | Browsers under remote control, stealer leftovers, fake installers and cheat tools, hosts redirects of account sites, tampered wallet and messenger apps |
| Browsers & privacy | Risky or sideloaded extensions, hijacked settings, camera/microphone history |
| Network & certificates | Connections and open ports by signature, unknown trusted root certificates, proxies |
| Windows settings | UAC, SmartScreen, firewall, Secure Boot, memory integrity, LSA protection, SMBv1 |
| Programs & drivers | Fake system processes, injected modules, known-vulnerable drivers, remote-access tools |
| Logs | Cleared logs, protection switched off, suspicious PowerShell, failed sign-ins |
| PC Doctor | Blue screens decoded, GPU driver resets, disk health, RAM speed, sensors via HWiNFO/LibreHardwareMonitor, live performance |
| Gaming | Throttling, overlays, Game Mode, Discord tampering |

## Editions
- **Portable:** one self-contained `TriageKit.exe`. Runs from a USB stick, installs nothing.
- **Installed:** the same exe adds a small Windows service and tray icon for daily checks with alerts for new issues
  (`TriageKit.exe install`, run as administrator).

## Privacy
- File contents are read locally, in memory, and never uploaded.
- Cookie values, saved passwords and login tokens are never read. The accounts check looks at names, paths and sizes only.
- Online lookups are off until you agree, and send SHA-256 fingerprints only (CIRCL; VirusTotal and MalwareBazaar
  only with your own keys).
- The update check downloads a signed announcement and sends nothing about the PC.

## Build
Requirements: .NET 10 SDK, Node.js 22+.

```
cd ui && npm ci && npx vite build && cd ..     # builds the UI into src/TriageKit.Cli/Ui/web
dotnet test -c Release
dotnet publish src/TriageKit.Cli -c Release -o artifacts/TriageKit
```

The UI preview with sample data: `cd ui && npx vite build --mode preview` and open `ui/preview/index.html` through any
local web server.

Release builds are produced by GitHub Actions (`.github/workflows/`) so anyone can check that a published exe was
built from this source. See [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## Documentation
[User guide](docs/USER-GUIDE.md) · [Architecture](docs/ARCHITECTURE.md) · [Security model](SECURITY.md) ·
[Roadmap](docs/ROADMAP.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) ·
[Third-party notices](THIRD-PARTY-NOTICES.md)

A clean result lowers risk but can't prove a PC is free of malware.
