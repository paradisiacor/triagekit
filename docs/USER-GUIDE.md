# TriageKit - user guide

TriageKit checks a Windows 10/11 PC for signs of malware and weak security settings and gives you a
plain-language report with a score and clear next steps. **It never changes, deletes or uploads anything.**

## Run it
1. Copy the `TriageKit` folder to a USB stick (or anywhere).
2. Double-click **TriageKit.exe** and approve the Windows prompt (administrator rights give a complete scan).
3. Click **Run check**. Findings appear in the app; the full report is saved next to the program in `Reports\<PC>_<date>\`.

Only scan PCs you own or have the owner's permission to check.

| File in the report folder | What it is |
|---|---|
| `report.html` | The report - open in any browser, works offline |
| `results.json` | All raw data (for IT tools and the future console) |
| `collector.log` | What the scanner did, step by step |
| `autoruns.csv` | Autoruns output, if Autoruns is installed |
| `manifest.sha256` | Fingerprints proving the report was not changed afterwards |

## Options
Double-clicking opens the TriageKit window. For USB sticks and scripts there is a console scan:
`TriageKit.exe cli [options]` (any option also starts it):

| Option | Effect |
|---|---|
| `--quick` | ~1-minute scan; skips the file sweep, malware rules, external scanners and reputation lookups |
| `--deep` | Malware rules across all user folders and Program Files (slow) |
| `--offline` | No online lookups at all (Defender's local check still runs) |
| `--no-vt` / `--no-yara` / `--no-defender-scan` | Skip individual parts |
| `--case 2026-014 --tech "Name"` | Adds case details to the report |
| `--out D:\Reports` | Saves reports somewhere else |
| `--no-open --no-pause --yes` | For automation |

Exit codes for scripts/RMM tools: `0` looks clean, `10` needs attention, `20` at risk, `30` likely compromised.

## Settings (`config.json`)
- Reputation checks work **without any keys**: Microsoft Defender re-checks suspicious files locally, and CIRCL recognises known-good files.
- `VirusTotalApiKey`, `MalwareBazaarAuthKey` - optional, your own free keys for extra opinions (personal use). Only fingerprints are sent, never files.
- `RunYara` - built-in malware rules scan unsigned programs and scripts (on by default).
- `AskCaseInfo` - set `true` to ask for case ID, technician and owner consent before each scan.
- `EventLogDays`, `RecentFileDays`, `RecentFileMaxItems` - how far back and how deep to look.
- `RunDefenderQuickScan`, `RunAutoruns` - turn the extra scans on/off.

## Installed edition (automatic daily checks)
Want TriageKit to keep watching a PC you own? Open a command prompt **as administrator** in the folder and run:

```
TriageKit.exe install
```

This copies TriageKit to `C:\Program Files\TriageKit`, adds a small background service and a tray icon next to the clock.
- The first scan runs about 5 minutes after installing, then once a day (default 12:30; missed scans catch up after start-up).
- The tray icon turns green / amber / red with the result, and pops up a note **only when something new** appears.
- Right-click the icon: *Open latest report*, *Open history* (score trend and what changed), *Scan now*.
- Reports and history live in `C:\ProgramData\TriageKit` (only administrators can change them).
- Settings: `C:\ProgramData\TriageKit\agent.json` (`DailyScanTime`, `QuickScheduledScans`, `KeepScans`, `NotifyOnNewFindings`).

Other commands: `TriageKit.exe status`, `TriageKit.exe scan-now`, `TriageKit.exe uninstall` (add `--purge` to delete history).
It is also listed in *Settings > Apps* as "TriageKit Security Agent".

## Reading the results
- **Critical** - strong sign of compromise (e.g. a fake Windows process, a file 5+ antivirus engines call malware).
  Disconnect from the internet, and change important passwords from a different device.
- **High** - needs action soon. **Medium** - review. **Low/Info** - good to know.
- A clean result lowers the risk but cannot prove a PC is malware-free.
