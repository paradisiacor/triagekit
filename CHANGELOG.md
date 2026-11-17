# Changelog

All notable changes to TriageKit. Versions follow semantic versioning; the beta channel gets every release.

## 0.15.0 — Safe Start

### New: Safe Start
- **Check a download** before running it: a file, a folder or an archive (ZIP, RAR, 7z, TAR, GZip, also nested). Nothing is unpacked to disk or run.
  - Programs inside archives get a real signature check in memory (signature valid, file unchanged since signing, trusted signer).
  - The built-in malware rules, plus red flags typical for malware-laced cracks and fake downloads: disguised file types, fake installers of popular apps, programs padded with filler to dodge antivirus uploads, scripts packed into unsigned programs, "disable your antivirus" readmes, password-protected programs, unusual runnable file types, shortcuts that start hidden commands, Office macros.
  - File fingerprints are looked up with reputation services if online lookups are allowed; Microsoft Defender checks files on disk.
  - An honest verdict (no threats found / suspicious / dangerous / known malware) that lists everything that couldn't be checked.
  - Archive-bomb protection: size, ratio and depth limits. Also from the command line: `TriageKit.exe check <file or folder>`.
- **Install Watch:** a "before" snapshot, install or run something, then compare. Shows new startup entries, tasks and services, Defender exclusions and switched-off protections, root certificates, drivers, browser extensions, hosts/proxy/DNS changes, new user accounts and installed programs, each judged, plus any new findings. The snapshot survives closing the app or restarting.

### Release readiness
- Checks that didn't run (switched off, tool not installed) show as "skipped" and checks that failed as "didn't finish" on the scan screen, never with a green tick.
- Fewer false alarms: programs inside downloaded ZIPs are judged by the malware rules instead of being listed; only typical lures (shortcuts, Windows scripts, a lone top-level script) are reported. Password-protected archives and accounts without a required password are Info.
- "Unsigned programs recently created" and "scripts recently created" findings now name the files.
- The CI pipeline runs a full offline check on a fresh Windows runner and keeps its results.

## 0.14.0 — free for everyone

TriageKit no longer has plans or licences. Every check, PC Doctor, Gaming and daily protection are included for everyone.

- Removed: Plan & licence page, licence files and the `license` command, the online licence check (leases), device IDs, the publisher licence console link, the paid reputation-service client.
- Daily protection (installed edition) runs without a trial or licence.
- Updates still come from the signed update service; nothing about the PC is sent.
- Old `license.json` / `lease.json` files are ignored and can be deleted.

## 0.13.2 — fixes from the first 0.13.1 run on a real PC

- Browser components (PDF viewer, Web Store, Edge and Brave helpers, including entries left behind by old browser versions) are no longer reported as unpacked extensions. Only "Load unpacked", --load-extension and components pointing outside the browser's own folder are reported.
- A CIRCL listing in a malware-sharing feed (for example malshare.com) is a lead, not "known malware": unsigned files are High ("flagged as suspicious, listed in …"), validly signed files are Info. "Known malware" (Critical) needs a named detection.
- Windows files signed through "Windows Production PCA 2023" (current Defender platform) are recognised as Microsoft's by checking that the chain ends in a Microsoft root; Defender's own scheduled tasks are no longer reported as non-Microsoft.

## 0.13.1 — Accounts & sessions, phase 2

From the independent review of 0.13.0 and the second real-PC run.

### Accounts & sessions
- Remote-control detection covers pinned Start-menu and taskbar shortcuts, Steam's -cef-enable-debugging flag and its .cef-enable-remote-debugging file, browser launch hijacks (changed open-command of Chrome/Edge/Brave), WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, a live DevToolsActivePort file, and unpacked extensions loaded from Preferences.
- A debug-launched browser is graded by who started it: signed test tools are Low; a suspicious or vanished parent, or a headless browser with a temporary profile, is High.
- Browser policy turning app-bound encryption off is High on PCs that aren't company-managed.
- Foreign or unsigned programs dropped into Chrome, Edge or Brave program folders.
- Stealer leftovers: weighted file/folder evidence (no more false alarms on app folders called "Discord" or "Steam"), helper-DLL sets, session copies only when they really are browser databases, Telegram tdata only when Telegram isn't installed there.
- hosts redirects grouped per address: internet (High), local network (Medium), this PC (Low). Relocated hosts files are followed.
- Fake installers: exact maker checks; "signed by someone else" (High) separated from "not signed" (Medium), with the download source when Windows recorded it. TeamViewer QuickSupport, RustDesk and ScreenConnect added.
- Cheat names use whole words (no more "bootloader" or "downloader" alarms).
- Desktop wallet and messenger apps with a modified app.asar (Exodus, Atomic, Ledger Live, Signal), Steam side-loaded DLLs.
- Outdated browsers (no update for 120+ days) and "update waiting, restart the browser".
- Repeated "sign out everywhere" advice is shown once.

### Fixed on a real PC
- AMSI-bypass rule no longer flags Microsoft runtime files (coreclr.dll, singlefilehost.exe, System.Management.Automation.dll).
- Stronger script stealer and clipper rules; new rules for cookie dumps over browser debugging, app-bound key decryption and Roblox cookie loggers.

## 0.13.0 — Accounts & sessions

New check "Accounts, sessions & downloads" (every plan) and a new "Accounts & sessions" area on the Overview. Read-only and private: TriageKit looks at names, paths and command lines, never at cookie values, passwords or tokens.

- **Browser under remote control:** browser shortcuts (desktop, Start menu, taskbar) and running Chrome, Edge, Brave, Opera or Vivaldi with --remote-debugging-port/pipe, --load-extension and similar flags, which current stealers use to read cookies despite browser encryption. Test automation with a temporary profile is Low.
- **Stealer leftovers:** folders with several typical stealer-log files (Passwords.txt, UserInformation.txt, Wallets, Cookies...) in Temp, AppData, ProgramData and Public; copies of browser databases (Login Data, Cookies, key4.db), Steam login files (ssfn, loginusers.vdf) and Telegram sessions (tdata) in temporary folders.
- **Chrome too old for app-bound encryption** (before version 127).
- **hosts-file redirects** of Steam, Discord, Epic, Battle.net, Riot, Roblox, EA, Ubisoft, Xbox, PlayStation, Twitch, FACEIT and Minecraft domains (High), and blocks of them (Low).
- **Fake installers:** SteamSetup, DiscordSetup, OBS, Chrome, Epic, Battle.net, Riot, EA, Roblox, Minecraft, TeamViewer, AnyDesk, Spotify, Zoom, Telegram, VLC, MSI Afterburner, NVIDIA and AMD installers in Downloads that aren't signed by their real maker.
- **Cheats, cracks and loaders:** unsigned executors, injectors, spoofers, "free Robux/V-Bucks" tools in Downloads from the last 60 days.
- **Extensions acting on account sites:** store extensions with access to Steam, Discord, Roblox, Epic, Battle.net, Riot or skin-trading sites (well-known ones excepted). Crypto wallet extensions are noted with protection advice.
- **New malware rules:** script-based info stealers (Python/JS/PowerShell) that read browser data together with wallets or app sessions, and script clippers that swap copied crypto addresses (the existing rules cover programs).
- **"Sign out everywhere" steps** come with every account-theft finding: changing a password doesn't end a stolen session.

## 0.12.2

From the first real-PC run (Ryzen 9 7900X3D, Radeon RX 7900 XT) and the independent verification of 0.12.1.

### Fixed on a real PC
- PC Doctor runs no longer appear on the Overview and in History as if they were security checks (areas showed "All good" without having been checked). Old entries are removed automatically. After a quick check, "Files & malware" says "Not in quick check" instead of "All good".
- Check times show real measured values (milliseconds below one second) instead of "0.0 s". Finished checks are revealed one by one and the percentage follows the expected work (the 20-second live measurement included), so progress moves steadily. This only paces the display; checks don't run slower.
- Driver latency: one core handling most hardware interrupts (20-30% is normal) no longer counts as micro-stutter on its own.
- "Service keeps failing": translated service names are matched to their real names; luafv, dam and MapsBroker are ignored; Windows' own services are Low with calm advice.
- HWiNFO: also found when it runs without administrator rights, and PC Doctor says when HWiNFO is open but "Shared Memory Support" is off.
- TriageKit's own window processes no longer appear in "busiest apps".
- Portable hardware tools (HWiNFO, CPU-Z, GPU-Z...) loading their signed driver from %TEMP% are Low ("Driver loaded from a temporary folder"), not High, and each install is reported once.
- Unknown root certificates: Low by default; Medium for a random-looking name, one added in the last 90 days, or one in a personal store. Certificates apps create for themselves (game launchers, Zadig/libwdi, AutoHotkey) are recognised. Sectigo's "AAA Certificate Services" is known.
- "Account can have an empty password" is Low and explains that this is common and not proof of an empty password.

### New
- PCIe link check for AMD, Intel and other graphics cards, from Windows' own device information (NVIDIA keeps using nvidia-smi). Laptops get a by-design note instead of "move the card".

### From the verification of 0.12.1
- The "certificate not issued by Microsoft" rule now really removes Microsoft trust (it had no effect).
- Portable "Open report" opens the report directly; copies are only made by the installed edition.
- Protected subfolders (View copies, Private) keep their own permissions when the data folder is secured; folders made by standard users are moved aside too; an admin account's ownership is only trusted inside the WebView2 profile.
- The desktop user for "Open report" is found through the Windows session (works when another admin's password was used).
- Measured findings: only the measured part of a title is ignored for identity, the subject (disk, GPU, app) keeps its digits, and a worse severity is a new finding.
- Malware sweep: newest files first; caps in Startup, Downloads and Desktop count as real gaps; archives that can't be opened are listed as unreadable.
- PC Doctor timeouts or failures no longer turn the security verdict into "Incomplete check".
- Run box: carets, backticks and quote tricks are undone before judging; more launchers (hh, pcalua, odbcconf, installutil, msbuild, finger), WebDAV shares and scheme-less mshta addresses are recognised; intranet installs (\\server\share) and local paths named "Cloudflare" no longer give High.
- Revocation: any unexpected answer from the revocation-checking pass falls back to the normal check.
- Two-socket boards, Ryzen 3000/5000 and mobile CPU temperature limits, AM5 board voltage sensors, LibreHardwareMonitor rails (midpoint of min/max), hotfix dates in the user's regional format.
- Server: the per-licence rate limit is per licence and caller.
- Known limit: Defender's single-file scan with -DisableRemediation may not record detections in Defender's history, so the language-independent fallback may not help there; to be confirmed in the VM test.

## 0.12.1

Fixes from the second independent review. Focus: no false alarms on healthy PCs.

### PC Doctor
- RAM: dual-channel kits on MSI, ASRock and Gigabyte Intel boards ("Controller0/Controller1") were reported as "same channel". Slot names are now parsed per vendor scheme; when a name isn't understood, nothing is said. No RAM advice in virtual machines or for soldered memory; mixed kits aren't flagged on laptops.
- CPU voltage: limits depend on the CPU (1.55 V for Intel and Ryzen 3000/5000, 1.45 V for Ryzen 7000/9000). VID (what the CPU asks for) is no longer judged. Low unless Windows also logged unexpected shutdowns or hardware errors. Advice is vendor-specific.
- Temperatures: CPU limit per model (Intel 100 °C, Ryzen 7000/9000 95 °C, X3D 89 °C), flagged within 2 °C of it. Graphics memory junction (GDDR6X) and hot spot have their own limits; graphics card VRMs are no longer called "motherboard VRM". HWiNFO's own thermal-throttling flags are used. SSD temperatures come only from Windows' disk counters (no duplicates).
- Power supply rails: the current reading and HWiNFO's average must both be out of spec; values more than 10% off are reported as a mis-scaled sensor (Info), standby rails are ignored.
- Live measurements: only the Windows disk is judged (not the USB stick TriageKit runs from or a sleeping data drive), with at least 3 slow samples. Memory shortage needs both page reads and memory really used up. Worst-core latency uses the 90th percentile. CPU hogs show who signed them; Windows components get calm advice and the app in the foreground isn't reported. Broken performance counters are reported instead of showing 0% in green. Process paths are read without opening processes for memory reading.
- Monitors: real model names from the monitor's EDID; Medium only for the main screen on mains power; no monitor findings from the background service.
- NVIDIA: works with old and new driver field names, one finding for the power brake, x8 PCIe is Low, and each part (monitors, RAM, GPU) fails on its own.
- HWiNFO: reads under HWiNFO's mutex, notices when the free version has stopped sharing after 12 hours or the data is stale. LibreHardwareMonitor detection gives up after 5 seconds; OpenHardwareMonitor (unmaintained) is no longer used.
- Measured findings keep their identity between runs, so "This is fine" sticks and history doesn't flap. All numbers use the same format on every Windows language.

### Security checks
- Run box history: harmless entries (Cloudflare or reCAPTCHA links, firmware scripts, "-Confirm:$false") no longer give High. High needs download-and-run, a code launcher pointed at the internet, or the scam's "I am not a robot" text.
- "Incomplete check" is only shown for real gaps in the security check. Limits reached (file caps, one damaged archive) and PC Doctor problems are listed as "optional details skipped" without changing the verdict.
- A Medium finding is never "Looks clean".
- PC Doctor and gaming findings no longer change the security score.
- Turning off "Look inside archives" or Autoruns is shown in the report, like turning off malware rules.
- Signatures: revocation is checked against Windows' cached lists (never online); a certificate that calls itself "Microsoft" but wasn't issued by a Microsoft CA isn't treated as Microsoft's.
- Defender: detections are also confirmed through Defender's own detection list, so they're found on non-English Windows.

### Hardening
- "Open report" in the installed edition: the copy goes to a random folder under the admin-only data folder, readable only by the signed-in user (also when TriageKit was started with another admin's password). Copies are removed after a day.
- ProgramData folder: files created there by standard users are moved aside and never reused; the folder is secured without following links.
- The tray task is registered from a file in the admin-only folder instead of %TEMP%.
- The elevated window refuses to start rather than fall back to a user-writable browser profile.
- The portable edition keeps its licence next to TriageKit.exe, so a technician's licence doesn't stay on a customer's PC.
- The window fits 1366 x 768 laptop screens at 125% scaling.

### Server
- Adding or removing an admin passkey needs a touch of an existing passkey (a stolen session can't add its own).
- Rate limits use Cloudflare's Rate Limiting binding across isolates; the licence budget is per licence, so invented device ids don't multiply it.

## 0.12.0
- PC Doctor 2.0: 20-second live measurements (driver latency, CPU hogs, disk delay, memory shortage), monitor refresh rate, RAM channels and mixed kits, NVIDIA temperature/throttling/PCIe lanes, voltages and temperatures from HWiNFO or LibreHardwareMonitor.
- Anti-VM / anti-sandbox malware rule (low severity, several signs needed).

## 0.11.0 to 0.11.3
- Fixes from the first independent review and two Windows Sandbox lab runs: "Incomplete check" verdict instead of a false all-clear, Defender quick scan off by default, passkey step-up for signing, secured ProgramData folder, ClickFix (Run box) check, exclusion boundaries, better redaction, ZIP entry limits, sweep order, tray sign-in task, pipe timeouts, WebView2 hardening, rate limits, Defender false positives, Windows built-in roots, self-extraction paths, EICAR rule, PC Doctor service-failure parsing.

## 0.10.0

### Detection
- Looks inside ZIP archives (nested up to 3 levels) and Office files, entirely in memory. Limits: 10,000 entries, 200 MB expanded, 32 MB per entry, compression ratio checks. Nothing is extracted to disk.
- Office macros: extracts VBA source from .docm/.xlsm/.doc/.xls and flags auto-run macros with download/shell keywords.
- Shortcuts (.lnk): reads target and arguments and flags hidden PowerShell / mshta / cmd commands, in Startup, Desktop, Downloads and inside archives.
- Password-protected or oversized archives are reported as "could not be checked" instead of silently skipped.

### Accuracy and control
- "This is fine…": accept one finding or every finding of a type, optionally for 30/90 days. Accepted findings stay in reports, marked, but don't lower the score.
- Folder exclusions. Whole drives, Windows and the Users folder can't be excluded, and Critical findings are never hidden by a rule-wide or folder-wide exclusion.
- Checks that could only partly read their data (permissions, missing logs, WMI errors) now say so ("Some data couldn't be read") instead of looking clean.

### Speed
- Independent checks run three at a time.
- Each file gets a 5-second total budget for malware rules, so a crafted file can't stall a scan.
- Timed-out checks are told to stop instead of running on in the background.
- Hashes and signatures of unchanged files in Windows and Program Files are remembered for 7 days (cache stored in an admin-only folder). Files in user folders are always re-checked.

### Privacy
- Shareable report: a copy without PC name, user names, e-mail, IP/MAC addresses, account SIDs, device IDs and serial numbers, and without raw collector data.

### Updates
- Signed update channel. The server signs each release announcement with a release key kept inside Cloudflare; the app checks the signature, only moves to newer versions, verifies the download's SHA-256, swaps the exe and keeps the previous one until the next start.
- Admin console: Releases tab to sign and publish an update.

### Other
- SBOMs (CycloneDX) for .NET and UI dependencies in `sbom/`.

## 0.9.0 (2026-11-14)
- Licence and lease keys generated inside Cloudflare (Durable Object); licences are server-signed. Old keys retired.
- Passkey-only admin console at /admin (create, revoke, restore, extend, devices, activity).
- Licence must be confirmed online every 30 days; at most one activation write per PC every 12 hours.
- Reports open as the signed-in user after an integrity check; installed-mode reports and API keys are admin-only.
- Autoruns runs from a verified private copy; tray verifies the service pipe; online lookups are opt-in.
- .NET 10, compressed built-in rules, 3D scene renders on demand.

## 0.8.2 and earlier
- Private beta builds.
