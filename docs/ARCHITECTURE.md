# Architecture

```
TriageKit.sln
├─ src/TriageKit.Core      engine, checks, intel, rules, reports            (no UI)
│  ├─ Engine/              ICheck, Scanner (parallel groups, timeouts, isolation), Scoring, models
│  ├─ Checks/              one class per area; all read-only (security, accounts & sessions, PC Doctor, gaming)
│  ├─ Intel/               FileIntel cache, Authenticode (WinVerifyTrust + catalogs + Microsoft root check), heuristics
│  ├─ Yara/                pure C# YARA-compatible engine and the YARA check  ← Resources/rules/core.yar.gz
│  ├─ Reputation/          Defender, CIRCL, MalwareBazaar, VirusTotal providers (hash only, opt-in)
│  ├─ Rules/               indicators + signed rule packs (ECDSA P-256)
│  ├─ Agent/               history (SQLite), settings, signed update announcements
│  ├─ Platform/            WMI / registry / profile helpers
│  └─ Reporting/           results.json, report.html, shareable report, manifest.sha256
├─ src/TriageKit.Cli       the single exe: WebView2 desktop app, console scan, installed service + tray
├─ ui/                     React + Vite + Tailwind UI, built into src/TriageKit.Cli/Ui/web
├─ rules-src/              source of the built-in malware rules
├─ server/                 update service (Cloudflare Worker): signed release announcements only
├─ website/                project website (Cloudflare static assets)
└─ tests/TriageKit.Tests   xUnit tests for all platform-independent logic
```

## Principles
1. **Read-only.** Checks collect and judge; they never modify the system. The only programs started are Defender's own
   `MpCmdRun.exe`, Microsoft-signed `autorunsc` (if present), NVIDIA's `nvidia-smi` for a read-only query, and, for
   installing the service, `sc.exe` / `schtasks.exe`.
2. **Detection content is data.** Indicators and YARA rules are embedded and can be replaced by signed rule packs.
3. **One schema.** `results.json` (`ScanResult`) is the contract between the engine, the app, reports and history.
4. **Fail soft and honestly.** Every check runs in isolation with a timeout. A check that could not finish is shown as
   such; it never looks clean.
5. **Explain everything.** Each finding has a plain-language title, detail, recommendation, a MITRE ATT&CK technique
   and a stable `RuleId`.

## Adding a check
1. Create a class implementing `ICheck` in `Checks/` (`Name`, optional `IsSlow`/`Order`, `Run(ctx)`).
2. Use `ctx.Files.Get(path)` for hashing and signatures (cached), `ctx.Indicators` for rule data and
   `ctx.Add(...)` for findings with a MITRE technique and a `RuleId`.
3. Return a serialisable object for the report tables; rows with a `Risk` property get colouring and filtering.
4. Register it in `CheckCatalog`, put the judging logic in static helpers and add tests (including a clean case).
