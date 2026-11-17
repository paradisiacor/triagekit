# Security model of TriageKit itself

A security tool runs with administrator rights on machines that may already be compromised. It must not become
the weakest link. This document is the threat model and the rules every change must follow.

## Threats and mitigations
| Threat | Mitigation (status) |
|---|---|
| Malicious data on the scanned PC (file names, extension names, command lines) attacks the report viewer (XSS) | JSON is HTML-escaped (`<`, `>`, `&`, U+2028/9) and the report renders with `textContent` only - never `innerHTML`. Unit-tested. **Done** |
| Tool is tricked into executing attacker files | Only these external programs are started during a check: MpCmdRun with -DisableRemediation, autorunsc only if validly Microsoft-signed, and NVIDIA's own nvidia-smi from System32 or Program Files for a read-only query (PC Doctor). The installer additionally uses sc.exe and schtasks.exe. Collected files are read as bytes for YARA, never executed. YARA regexes run with a timeout. **Done** |
| Tampered TriageKit binary or rule pack on a USB stick | Rule packs must carry an ECDSA P-256 signature from the publisher key compiled into the app; unsigned, altered or unlisted files are refused (**done**). Release builds come from GitHub Actions; Authenticode signing through SignPath Foundation (**applying**); SHA-256 published with every release |
| Hung or hostile WMI/COM provider stalls the scan | Each check runs on its own task with a timeout. **Done** |
| Report altered after the scan (evidence integrity) | `manifest.sha256` of all outputs. **Done**; signed manifests for the console (**later**) |
| Privacy - collecting more than needed | File contents are read locally, in memory, for malware rules and archive/macro inspection, and never uploaded. Browser history, passwords and cookies are never read. Online lookups send SHA-256 hashes only, and only when turned on; VirusTotal only with the user's own key. **Done** |
| Stolen admin session publishes a malicious update | The update service only announces releases. Signing needs a fresh passkey assertion bound to a digest of the exact announcement; adding or removing a passkey needs an assertion from an existing passkey. The app verifies the announcement signature and the SHA-256 of the download. Residual: a malicious deploy to the Cloudflare account could use the stored key (offline release signing planned). **Done** |
| Elevated process writes into user-writable places | Report copies for the browser go to a random, pre-ACL'd folder under the admin-only data folder; the tray task XML is written to the admin-only folder; files in ProgramData created by standard users are moved aside, never reused. **Done** |
| Another program steers the elevated app window | WebView2 environment overrides are ignored when elevated; the page is served from the exe, navigation is locked to it, no dev tools, and the page can't name file paths. WebView2 itself never runs elevated (its browser runs as the desktop user), so its profile in ProgramData is writable by SYSTEM, Administrators and that one account only; the elevated app never reads anything back from it. **Done** |
| Installed agent as an attack path (SolarWinds/Kaseya pattern) | No remote commands of any kind: the service only runs scheduled local checks and answers a local, network-denied pipe with two commands. Updates are signed and verified. **Done** |
| Supply chain (NuGet, npm, build machine) | Locked package versions (`package-lock.json`), builds on GitHub-hosted runners from tagged source, `Deterministic` builds; CycloneDX SBOM in `sbom/` (**done**) |

## Rules for contributors
- Checks are read-only. No registry/file writes outside the output folder, no network except opt-in reputation lookups.
- Never render untrusted strings as HTML; never pass them to a shell.
- Never execute binaries from the scanned machine or the USB stick unless signature-verified against an expected publisher.
- New network endpoints require an explicit config switch and must be documented here.
- Never read cookie values, saved passwords, login tokens or message contents. Names, paths, sizes and command lines only.

## Reporting a vulnerability
Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting). Don't open a public issue for a vulnerability. You'll get an answer within a week;
fixes are released as soon as they're ready and credited in the changelog unless you'd rather stay anonymous.

Supported versions: the latest release only.

## Signing keys
- Rule packs: public key `src/TriageKit.Core/Resources/rulepack-public.pem`, compiled into the app. The private key is
  kept offline by the maintainer and never committed. Packs are signed with
  `dotnet run --project tools/RulePackTool -- sign <packDir> <private.pem> <version>`.
- Update announcements: public key `src/TriageKit.Core/Resources/release-public.pem`. The private key lives inside the
  update service's Durable Object and can only be used with a fresh passkey touch.
- Executables: Authenticode signing through SignPath Foundation, see `CODE_SIGNING_POLICY.md`.
