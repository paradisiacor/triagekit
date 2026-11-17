# Contributing

Thanks for helping. TriageKit is GPL-3.0-only; by sending a pull request you agree that your contribution is
released under the same licence.

## Ground rules
- **Read-only, always.** Checks collect and judge; they never change the system. No writes outside the report folder.
- **Privacy first.** Never read cookie values, saved passwords, login tokens or message contents. No new network
  calls without an explicit setting, documented in `SECURITY.md` and the privacy policy.
- **No false alarms on clean PCs.** A finding must be explainable in plain words, name the exact file, key or setting,
  and say how to fix it. Prefer a lower severity when the evidence is thin.
- **Tests.** Put judging logic in testable static helpers and add tests, including a "clean PC" case that must not fire.
- Never render untrusted strings as HTML and never pass them to a shell.

## Getting started
```
cd ui && npm ci && npx vite build && cd ..
dotnet test -c Release
```
The app itself is Windows-only; tests run anywhere .NET 10 runs.

## Detection rules
Rules live in `rules-src/core.yar`. After changing them, regenerate the embedded copy
(`src/TriageKit.Core/Resources/rules/core.yar.gz`, gzip with mtime 0) and add a test with a minimal sample that must
match and one that must not. Never commit real malware; use short, inert snippets.

## Reporting security problems
Please don't open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
