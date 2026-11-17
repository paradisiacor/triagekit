# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

## What is signed
Only `TriageKit.exe` release builds made by the GitHub Actions workflow `.github/workflows/release.yml` from a tagged
commit of this repository. Nothing built on a personal machine is ever signed. The SHA-256 of every signed file is
published with the GitHub release.

## Team roles
| Role | Who |
|---|---|
| Committers and reviewers | The repository owner and collaborators with write access to [paradisiacor/triagekit](https://github.com/paradisiacor/triagekit) |
| Approvers | The repository owner ([@paradisiacor](https://github.com/paradisiacor)) |

Every signing request is approved manually by an approver. All team members use multi-factor authentication for
GitHub and SignPath.

## Privacy policy
This program will not transfer any information to other networked systems unless specifically requested by the user
or the person installing or operating it.

In detail:
- Online reputation lookups are off until the user agrees, and then send SHA-256 file fingerprints only (CIRCL; VirusTotal
  and MalwareBazaar only with the user's own keys).
- The update check (which can be turned off) downloads a signed announcement and sends nothing about the PC.
- Nothing else leaves the PC. Reports stay local unless the user shares them.

The full privacy policy is at https://triagekit-web.paradisiac.workers.dev/privacy.
