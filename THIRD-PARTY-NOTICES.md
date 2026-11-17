# Third-party components

TriageKit is GPL-3.0-only (see `LICENSE` and `NOTICE`). It includes or links the components below, each under
its own licence. Full dependency lists are in `sbom/` (CycloneDX).

## Windows app (.NET)
| Component | Licence |
|---|---|
| .NET runtime and libraries (System.Management, System.Diagnostics.EventLog, System.ServiceProcess.ServiceController, System.Security.Cryptography.Pkcs) | MIT |
| Microsoft.Data.Sqlite | MIT |
| SQLitePCLRaw | Apache-2.0 |
| SQLite (e_sqlite3) | Public domain |
| Microsoft Edge WebView2 SDK (Microsoft.Web.WebView2) | Microsoft WebView2 SDK licence (redistributable); covered by the section 7 permission in `NOTICE` |

## User interface (bundled into the app)
| Component | Licence |
|---|---|
| React, React DOM | MIT |
| three.js, @react-three/fiber | MIT |
| Motion | MIT |
| clsx | MIT |
| Lucide icons (lucide-react) | ISC |
| Geist and Geist Mono fonts (@fontsource-variable) | SIL Open Font License 1.1 |
| Tailwind CSS, Vite (build only) | MIT |

## Tests and build tools
| Component | Licence |
|---|---|
| xUnit, xunit.runner.visualstudio | Apache-2.0 |
| Microsoft.NET.Test.Sdk, coverlet.collector | MIT |

## Not bundled, used only if present
- Sysinternals Autoruns (Microsoft). Not redistributable, so it is never shipped. TriageKit runs it only if you place
  `autorunsc64.exe` in `tools\Sysinternals\` and it carries a valid Microsoft signature.
- HWiNFO and LibreHardwareMonitor. TriageKit only reads the sensor values they publish while running.

## Detection content
The malware rules (`rules-src/core.yar`) and indicators (`src/TriageKit.Core/Resources/indicators.json`) are
original work of this project, released under GPL-3.0-only. Names of known-vulnerable drivers and remote-access
tools are factual references.
