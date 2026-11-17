using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using TriageKit.Cli.Agent;
using TriageKit.Core.Agent;
using TriageKit.Core.Platform;

namespace TriageKit.Cli;

[SupportedOSPlatform("windows")]
internal static class Program
{
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll")] private static extern bool AllocConsole();
    private static bool _ownConsole;

    /// <summary>
    /// TriageKit.exe is a Windows (GUI) program. For command-line use we attach to the console we were started
    /// from, or open our own window if started from Explorer with arguments (e.g. a shortcut with --cli).
    /// </summary>
    private static void EnsureConsole()
    {
        if (!AttachConsole(-1)) { AllocConsole(); _ownConsole = true; }
        var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
        Console.SetOut(stdout); Console.SetError(stdout);
        Console.SetIn(new StreamReader(Console.OpenStandardInput()));
    }

    [STAThread]
    private static int Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
        var a = new Args(args);
        if (!OperatingSystem.IsWindows()) return 1;

        // No arguments: the desktop app. Falls back to the console scan if the WebView2 runtime is missing.
        if (args.Length == 0)
        {
            if (Ui.AppWindow.RuntimeAvailable(out _)) return Ui.AppWindow.Run(version);
            var answer = System.Windows.Forms.MessageBox.Show(
                "The Microsoft Edge WebView2 Runtime is needed for TriageKit's window but isn't installed on this PC.\n\n" +
                "Click OK to run the scan in a console window instead (same checks, same report), or Cancel to exit.\n\n" +
                "You can install the runtime from https://go.microsoft.com/fwlink/p/?LinkId=2124703",
                "TriageKit", System.Windows.Forms.MessageBoxButtons.OKCancel, System.Windows.Forms.MessageBoxIcon.Information);
            if (answer != System.Windows.Forms.DialogResult.OK) return 0;
            EnsureConsole();
            return InteractiveScan(a, version, pauseAtEnd: true);
        }
        if (a.Verb == "open" && Ui.AppWindow.RuntimeAvailable(out _))
            return Ui.AppWindow.Run(version, a.Positional(1));
        if (a.Verb is not ("service" or "tray")) EnsureConsole();
        if (a.Has("--help", "-h", "/?")) { PrintHelp(version); return 0; }
        if (a.Has("--version")) { Console.WriteLine(version); return 0; }

        switch (a.Verb)
        {
            case "service":
                var svc = new AgentService(version);
                if (a.Has("--console")) { svc.RunInteractive(); return 0; }
                ServiceBase.Run(svc);
                return 0;
            case "tray":
                FreeConsole();                       // no console window behind the tray icon
                return TrayApp.Run();
            case "install":
                return Installer.Install(version, Console.WriteLine);
            case "uninstall":
                return Installer.Uninstall(a.Has("--purge"), Console.WriteLine);
            case "scan-now":
                Console.WriteLine(AgentClient.Send("SCAN") ?? "The TriageKit service is not running.");
                return 0;
            case "status":
                return PrintStatus();
            case "cli":
            case null:
                return InteractiveScan(a, version, pauseAtEnd: _ownConsole);
            default:
                Console.WriteLine($"Unknown command '{a.Verb}'. Run TriageKit.exe --help.");
                return 1;
        }
    }

    // ------------------------------------------------------------------ portable scan (default)
    private static int InteractiveScan(Args a, string version, bool pauseAtEnd)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        var baseDir = AppContext.BaseDirectory;
        var cfg = AppConfig.Load(a.Value("--config") ?? Path.Combine(baseDir, "config.json"), m => Console.Error.WriteLine(m));
        var caseId = a.Value("--case"); var tech = a.Value("--tech");
        if (cfg.AskCaseInfo && caseId is null && !a.Has("--yes"))
        {
            caseId = Prompt("Case / ticket ID (optional): ");
            tech ??= Prompt("Technician name (optional): ");
            var consent = Prompt("Has the device owner agreed to this scan? (y/n): ");
            if (!consent.StartsWith("y", StringComparison.OrdinalIgnoreCase)) { Console.WriteLine("Scan cancelled: the owner's consent is required."); return 2; }
        }
        var elevated = Sys.IsElevated();
        var outRoot = a.Value("--out") ?? Path.Combine(baseDir, "Reports");
        Banner(version, outRoot, elevated, a.Has("--quick"));

        var outcome = ScanRunner.Run(new ScanRequest
        {
            BaseDirectory = baseDir, OutputRoot = outRoot, Config = cfg, Quick = a.Has("--quick"), Deep = a.Has("--deep"), Offline = a.Has("--offline"),
            NoVirusTotal = a.Has("--no-vt"), NoYara = a.Has("--no-yara"), NoDefenderScan = a.Has("--no-defender-scan"),
            AllowUnsignedRules = a.Has("--allow-unsigned-rules"), CaseId = caseId, Technician = tech,
            Status = Status,
            Progress = (name, i, n) =>
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"\r  [{i,2}/{n}] {name}".PadRight(Math.Max(10, SafeWidth())));
                Console.ResetColor();
            },
        }, version);
        var result = outcome.Result;

        Console.WriteLine();
        Console.ForegroundColor = result.Verdict switch { "Looks clean" => ConsoleColor.Green, "Needs attention" => ConsoleColor.Yellow, _ => ConsoleColor.Red };
        Console.WriteLine($"  Score {result.Score}/100  -  {result.Verdict}");
        Console.ResetColor();
        Console.WriteLine($"  Critical {result.Counts["Critical"]}  High {result.Counts["High"]}  Medium {result.Counts["Medium"]}  Low {result.Counts["Low"]}  Info {result.Counts["Info"]}");
        Console.WriteLine($"  Rules: {outcome.RulesVersion}");
        Console.WriteLine($"  Report: {outcome.ReportHtml}");
        Console.WriteLine();
        if (!a.Has("--no-open")) Agent.AsUser.Open(outcome.ReportHtml);
        if (pauseAtEnd && !a.Has("--no-pause"))
        {
            Console.WriteLine("  Want automatic daily checks? Run 'TriageKit.exe install' as administrator.");
            Console.WriteLine("  Press any key to close.");
            Console.ReadKey(true);
        }
        // Exit code for automation (RMM/Intune): 0 clean, 10 attention, 20 at risk, 30 likely compromised.
        return result.Verdict switch { "Looks clean" => 0, "Incomplete check" => 5, "Needs attention" => 10, "At risk" => 20, _ => 30 };
    }

    private static int PrintStatus()
    {
        var s = AgentStatus.Read(AgentPaths.StatusFile);
        if (s is null) { Console.WriteLine("The installed agent is not set up on this PC. Run 'TriageKit.exe install' as administrator."); return 1; }
        Console.WriteLine($"TriageKit agent {s.Version} - {s.State}");
        Console.WriteLine($"  Last scan : {s.LastScanTime ?? "none yet"}  {(s.Verdict is null ? "" : $"{s.Verdict} ({s.Score}/100)")}");
        Console.WriteLine($"  Next scan : {s.NextScan ?? "-"}");
        Console.WriteLine($"  Report    : {s.ReportPath ?? "-"}");
        Console.WriteLine($"  History   : {AgentPaths.HistoryHtml}");
        if (s.LastError is not null) Console.WriteLine($"  Last error: {s.LastError}");
        return 0;
    }

    private static int SafeWidth() { try { return Console.WindowWidth - 1; } catch { return 100; } }
    private static string Prompt(string q) { Console.Write(q); return Console.ReadLine()?.Trim() ?? ""; }

    private static void Status(string m)
    {
        if (Console.IsOutputRedirected) return;
        var w = Math.Max(20, SafeWidth());
        var text = "        " + m;
        Console.Write("\r" + (text.Length > w ? text[..w] : text.PadRight(w)));
    }

    private static void Banner(string version, string outRoot, bool elevated, bool quick)
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine($"  TriageKit {version}  -  read-only security check");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  Device: {Environment.MachineName}   Mode: {(quick ? "Quick" : "Full")}");
        Console.WriteLine($"  Reports: {outRoot}");
        Console.ResetColor();
        if (!elevated)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  Not running as administrator - some checks will be incomplete.");
            Console.ResetColor();
        }
        Console.WriteLine("  Nothing on this PC will be changed.\n");
    }

    private static void PrintHelp(string version) => Console.WriteLine($@"TriageKit {version} - read-only Windows security triage

Desktop app (default):
  TriageKit.exe                 Opens the TriageKit window

Console scan (for USB/automation; use ""start /wait"" in cmd to get the exit code):
  TriageKit.exe cli [options]   (any option below also starts a console scan)
  --quick              Fast scan (~1 min): skips file sweep, YARA, external scanners and reputation lookups
  --deep               Deep scan: malware rules across all user folders and Program Files (slow)
  --offline            No online lookups at all (Defender's local check still runs)
  --no-vt / --no-yara / --no-defender-scan   Skip individual parts
  --out <dir>          Where to write reports (default: Reports\ next to TriageKit.exe)
  --case <id> --tech <name>   Case details shown in the report
  --config <file>      Use a different config.json
  --allow-unsigned-rules      Load rules\ even if not signed (rule authors only)
  --no-open --no-pause --yes  For automation

Installed edition (run as administrator):
  TriageKit.exe install           Install the background agent (daily scans, history, tray alerts)
  TriageKit.exe uninstall [--purge]   Remove it (--purge also deletes history and reports)
  TriageKit.exe status            Show agent status
  TriageKit.exe scan-now          Ask the agent to scan now

Exit codes (scan): 0 looks clean, 10 needs attention, 20 at risk, 30 likely compromised.");

    private sealed class Args
    {
        private readonly List<string> _a;
        public Args(string[] a) => _a = a.ToList();
        public int Count => _a.Count;
        /// <summary>First argument if it is a verb (not an option).</summary>
        public string? Verb => _a.Count > 0 && !_a[0].StartsWith('-') && !_a[0].StartsWith('/') ? _a[0].ToLowerInvariant() : null;
        public string? Positional(int i) => i < _a.Count && !_a[i].StartsWith('-') ? _a[i] : null;
        public bool Has(params string[] names) => _a.Any(x => names.Contains(x, StringComparer.OrdinalIgnoreCase));
        public string? Value(string name) { int i = _a.FindIndex(x => x.Equals(name, StringComparison.OrdinalIgnoreCase)); return i >= 0 && i + 1 < _a.Count ? _a[i + 1] : null; }
    }
}
