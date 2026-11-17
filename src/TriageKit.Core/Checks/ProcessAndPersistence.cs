using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

public sealed record ProcessRow(string Risk, string? Name, long PID, string? Path, string? Parent, string? Signer, string Signature,
                                string? CommandLine, string? Started, string? SHA256, string? Company);

[SupportedOSPlatform("windows")]
public sealed class ProcessCheck : ICheck
{
    public string Name => "Running processes";

    public object? Run(CheckContext ctx)
    {
        var procs = Wmi.Query("SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate FROM Win32_Process");
        var byId = procs.GroupBy(p => p.L("ProcessId") ?? -1).ToDictionary(g => g.Key, g => g.First());
        var miner = ctx.Indicators.MinerProcessPatterns.Select(p => new Regex(p, RegexOptions.IgnoreCase)).ToList();
        var rows = new List<ProcessRow>();

        foreach (var p in procs)
        {
            var name = p.S("Name"); var path = p.S("ExecutablePath"); var cmd = p.S("CommandLine");
            var intel = path is null ? null : ctx.Files.Get(path);
            var parentId = p.L("ParentProcessId") ?? -1;
            var parent = byId.TryGetValue(parentId, out var pp) ? $"{pp.S("Name")} ({parentId})" : parentId.ToString();
            var risk = PathHeuristics.ExecutableRisk(intel);
            var row = () => new ProcessRow(risk, name, p.L("ProcessId") ?? 0, path, parent, intel?.Signer,
                                           intel?.SignatureStatus.ToString() ?? "Protected / no path", Sys.Trunc(cmd), p.Date("CreationDate")?.ToString("s"), intel?.SHA256, intel?.Company);

            // 1. Windows process names running from the wrong folder (masquerading).
            if (name is not null && path is not null && ctx.Indicators.SystemProcessLocations.TryGetValue(name.ToLowerInvariant(), out var dirs))
            {
                var dir = System.IO.Path.GetDirectoryName(path) ?? "";
                var allowed = dirs.Select(d => string.IsNullOrEmpty(d) ? Sys.SystemRoot : System.IO.Path.Combine(Sys.SystemRoot, d));
                if (!allowed.Any(a => string.Equals(a.TrimEnd('\\'), dir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)))
                {
                    risk = Risk.Critical;
                    ctx.Add(Severity.Critical, "Processes", $"Fake system process: {name} running from {path}",
                        "This program uses the name of a Windows system process but runs from the wrong folder - a classic malware disguise.",
                        "Disconnect the PC from the internet and investigate this file immediately. Check its hash on VirusTotal.", row(), "T1036.005", "process.masquerade");
                }
            }
            // 2. Signed binary whose contents no longer match the signature = tampered.
            if (intel?.SignatureStatus == SignatureStatus.HashMismatch)
                ctx.Add(Severity.Critical, "Processes", $"Tampered signed program running: {name}", $"{path} carries a signature that no longer matches the file contents.",
                        "Treat as compromised. Reinstall the program from the official source.", row(), "T1036.001", "process.tampered");
            // 3. Crypto miners.
            if (name is not null && miner.Any(m => m.IsMatch(name)))
            {
                risk = PathHeuristics.Max(risk, Risk.High);
                ctx.Add(Severity.High, "Processes", $"Possible crypto-miner running: {name}", path ?? "", "If you did not install a miner on purpose, remove it - miners are often installed by malware.", row(), "T1496", "process.miner");
            }
            // 4. Hidden / encoded / download-and-run script command lines.
            if (CommandLine.IsSuspiciousScriptHost(cmd))
            {
                risk = PathHeuristics.Max(risk, Risk.High);
                ctx.Add(Severity.High, "Processes", $"Suspicious script command running (PID {p.L("ProcessId")})", Sys.Trunc(cmd, 400),
                        "Encoded, hidden or download-and-run scripts are typical of malware loaders. Find out what started it (Parent).", row(), "T1059.001", "process.script-loader");
            }
            // 5. Unsigned code in risky folders (never report TriageKit itself).
            if (SelfIdentity.IsSelf(path, intel?.SHA256)) { rows.Add(row()); continue; }
            if (intel is { IsSigned: false, Exists: true } && risk == Risk.High && intel.Suspicious)
                ctx.Add(Severity.High, "Processes", $"Unsigned program running from a risky folder: {name}", path ?? "",
                        "Legitimate software rarely runs unsigned from Temp/Downloads/Public. Check the file on VirusTotal.", row(), "T1204.002", "process.unsigned-risky");
            else if (risk == Risk.Medium)
                ctx.Add(Severity.Low, "Processes", $"Unsigned program running from a user folder: {name}", path ?? "", "Make sure you recognise this program.", row(), ruleId: "process.unsigned-user");

            rows.Add(row());
        }
        return rows;
    }
}

public sealed record AutostartRow(string Risk, string Location, string Name, string? Target, string? Signer, string Signature,
                                  string? Command, string? Extra, string? SHA256);

[SupportedOSPlatform("windows")]
public sealed class AutostartCheck : ICheck
{
    public string Name => "Autostarts & persistence";
    private CheckContext _ctx = null!;
    private readonly List<AutostartRow> _rows = new();

    private static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
    };

    public object? Run(CheckContext ctx)
    {
        _ctx = ctx; _rows.Clear();
        RegistryRun(); Winlogon(); AppInitAndIfeo(); StartupFolders(); Services(); ScheduledTasks();
        var wmi = WmiSubscriptions();
        return new { Entries = _rows.ToList(), WmiSubscriptions = wmi };
    }

    private string Evaluate(string location, string name, string? command, string? extra, string mitre, string ruleId, bool skipMicrosoft = false)
    {
        var target = CommandLine.ExtractTarget(command, resolve: Sys.ResolveProgram);
        var intel = _ctx.Files.Get(target);
        if (skipMicrosoft && intel is { IsMicrosoft: true } && target!.StartsWith(Sys.SystemRoot, StringComparison.OrdinalIgnoreCase)) return Risk.Info;
        var risk = PathHeuristics.ExecutableRisk(intel);
        if (CommandLine.IsSuspiciousScriptHost(command)) risk = PathHeuristics.Max(risk, Risk.High);
        var row = new AutostartRow(risk, location, name, target, intel?.Signer, intel?.SignatureStatus.ToString() ?? "Unknown", Sys.Trunc(command), extra, intel?.SHA256);
        _rows.Add(row);
        var friendly = location.StartsWith("Service") ? "service" : location.StartsWith("Scheduled") ? "scheduled task" : "autostart entry";
        if (risk is Risk.Critical or Risk.High)
            _ctx.Add(Risk.ToSeverity(risk), "Persistence", $"Risky {friendly}: {name}", $"{location}\n{command}",
                     "Find out what this program is. If you don't recognise it, check its hash on VirusTotal and disable the entry (Autoruns or Task Manager > Startup).", row, mitre, ruleId);
        else if (risk == Risk.Medium)
        {
            // Unsigned + starts with Windows + lives in a user folder is the classic malware pattern. Recent ones matter most.
            bool recent = DateTime.TryParse(intel?.Created, out var created) && created > DateTime.Now.AddDays(-Math.Max(_ctx.Options.RecentFileDays, 14));
            _ctx.Add(recent ? Severity.Medium : Severity.Low, "Persistence", $"Unsigned {friendly} from a user folder: {name}", $"{location}\n{command}" + (recent ? $"\nCreated: {created:yyyy-MM-dd HH:mm}" : ""),
                     recent ? "This program was added recently, isn't signed and starts with Windows. If you didn't install something new, look it up and disable the entry."
                            : "Make sure you recognise this program.", row, mitre, ruleId);
        }
        return risk;
    }

    private void RegistryRun()
    {
        foreach (var k in RunKeys)
            foreach (var (n, v) in Reg.Values(Registry.LocalMachine, k))
                if (!string.IsNullOrEmpty(n)) Evaluate($@"HKLM\{k}", n, v?.ToString(), null, "T1547.001", "persistence.run-key");
        foreach (var sid in Reg.LoadedUserSids())
            foreach (var k in RunKeys)
                foreach (var (n, v) in Reg.Values(Registry.Users, $@"{sid}\{k}"))
                    if (!string.IsNullOrEmpty(n)) Evaluate($@"HKU\{sid}\{k}", n, v?.ToString(), null, "T1547.001", "persistence.run-key");
    }

    private void Winlogon()
    {
        const string k = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var shell = Reg.Value(Registry.LocalMachine, k, "Shell") as string;
        if (!string.IsNullOrEmpty(shell) && !Regex.IsMatch(shell.Trim(), @"^explorer\.exe,?$", RegexOptions.IgnoreCase))
            _ctx.Add(Severity.Critical, "Persistence", "Windows logon shell has been modified", $"Shell = {shell}",
                     "Reset the Shell value to explorer.exe and investigate the program it points to.", new { Shell = shell }, "T1547.004", "persistence.winlogon-shell");
        var userinit = Reg.Value(Registry.LocalMachine, k, "Userinit") as string;
        if (!string.IsNullOrEmpty(userinit) && !Regex.IsMatch(userinit.Trim(), @"^[a-z]:\\windows\\system32\\userinit\.exe,?$", RegexOptions.IgnoreCase))
            _ctx.Add(Severity.Critical, "Persistence", "Windows logon Userinit has been modified", $"Userinit = {userinit}",
                     "Reset Userinit to C:\\Windows\\system32\\userinit.exe, and investigate any extra program listed.", new { Userinit = userinit }, "T1547.004", "persistence.winlogon-userinit");
    }

    private void AppInitAndIfeo()
    {
        foreach (var k in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
            if (Reg.Value(Registry.LocalMachine, k, "AppInit_DLLs") is string ai && !string.IsNullOrWhiteSpace(ai))
                _ctx.Add(Severity.High, "Persistence", "AppInit_DLLs is set", $"This DLL is loaded into every program with a window: {ai}",
                         "Investigate the DLL and clear AppInit_DLLs if it is not from security software you trust.", new { AppInit_DLLs = ai }, "T1546.010", "persistence.appinit");

        const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        foreach (var exe in Reg.SubKeys(Registry.LocalMachine, ifeo))
            if (Reg.Value(Registry.LocalMachine, $@"{ifeo}\{exe}", "Debugger") is string dbg && !string.IsNullOrWhiteSpace(dbg))
            {
                bool knownTool = Regex.IsMatch(dbg, @"procexp|systeminformer|processhacker|vsjitdebugger", RegexOptions.IgnoreCase);
                _ctx.Add(knownTool ? Severity.Info : Severity.High, "Persistence", $"Program hijack (IFEO debugger) on {exe}", $"Starting {exe} actually runs: {dbg}",
                         knownTool ? "This looks like a known tool replacing Task Manager - fine if you set it up." : "Remove this Debugger value unless you set it up deliberately.",
                         new { Program = exe, Debugger = dbg }, "T1546.012", "persistence.ifeo");
            }
    }

    private void StartupFolders()
    {
        var folders = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp") };
        folders.AddRange(Sys.UserProfiles().Select(u => Path.Combine(u.Path, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")));
        foreach (var f in folders.Where(Directory.Exists))
        {
            string[] files; try { files = Directory.GetFiles(f); } catch { continue; }
            foreach (var file in files.Where(x => !x.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)))
            {
                var cmd = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? Shortcut.Resolve(file) ?? file : file;
                Evaluate($"Startup folder: {f}", Path.GetFileName(file), cmd, null, "T1547.001", "persistence.startup-folder");
            }
        }
    }

    private void Services()
    {
        foreach (var s in Wmi.Query("SELECT Name, DisplayName, PathName, StartMode, State, StartName FROM Win32_Service"))
        {
            var cmd = s.S("PathName"); if (string.IsNullOrEmpty(cmd)) continue;
            Evaluate("Service", $"{s.S("Name")} ({s.S("DisplayName")})", cmd, $"{s.S("StartMode")} / {s.S("State")} / {s.S("StartName")}", "T1543.003", "persistence.service", skipMicrosoft: true);
        }
        _rows.RemoveAll(r => r.Location == "Service" && r.Risk == Risk.Info && (r.Signer?.StartsWith("Microsoft") ?? false) && (r.Target?.StartsWith(Sys.SystemRoot, StringComparison.OrdinalIgnoreCase) ?? false));
    }

    private void ScheduledTasks()
    {
        var root = Path.Combine(Sys.SystemRoot, @"System32\Tasks");
        if (!Directory.Exists(root)) return;
        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).ToList(); }
        catch { return; }
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        foreach (var file in files)
        {
            XDocument doc; try { doc = XDocument.Load(file); } catch { continue; }
            var taskPath = file[root.Length..].Replace('\\', '\\');
            var folder = Path.GetDirectoryName(taskPath) ?? "\\";
            bool isMicrosoftFolder = taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase);
            var author = doc.Descendants(ns + "Author").FirstOrDefault()?.Value;
            var hidden = doc.Descendants(ns + "Hidden").FirstOrDefault()?.Value;
            var enabled = doc.Descendants(ns + "Settings").Elements(ns + "Enabled").FirstOrDefault()?.Value ?? "true";
            foreach (var exec in doc.Descendants(ns + "Exec"))
            {
                var command = exec.Element(ns + "Command")?.Value?.Trim();
                if (string.IsNullOrEmpty(command)) continue;
                var args = exec.Element(ns + "Arguments")?.Value;
                var full = (command.Contains(' ') && !command.StartsWith('"') ? $"\"{command}\"" : command) + (string.IsNullOrEmpty(args) ? "" : " " + args);
                var target = CommandLine.ExtractTarget(full, resolve: Sys.ResolveProgram);
                var intel = _ctx.Files.Get(target);
                if (isMicrosoftFolder && intel is { IsMicrosoft: true }) continue;  // genuine Windows task
                var risk = Evaluate($"Scheduled task {folder}", Path.GetFileName(taskPath), full, $"Enabled: {enabled} / Hidden: {hidden ?? "false"} / Author: {author}", "T1053.005", "persistence.scheduled-task");
                // Non-Microsoft program hiding among Windows' own tasks is a known trick.
                if (isMicrosoftFolder && intel is not null && intel.Exists && !intel.IsMicrosoft && risk is not (Risk.High or Risk.Critical))
                    _ctx.Add(Severity.Medium, "Persistence", $"Non-Microsoft program in a Windows task folder: {Path.GetFileName(taskPath)}", $"{taskPath}\n{full}",
                             "Malware hides tasks under \\Microsoft\\. Check whether this belongs to software you installed.", new { Task = taskPath, Command = full, intel.Signer }, "T1053.005", "persistence.task-masquerade");
            }
        }
    }

    private List<object> WmiSubscriptions()
    {
        var found = new List<object>();
        foreach (var c in Wmi.Query("SELECT * FROM __EventConsumer", @"root\subscription"))
        {
            var name = c.S("Name") ?? "(unnamed)";
            if (_ctx.Indicators.KnownGoodWmiConsumers.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            var detail = c.S("CommandLineTemplate") ?? (c.S("ScriptText") is string st ? Sys.Trunc(st, 400) : c.S("__CLASS"));
            var row = new { Name = name, Class = c.S("__CLASS"), Detail = detail };
            found.Add(row);
            _ctx.Add(Severity.High, "Persistence", $"WMI event subscription: {name}", $"{c.S("__CLASS")}: {detail}",
                     "WMI subscriptions are a stealthy way to run code automatically. Investigate unless it belongs to known management software.", row, "T1546.003", "persistence.wmi");
        }
        return found;
    }
}

/// <summary>Reads .lnk targets via the Windows Script Host COM object (read-only).</summary>
[SupportedOSPlatform("windows")]
internal static class Shortcut
{
    public static string? Resolve(string lnk)
    {
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell"); if (t is null) return null;
            dynamic shell = Activator.CreateInstance(t)!;
            try
            {
                dynamic sc = shell.CreateShortcut(lnk);
                string target = sc.TargetPath; string args = sc.Arguments;
                return string.IsNullOrEmpty(target) ? null : $"\"{target}\" {args}".Trim();
            }
            finally { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell); }
        }
        catch { return null; }
    }
}
