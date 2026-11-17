using System.Reflection;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Yara;

public static class YaraRuleSet
{
    /// <summary>Rules compiled into the binary.</summary>
    public static List<YaraRule> LoadBuiltIn()
    {
        var asm = Assembly.GetExecutingAssembly();
        var rules = new List<YaraRule>();
        // Built-in rules ship gzip-compressed so their detection strings don't sit in the binary as plain text
        // (which other antivirus products could mistake for malware).
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith("rules/") && n.EndsWith(".yar.gz")).OrderBy(n => n))
        {
            using var s = asm.GetManifestResourceStream(name)!;
            using var gz = new System.IO.Compression.GZipStream(s, System.IO.Compression.CompressionMode.Decompress);
            using var r = new StreamReader(gz);
            rules.AddRange(YaraParser.Parse(r.ReadToEnd(), name[..^3]));
        }
        return rules;
    }

    /// <summary>Built-in rules plus the rules of a trusted (signed) rule pack, as the YARA check uses them.</summary>
    public static List<YaraRule> LoadAll(ScanOptions o, List<string>? errors = null)
    {
        var rules = LoadBuiltIn();
        if (!o.ExternalRulesTrusted) return rules;
        var names = rules.Select(r => r.Name).ToHashSet();
        var manifest = Path.Combine(o.RulesDirectory, TriageKit.Core.Rules.RulePack.ManifestName);
        var allowed = File.Exists(manifest) ? TriageKit.Core.Rules.RulePack.SignedFiles(o.RulesDirectory) : null;
        rules.AddRange(LoadDirectory(Path.Combine(o.RulesDirectory, "yara"), errors ?? new List<string>(), names, allowed));
        return rules;
    }

    /// <summary>Additional rule files from a directory. Broken files are skipped and reported, never fatal.</summary>
    public static List<YaraRule> LoadDirectory(string dir, List<string> errors, ISet<string> existingNames, ISet<string>? allowedFiles = null)
    {
        var rules = new List<YaraRule>();
        if (!Directory.Exists(dir)) return rules;
        foreach (var file in Directory.GetFiles(dir, "*.yar").Concat(Directory.GetFiles(dir, "*.yara")).OrderBy(f => f))
        {
            if (allowedFiles is not null && !allowedFiles.Contains(Path.GetFullPath(file))) { errors.Add($"{Path.GetFileName(file)}: not covered by the signed manifest - ignored"); continue; }
            try
            {
                foreach (var rule in YaraParser.Parse(File.ReadAllText(file), Path.GetFileName(file)))
                    if (existingNames.Add(rule.Name)) rules.Add(rule);
            }
            catch (Exception ex) { errors.Add($"{Path.GetFileName(file)}: {ex.Message}"); }
        }
        return rules;
    }
}

/// <summary>Runs YARA rules against unsigned executables and scripts collected by earlier checks plus a script sweep.</summary>
public sealed class YaraCheck : ICheck
{
    private readonly string? _name;
    public string Name => _name ?? "YARA scan";
    public bool IsSlow => true;
    public int Order => 80;   // after collectors, before reputation

    private const long MaxFileBytes = 32L * 1024 * 1024;
    private static readonly Regex ScriptExt = new(@"\.(ps1|psm1|vbs|vbe|js|jse|mjs|cjs|py|pyw|au3|ahk|hta|bat|cmd|wsf)$", RegexOptions.IgnoreCase);
    private static readonly Regex BinaryExt = new(@"\.(exe|dll|scr|com|cpl|sys)$", RegexOptions.IgnoreCase);
    private static readonly Regex ContainerExt = new(@"\.(zip|docm|xlsm|pptm|dotm|xltm|docx|xlsx|pptx|doc|xls|ppt|xlam)$", RegexOptions.IgnoreCase);
    private static readonly Regex SweepExt = new(@"\.(ps1|psm1|vbs|vbe|js|jse|mjs|cjs|py|pyw|au3|ahk|hta|bat|cmd|wsf|lnk|zip|docm|xlsm|pptm|dotm|xltm|docx|xlsx|doc|xls|xlam)$", RegexOptions.IgnoreCase);
    private readonly IReadOnlyList<YaraRule>? _rules;
    private readonly IEnumerable<string>? _extraTargets;

    public YaraCheck() { }
    /// <summary>Same rules, explicit target list, own name (used by the deep scan).</summary>
    public YaraCheck(string name, IEnumerable<string> targets) { _name = name; _extraTargets = targets; }
    /// <summary>Test constructor: explicit rules and targets.</summary>
    public YaraCheck(IEnumerable<YaraRule> rules, IEnumerable<string> targets) { _rules = rules.ToList(); _extraTargets = targets; }

    public object? Run(CheckContext ctx)
    {
        if (!ctx.Options.RunYara)
        {
            // Something running as the user could switch this off before a technician scans; make it visible.
            ctx.Add(Severity.Info, "Collector", "Malware rule scan is switched off", "RunYara is false in config.json, so files were not checked against malware rules.",
                    "Turn it back on in Settings unless you switched it off on purpose.", ruleId: "collector.disabled");
            return new { Ran = false, Reason = "Disabled in config" };
        }
        if (!ctx.Options.ScanArchives && _name is null)
            ctx.Add(Severity.Info, "Collector", "Archives and Office files aren't opened", "\"Look inside archives\" is off in Settings, so malware hidden inside ZIP files, Office macros and shortcut targets was not checked.",
                    "Turn it back on in Settings unless you switched it off on purpose.", ruleId: "collector.disabled");
        var errors = new List<string>();
        List<YaraRule> rules;
        if (_rules is not null) rules = _rules.ToList();
        else
        {
            rules = YaraRuleSet.LoadBuiltIn();
            var names = new HashSet<string>(rules.Select(r => r.Name));
            if (ctx.Options.ExternalRulesTrusted)
            {
                var manifest = Path.Combine(ctx.Options.RulesDirectory, TriageKit.Core.Rules.RulePack.ManifestName);
                var allowed = File.Exists(manifest) ? TriageKit.Core.Rules.RulePack.SignedFiles(ctx.Options.RulesDirectory) : null;  // null = unsigned rules explicitly allowed
                rules.AddRange(YaraRuleSet.LoadDirectory(Path.Combine(ctx.Options.RulesDirectory, "yara"), errors, names, allowed));
            }
        }
        foreach (var e in errors) ctx.Add(Severity.Info, "YARA", "A rule file could not be loaded", e, "Fix or remove the rule file.");
        var scanner = new YaraScanner(rules);

        var targets = Targets(ctx).ToList();
        var rows = new List<object>();
        int scanned = 0, skipped = 0, incompleteFiles = 0, containers = 0;
        var unreadable = new List<string>();
        foreach (var path in targets)
        {
            if (ctx.Cancellation.IsCancellationRequested) break;
            // Excluded folders are still scanned: the accept list later hides non-critical results, but a Critical match always shows.
            lock (ctx.RuleScanned) { if (!ctx.RuleScanned.Add(path)) continue; }
            if (ctx.Options.ScanArchives && ContainerExt.IsMatch(path))
            {
                containers++;
                // A container that can't be opened is reported with the unreadable files (a damaged or crafted archive is
                // exactly what malware uses to slip past scanners), not hidden as a minor note.
                try { ScanContainer(ctx, scanner, path, rows, unreadable); } catch (Exception ex) { lock (unreadable) unreadable.Add(path); CheckContext.Minor($"Couldn't open {Path.GetFileName(path)}", ex); }
                continue;
            }
            byte[] data;
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists || fi.Length == 0 || fi.Length > MaxFileBytes) { skipped++; continue; }
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                data = new byte[fi.Length];
                fs.ReadExactly(data);
            }
            catch { skipped++; continue; }
            if (SelfIdentity.IsSelf(path, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)))) { skipped++; continue; }
            scanned++;
            if (ctx.Options.ScanArchives && path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) CheckShortcut(ctx, path, data, rows);
            if (!ScanBytes(ctx, scanner, path, null, data, rows)) incompleteFiles++;
        }
        if (incompleteFiles > 0) CheckContext.Note($"{incompleteFiles} file(s) hit the per-file time limit and were only partly checked");
        if (unreadable.Count > 0)
            ctx.Add(Severity.Info, "Files", $"{unreadable.Count} archive(s) could not be fully checked", string.Join("\n", unreadable.Take(10)),
                    "Password-protected or oversized archives can hide malware. Only open them if you trust the sender.", unreadable, null, "archive.unreadable");
        return new { Ran = true, Rules = rules.Count, RuleErrors = errors, Scanned = scanned, Containers = containers, Skipped = skipped, PartlyChecked = incompleteFiles, Matches = rows };
    }

    /// <summary>Runs the rules over one buffer. Returns false when the time budget ran out.</summary>
    private static bool ScanBytes(CheckContext ctx, YaraScanner scanner, string path, string? inner, byte[] data, List<object> rows)
    {
        bool isPe = data.Length > 1 && data[0] == 'M' && data[1] == 'Z';
        var matches = scanner.Scan(data, ctx.Options.RuleBudgetPerFile, ctx.Cancellation, out bool incomplete);
        var shown = inner is null ? path : $"{path} » {inner}";
        var name = inner is null ? Path.GetFileName(path) : $"{Path.GetFileName(path)} » {Path.GetFileName(inner)}";
        foreach (var m in matches)
        {
            var target = m.Rule.Meta.GetValueOrDefault("target", "any");
            if (target == "pe" && !isPe) continue;
            if (target == "script" && isPe) continue;
            var sev = Enum.TryParse<Severity>(m.Rule.Meta.GetValueOrDefault("severity", "medium"), true, out var s) ? s : Severity.Medium;
            var strings = string.Join(", ", m.Hits.Keys.Take(6).Select(id => m.Rule.Strings.First(x => x.Id == id).Display).Select(d => d.Length > 60 ? d[..60] + "..." : d));
            var desc = m.Rule.Meta.GetValueOrDefault("description", m.Rule.Name);
            var row = new { Risk = sev.ToString(), Path = shown, Rule = m.Rule.Name, Description = desc, Matched = strings, Tags = string.Join(" ", m.Rule.Tags) };
            lock (rows) rows.Add(row);
            ctx.Add(sev, "YARA", $"{desc}: {name}", $"{shown}\nRule: {m.Rule.Name}\nMatched: {strings}",
                    m.Rule.Meta.GetValueOrDefault("advice", inner is null ? "Review this file. If you don't recognise it, remove it." : "This archive or document contains a file that matches a malware rule. Don't open it unless you trust the sender."),
                    row, m.Rule.Meta.GetValueOrDefault("mitre"), "yara." + m.Rule.Name);
            if (inner is null) ctx.Files.Get(path);   // feed the reputation check
        }
        return !incomplete;
    }

    private static readonly Regex InnerWanted = new(@"(\.(exe|dll|scr|com|cpl|ps1|psm1|vbs|vbe|js|jse|mjs|cjs|py|pyw|au3|ahk|hta|bat|cmd|wsf|lnk|msi|iso|img)$|^vbaProject\.bin$)", RegexOptions.IgnoreCase);

    /// <summary>Files inside a downloaded ZIP that are typical malware lures: shortcuts and Windows script types anywhere,
    /// and JavaScript only at the top level (web projects and plugins are full of .js files). Programs (.exe) are normal
    /// in downloads and are judged by the malware rules instead; macOS "._" metadata files are ignored.</summary>
    internal static bool DeliveryLure(string entry)
    {
        var name = entry.Replace('\\', '/');
        var file = name[(name.LastIndexOf('/') + 1)..];
        if (file.StartsWith("._", StringComparison.Ordinal) || name.StartsWith("__MACOSX/", StringComparison.OrdinalIgnoreCase)) return false;
        if (Regex.IsMatch(file, @"\.(scr|jse|vbs|vbe|hta|lnk|wsf|bat|cmd|ps1)$", RegexOptions.IgnoreCase)) return true;
        return !name.Contains('/') && file.EndsWith(".js", StringComparison.OrdinalIgnoreCase);
    }

    private static void ScanContainer(CheckContext ctx, YaraScanner scanner, string path, List<object> rows, List<string> unreadable)
    {
        var fi = new FileInfo(path);
        if (!fi.Exists || fi.Length == 0 || fi.Length > ZipContents.MaxTotalBytes) return;
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        Span<byte> head = stackalloc byte[8];
        int n = fs.Read(head);
        fs.Position = 0;
        if (n >= 4 && ZipContents.IsZip(head))
        {
            var budget = new ZipContents.Budget();
            var macroSources = new List<string>();
            foreach (var e in ZipContents.Read(fs, InnerWanted.IsMatch, budget, ctx.Cancellation))
            {
                if (e.Name.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)) { macroSources.AddRange(VbaMacros.ExtractSources(e.Data)); if (macroSources.Count == 0) macroSources.Add(""); continue; }
                if (e.Name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) CheckShortcut(ctx, $"{path} » {e.Name}", e.Data, rows);
                ScanBytes(ctx, scanner, path, e.Name, e.Data, rows);
                if (DeliveryLure(e.Name) && InRiskyFolder(path) && path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && Recent(fi, ctx))
                    ctx.Add(Severity.Low, "Files", $"Recent download contains a program or script: {Path.GetFileName(path)} » {Path.GetFileName(e.Name)}",
                            $"{path}\nInside: {e.Name}", "Archives that contain scripts or shortcuts are a common way to deliver malware. Only run it if you trust the sender.",
                            new { Path = path, Entry = e.Name }, "T1566.001", "archive.executable-inside");
            }
            if (macroSources.Count > 0) ReportMacros(ctx, path, fi, macroSources.Where(x => x.Length > 0), rows);
            if (budget.Encrypted || budget.LimitHit) lock (unreadable) unreadable.Add($"{path} ({(budget.Encrypted ? "password-protected" : budget.LimitReason)})");
            return;
        }
        if (n >= 8 && VbaMacros.IsOle(head) && fi.Length <= MaxFileBytes)
        {
            var data = new byte[fi.Length];
            fs.ReadExactly(data);
            var sources = VbaMacros.ExtractSources(data);
            if (sources.Count > 0) ReportMacros(ctx, path, fi, sources, rows);
            ScanBytes(ctx, scanner, path, null, data, rows);
        }
    }

    private static bool InRiskyFolder(string path) =>
        Regex.IsMatch(path, @"\\(Downloads|Desktop|AppData\\Local\\Temp|Temp|Outlook|INetCache|Content\.Outlook)\\", RegexOptions.IgnoreCase);
    private static bool Recent(FileInfo fi, CheckContext ctx) => fi.LastWriteTime > DateTime.Now.AddDays(-Math.Max(ctx.Options.RecentFileDays, 14));

    private static void ReportMacros(CheckContext ctx, string path, FileInfo fi, IEnumerable<string> sources, List<object> rows)
    {
        var v = VbaMacros.Analyse(sources);
        bool risky = InRiskyFolder(path);
        var sev = v.AutoExec.Count > 0 && v.Suspicious.Count > 0 ? (risky ? Severity.High : Severity.Medium)
                : v.AutoExec.Count > 0 || v.Suspicious.Count >= 2 ? (risky ? Severity.Medium : Severity.Low)
                : risky && Recent(fi, ctx) ? Severity.Low : Severity.Info;
        var what = v.AutoExec.Count > 0 ? "runs automatically when opened" : "contains macros";
        var detail = $"{path}\nAuto-run: {(v.AutoExec.Count > 0 ? string.Join(", ", v.AutoExec) : "none found")}\nSuspicious keywords: {(v.Suspicious.Count > 0 ? string.Join(", ", v.Suspicious) : "none found")}";
        var row = new { Risk = sev.ToString(), Path = path, Rule = "office-macro", Description = $"Office document {what}", Matched = string.Join(", ", v.AutoExec.Concat(v.Suspicious).Take(8)), Tags = "macro" };
        lock (rows) rows.Add(row);
        ctx.Add(sev, "Files", $"Office document {what}: {Path.GetFileName(path)}", detail,
                sev <= Severity.Medium ? "Don't enable editing or macros in this document unless you wrote it or fully trust the sender. Macro documents are a leading way to infect PCs."
                                       : "Macros are normal in some business documents. Only enable them for documents you trust.",
                row, "T1204.002", v.AutoExec.Count > 0 && v.Suspicious.Count > 0 ? "office.macro-autoexec-suspicious" : "office.macro");
    }

    private static void CheckShortcut(CheckContext ctx, string shown, byte[] data, List<object> rows)
    {
        var info = Shortcut.Parse(data);
        if (info is null) return;
        var why = Shortcut.Assess(info);
        if (why is null) return;
        bool startup = shown.Contains(@"\Startup\", StringComparison.OrdinalIgnoreCase) || shown.Contains(@"\Start Menu\", StringComparison.OrdinalIgnoreCase);
        var sev = startup || shown.Contains(" » ") ? Severity.High : Severity.Medium;
        var args = info.Arguments ?? "";
        var row = new { Risk = sev.ToString(), Path = shown, Rule = "lnk-suspicious", Description = "Shortcut runs a hidden command", Matched = why, Tags = "lnk" };
        lock (rows) rows.Add(row);
        ctx.Add(sev, "Files", $"Shortcut runs a hidden command: {Path.GetFileName(shown)}",
                $"{shown}\nTarget: {info.Target}\nArguments: {(args.Length > 400 ? args[..400] + "..." : args)}\nWhy: it {why}",
                "Shortcuts that start PowerShell, mshta or cmd with hidden commands are a common malware trick. Don't open it; delete it if you didn't create it.",
                new { Path = shown, info.Target, Arguments = args.Length > 2000 ? args[..2000] : args }, "T1204.002", "lnk.suspicious");
    }

    private IEnumerable<string> Targets(CheckContext ctx)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var own = new[] { AppContext.BaseDirectory, ctx.Options.RulesDirectory, ctx.Options.ToolsDirectory, ctx.Options.OutputDirectory }
            .Where(d => !string.IsNullOrEmpty(d)).Select(d => Path.GetFullPath(d).TrimEnd('\\', '/')).ToList();
        bool Own(string p) => own.Any(o => p.StartsWith(o + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || p.StartsWith(o + "\\", StringComparison.OrdinalIgnoreCase));

        if (_extraTargets is not null)
        {
            foreach (var t in _extraTargets) if (seen.Add(t)) yield return t;
            yield break;
        }
        // 1. Unsigned (or tampered) executables already discovered by other checks.
        foreach (var f in ctx.Files.All.Where(f => f.Exists && (!f.IsSigned || f.SignatureStatus == SignatureStatus.HashMismatch)))
            if (!Own(f.Path) && (BinaryExt.IsMatch(f.Path) || ScriptExt.IsMatch(f.Path)) && seen.Add(f.Path)) yield return f.Path;
        // 2. Scripts in the places malware drops them (Windows only).
        if (!OperatingSystem.IsWindows()) yield break;
        foreach (var p in ScriptSweep(ctx)) if (!Own(p) && seen.Add(p)) yield return p;
    }

    private static bool IsStartup(string p) => p.Contains(@"\Startup\", StringComparison.OrdinalIgnoreCase);

    [SupportedOSPlatform("windows")]
    private static IEnumerable<string> ScriptSweep(CheckContext ctx)
    {
        var since = DateTime.Now.AddDays(-Math.Max(ctx.Options.RecentFileDays, 30));
        // Order matters: the places users open files from come first, so a busy AppData can't use up the budget.
        var roots = new List<(string Dir, int Depth)>
        {
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs\StartUp"), 0),
        };
        var profiles = Sys.UserProfiles().ToList();
        foreach (var u in profiles) roots.Add((Path.Combine(u.Path, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"), 0));
        foreach (var u in profiles) { roots.Add((Path.Combine(u.Path, "Downloads"), 2)); roots.Add((Path.Combine(u.Path, "Desktop"), 1)); }
        foreach (var u in profiles) roots.Add((Path.Combine(u.Path, @"AppData\Local\Temp"), 3));
        roots.Add((Path.Combine(Sys.SystemRoot, "Temp"), 2));
        roots.Add((Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public", 3));
        roots.Add((Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 2));
        foreach (var u in profiles) { roots.Add((Path.Combine(u.Path, @"AppData\Roaming"), 2)); roots.Add((Path.Combine(u.Path, @"AppData\Local"), 1)); }
        int count = 0;
        const int Total = 1500, PerRoot = 300;
        foreach (var (dir, depth) in roots.Where(r => Directory.Exists(r.Dir)))
        {
            // Startup, Downloads and Desktop are where malicious files land; missing files there is a real gap.
            bool prime = IsStartup(dir + "\\") || dir.EndsWith(@"\Downloads", StringComparison.OrdinalIgnoreCase) || dir.EndsWith(@"\Desktop", StringComparison.OrdinalIgnoreCase);
            var matches = new List<FileInfo>();
            try
            {
                foreach (var f in new DirectoryInfo(dir).EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = depth > 0, MaxRecursionDepth = Math.Max(depth, 1), IgnoreInaccessible = true }))
                {
                    if (ctx.Cancellation.IsCancellationRequested) yield break;
                    bool match; try { match = (ctx.Options.ScanArchives ? SweepExt : ScriptExt).IsMatch(f.Name) && (f.LastWriteTime > since || IsStartup(f.FullName)) && f.Length < ZipContents.MaxTotalBytes && (f.Length < MaxFileBytes || ContainerExt.IsMatch(f.Name)); } catch { continue; }
                    if (match) matches.Add(f);
                    if (matches.Count > PerRoot * 20) break;   // bound memory on huge folders; newest-first below still applies
                }
            }
            catch { continue; }
            // Newest first: a fresh download matters more than last month's.
            var take = matches.OrderByDescending(f => { try { return f.LastWriteTimeUtc; } catch { return DateTime.MinValue; } }).Take(PerRoot).ToList();
            if (matches.Count > PerRoot)
            {
                var msg = $"Only the newest {PerRoot} of {matches.Count}+ matching files in {dir} were checked";
                if (prime) CheckContext.Note(msg); else CheckContext.Minor(msg);
            }
            foreach (var f in take)
            {
                if (count >= Total)
                {
                    // The prime folders come first, so reaching the total there is a real gap; later folders are extra.
                    var msg = $"File sweep stopped at {Total} files; later folders (from {dir}) were not checked";
                    if (prime) CheckContext.Note(msg); else CheckContext.Minor(msg);
                    yield break;
                }
                count++;
                yield return f.FullName;
            }
        }
    }
}
