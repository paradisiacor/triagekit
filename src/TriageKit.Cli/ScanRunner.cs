using System.Runtime.Versioning;
using System.Text.Json;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;
using TriageKit.Core.Reporting;
using TriageKit.Core.Rules;

namespace TriageKit.Cli;

public sealed class AppConfig
{
    public string? VirusTotalApiKey { get; set; }
    public int VirusTotalMaxLookups { get; set; } = 8;
    public int VirusTotalDelaySeconds { get; set; } = 16;
    public bool AskCaseInfo { get; set; }
    public int EventLogDays { get; set; } = 30;
    public int RecentFileDays { get; set; } = 14;
    public int RecentFileMaxItems { get; set; } = 400;
    /// <summary>Off by default: Microsoft Defender removes threats it finds, so this step is not read-only.</summary>
    public bool RunDefenderQuickScan { get; set; } = false;
    public bool RunAutoruns { get; set; } = true;
    public bool RunYara { get; set; } = true;
    public int ReputationMaxFiles { get; set; } = 60;
    public bool ReputationDefender { get; set; } = true;
    public bool ReputationCircl { get; set; } = true;
    public string? MalwareBazaarAuthKey { get; set; }
    /// <summary>Off until the user agrees: file fingerprints are only sent to reputation services with consent.</summary>
    public bool OnlineLookups { get; set; }
    public bool OnlineLookupsAsked { get; set; }
    /// <summary>Extra modules included in every full check, e.g. "doctor", "gaming".</summary>
    public List<string> IncludeModules { get; set; } = new();
    /// <summary>Look inside ZIP archives and Office documents, and read shortcut targets.</summary>
    public bool ScanArchives { get; set; } = true;
    /// <summary>Remember hashes and signatures of Windows and Program Files files between scans (faster repeat scans).</summary>
    public bool RememberFileChecks { get; set; } = true;
    /// <summary>Run independent checks side by side (1 = one at a time).</summary>
    public int Parallelism { get; set; } = 3;
    /// <summary>Where signed update announcements come from (default: the TriageKit update service).</summary>
    public string? UpdateServerUrl { get; set; }
    /// <summary>Look for a newer version once a day (sends nothing about this PC).</summary>
    public bool CheckForUpdates { get; set; } = true;
    public string UpdateChannel { get; set; } = "beta";

    public static readonly string[] SecretKeys = { "VirusTotalApiKey", "MalwareBazaarAuthKey" };

    public static AppConfig Load(string path, Action<string>? warn = null)
    {
        var cfg = new AppConfig();
        try
        {
            if (File.Exists(path))
                cfg = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }) ?? new();
        }
        catch (Exception ex) { warn?.Invoke($"config.json could not be read ({ex.Message}); using defaults."); }
        // Keys stored in the admins-only secrets file (installed copy) override config.json.
        var sec = ReadSecrets();
        if (sec["VirusTotalApiKey"]?.GetValue<string>() is { Length: > 0 } vt) cfg.VirusTotalApiKey = vt;
        if (sec["MalwareBazaarAuthKey"]?.GetValue<string>() is { Length: > 0 } mb) cfg.MalwareBazaarAuthKey = mb;
        return cfg;
    }

    public static System.Text.Json.Nodes.JsonObject ReadSecrets()
    {
        try
        {
            if (OperatingSystem.IsWindows() && File.Exists(Agent.AgentPaths.SecretsFile))
                return System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(Agent.AgentPaths.SecretsFile)) as System.Text.Json.Nodes.JsonObject ?? new();
        }
        catch { /* not readable without admin rights, or damaged: behave as if there are no stored keys */ }
        return new();
    }

    public static void WriteSecrets(System.Text.Json.Nodes.JsonObject secrets)
    {
        var dir = Path.GetDirectoryName(Agent.AgentPaths.SecretsFile)!;
        if (OperatingSystem.IsWindows()) Agent.SecureFolder.EnsurePrivate(dir); else Directory.CreateDirectory(dir);
        File.WriteAllText(Agent.AgentPaths.SecretsFile, secrets.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

public sealed class ScanRequest
{
    public required string BaseDirectory { get; init; }        // where TriageKit.exe, rules\ and tools\ live
    public required string OutputRoot { get; init; }
    public required AppConfig Config { get; init; }
    public string Edition { get; init; } = "Portable";
    public bool Quick { get; init; }
    public bool Deep { get; init; }
    public bool Offline { get; init; }
    public bool NoVirusTotal { get; init; }
    public bool NoYara { get; init; }
    public bool NoDefenderScan { get; init; }
    public bool AllowUnsignedRules { get; init; }
    public string? CaseId { get; init; }
    public string? Technician { get; init; }
    public Action<string>? Status { get; init; }
    public Action<string, int, int>? Progress { get; init; }
    /// <summary>A check finished: its name and how long it took in milliseconds.</summary>
    public Action<string, long>? CheckFinished { get; init; }
    /// <summary>A check starts running (checks in later groups wait for earlier ones).</summary>
    public Action<string>? CheckStarted { get; init; }
    public CancellationToken Cancellation { get; init; }
    /// <summary>Exact modules to run (null = security + the configured extra modules).</summary>
    public IEnumerable<string>? Modules { get; init; }
    public string FolderSuffix { get; init; } = "";
    /// <summary>Uses the installed copy's shared data (accepted findings, file cache) in ProgramData.</summary>
    public bool Installed { get; init; }
}

public sealed record ScanOutcome(ScanResult Result, string ReportHtml, string ResultsJson, string OutputDirectory, string RulesVersion);

/// <summary>Where per-PC data lives. The installed copy keeps it in ProgramData (admin-only where it matters).</summary>
[SupportedOSPlatform("windows")]
public static class AppPaths
{
    public static string SuppressionsFile(bool installed, string baseDir) => installed ? Path.Combine(Agent.AgentPaths.DataDir, "accepted.json") : Path.Combine(baseDir, "accepted.json");

    /// <summary>The file cache must not be writable by normal users (it says which files were verified), so it always
    /// lives in an admin-only folder, also for the portable copy.</summary>
    public static string? FileCache(bool installed)
    {
        try
        {
            var dir = installed ? Path.GetDirectoryName(Agent.AgentPaths.SecretsFile)! : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TriageKit", "PortableCache");
            Agent.SecureFolder.EnsurePrivate(dir);
            return Path.Combine(dir, "filecache.json");
        }
        catch { return null; }
    }
}

/// <summary>One scan, shared by the interactive portable mode and the background service.</summary>
[SupportedOSPlatform("windows")]
public static class ScanRunner
{
    /// <summary>Modules beyond the security check (PC Doctor, Gaming), free for everyone and chosen in Settings.</summary>
    public static readonly string[] AddOnModules = { "doctor", "gaming" };

    private static HashSet<string> BuildModules(ScanRequest req, AppConfig cfg)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (req.Modules is not null) foreach (var m in req.Modules) set.Add(m);
        else { set.Add("security"); if (!req.Quick) foreach (var m in cfg.IncludeModules) set.Add(m); }
        if (set.Count == 0) set.Add("security");
        return set;
    }

    public static ScanOutcome Run(ScanRequest req, string version)
    {
        var outDir = Path.Combine(req.OutputRoot, $"{Environment.MachineName}_{DateTime.Now:yyyyMMdd-HHmmss}{req.FolderSuffix}");
        Directory.CreateDirectory(outDir);
        using var log = new StreamWriter(Path.Combine(outDir, "collector.log")) { AutoFlush = true };
        void Log(string m) { lock (log) log.WriteLine($"{DateTime.Now:HH:mm:ss} {m}"); }

        var cfg = req.Config;
        bool offline = req.Offline || !cfg.OnlineLookups;
        var rulesDir = Path.Combine(req.BaseDirectory, "rules");
        var pack = RulePack.Verify(rulesDir);
        bool rulesTrusted = pack.Trusted || req.AllowUnsignedRules;
        bool packPresent = Directory.Exists(rulesDir) && Directory.EnumerateFiles(rulesDir, "*", SearchOption.AllDirectories).Any(f => f.EndsWith(".json") || f.EndsWith(".yar"));
        Log(pack.Trusted ? $"Rule pack verified: {pack.Version}" : $"Rule pack not trusted: {pack.Error}");
        var indicators = rulesTrusted ? Indicators.Load(Path.Combine(rulesDir, "indicators.json"), Log) : Indicators.LoadBuiltIn();

        var elevated = Sys.IsElevated();
        var options = new ScanOptions
        {
            Quick = req.Quick && !req.Deep, Deep = req.Deep, CheckTimeout = req.Deep ? TimeSpan.FromMinutes(60) : TimeSpan.FromMinutes(10), Elevated = elevated, OutputDirectory = outDir, ToolsDirectory = Path.Combine(req.BaseDirectory, "tools"),
            VirusTotalApiKey = req.NoVirusTotal || offline ? null : cfg.VirusTotalApiKey, VirusTotalMaxLookups = cfg.VirusTotalMaxLookups,
            VirusTotalDelaySeconds = cfg.VirusTotalDelaySeconds, EventLogDays = cfg.EventLogDays, RecentFileDays = cfg.RecentFileDays,
            RecentFileMaxItems = cfg.RecentFileMaxItems, RunDefenderQuickScan = cfg.RunDefenderQuickScan && !req.NoDefenderScan,
            RunAutoruns = cfg.RunAutoruns, RunYara = cfg.RunYara && !req.NoYara,
            ReputationMaxFiles = cfg.ReputationMaxFiles, ReputationDefender = cfg.ReputationDefender, ReputationCircl = cfg.ReputationCircl && !offline,
            MalwareBazaarAuthKey = offline ? null : cfg.MalwareBazaarAuthKey,
            RulesDirectory = rulesDir, ExternalRulesTrusted = rulesTrusted,
            Modules = BuildModules(req, cfg),
            ScanArchives = cfg.ScanArchives, Parallelism = Math.Clamp(cfg.Parallelism, 1, 6),
            Suppressions = SuppressionSet.Load(AppPaths.SuppressionsFile(req.Installed, req.BaseDirectory)),
            FileCachePath = cfg.RememberFileChecks && elevated ? AppPaths.FileCache(req.Installed) : null,
        };

        var ctx = new CheckContext(options, indicators, new FileIntelService(), m => { Log(m); req.Status?.Invoke(m); });
        var meta = new ScanMeta { KitVersion = version, Edition = req.Edition, Elevated = elevated, Quick = req.Quick, CaseId = req.CaseId,
                                  Technician = req.Technician, RulePackVersion = rulesTrusted && pack.Version is not null ? pack.Version : indicators.Version };
        if (packPresent && !pack.Trusted && !req.AllowUnsignedRules)
            ctx.Add(Severity.Info, "Collector", "Rule update ignored: not signed by the publisher", $"The rules folder failed verification ({pack.Error}). Built-in rules were used instead.",
                    "Download the latest rule pack from the official website.", ruleId: "collector.rulepack-untrusted");
        if (req.AllowUnsignedRules)
            ctx.Add(Severity.Info, "Collector", "Unsigned rules were allowed (--allow-unsigned-rules)", "Only use this when writing and testing your own rules.", ruleId: "collector.rulepack-unsigned");

        var result = new Scanner(CheckCatalog.All()).Run(ctx, meta, (name, i, n) => { Log($"Check {i}/{n}: {name}"); req.Progress?.Invoke(name, i, n); }, req.Cancellation, req.CheckFinished, req.CheckStarted);
        foreach (var t in result.Timings) Log($"Timing {t.Key}: {t.Value} ms");
        var (html, json) = ReportWriter.Write(result, outDir);
        Log($"Report written: {html}");
        return new ScanOutcome(result, html, json, outDir, meta.RulePackVersion);
    }
}
