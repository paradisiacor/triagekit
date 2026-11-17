using System.Diagnostics;
using TriageKit.Core.Intel;
using TriageKit.Core.Rules;

namespace TriageKit.Core.Engine;

public sealed class ScanOptions
{
    public bool Quick { get; set; }
    public bool Elevated { get; set; }
    public string OutputDirectory { get; set; } = "";
    public string ToolsDirectory { get; set; } = "";
    public string? VirusTotalApiKey { get; set; }
    public int VirusTotalMaxLookups { get; set; } = 40;
    public int VirusTotalDelaySeconds { get; set; } = 16;
    public int EventLogDays { get; set; } = 30;
    public int RecentFileDays { get; set; } = 14;
    public int RecentFileMaxItems { get; set; } = 400;
    public bool RunDefenderQuickScan { get; set; } = true;
    public bool RunAutoruns { get; set; } = true;
    // Reputation (v0.3): key-free sources on by default, keyed sources only with the user's own key.
    public int ReputationMaxFiles { get; set; } = 60;
    public bool ReputationDefender { get; set; } = true;
    public bool ReputationCircl { get; set; } = true;
    public string? MalwareBazaarAuthKey { get; set; }
    // YARA (v0.3)
    public bool RunYara { get; set; } = true;
    public string RulesDirectory { get; set; } = "";
    /// <summary>True only when the external rule pack's signature verified (or the user explicitly allowed unsigned rules).</summary>
    public bool ExternalRulesTrusted { get; set; }
    public TimeSpan CheckTimeout { get; set; } = TimeSpan.FromMinutes(10);
    /// <summary>Deep scan: whole-drive malware rules and other opt-in, slower checks.</summary>
    public bool Deep { get; set; }
    /// <summary>Modules to run. The standard scan is just "security"; add-ons are opt-in.</summary>
    public HashSet<string> Modules { get; set; } = new(StringComparer.OrdinalIgnoreCase) { "security" };
    /// <summary>How many independent collectors may run at the same time.</summary>
    public int Parallelism { get; set; } = 3;
    /// <summary>Time budget for matching one file against all malware rules.</summary>
    public TimeSpan RuleBudgetPerFile { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Persistent cache of file hashes/signatures between scans (null = no cache).</summary>
    public string? FileCachePath { get; set; }
    /// <summary>Accepted findings and exclusions chosen by the user.</summary>
    public SuppressionSet Suppressions { get; set; } = new();
    /// <summary>Look inside ZIP archives and Office documents, and read shortcut (.lnk) targets.</summary>
    public bool ScanArchives { get; set; } = true;
}

/// <summary>Shared state handed to every check.</summary>
public sealed class CheckContext
{
    private readonly List<Finding> _findings = new();
    private readonly object _lock = new();

    public CheckContext(ScanOptions options, Indicators indicators, FileIntelService files, Action<string>? log = null)
    {
        Options = options; Indicators = indicators; Files = files; Log = log ?? (_ => { });
    }

    public ScanOptions Options { get; }
    public Indicators Indicators { get; }
    public FileIntelService Files { get; }
    /// <summary>Files already scanned with malware rules in this run (so the deep sweep doesn't repeat them).</summary>
    public HashSet<string> RuleScanned { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Action<string> Log { get; }

    // Each check runs on its own task (several at once), so its cancellation token and notes are per task.
    private static readonly AsyncLocal<CancellationToken> _token = new();
    private static readonly AsyncLocal<List<string>?> _notes = new();
    private static readonly AsyncLocal<List<string>?> _minor = new();
    private static readonly AsyncLocal<string?> _module = new();
    internal static readonly AsyncLocal<CheckContext?> CurrentContext = new();
    public CancellationToken Cancellation { get => _token.Value; internal set => _token.Value = value; }

    /// <summary>Records that part of a check could not be read (it must not look "clean" when it actually failed).</summary>
    public static void Note(string what, Exception? ex = null)
    {
        var list = _notes.Value;
        if (list is null) return;
        var text = ex is null ? what : $"{what}: {ex.GetType().Name} {ex.Message}".Trim();
        lock (list) if (list.Count < 20 && !list.Contains(text)) list.Add(text);
    }
    /// <summary>
    /// Records a small, expected gap that doesn't make the result untrustworthy: a cap on how many files were
    /// examined, one damaged archive, an optional helper tool that didn't answer. Listed for the user, but it does
    /// not turn a clean result into "Incomplete check".
    /// </summary>
    public static void Minor(string what, Exception? ex = null)
    {
        var list = _minor.Value;
        if (list is null) return;
        var text = ex is null ? what : $"{what}: {ex.GetType().Name} {ex.Message}".Trim();
        lock (list) if (list.Count < 20 && !list.Contains(text)) list.Add(text);
    }
    internal static void SetModule(string? module) => _module.Value = module;
    internal static void BeginNotes(List<string> list, List<string>? minor = null, string? module = null) { _notes.Value = list; _minor.Value = minor; _module.Value = module; }

    /// <summary>True when the user excluded this path from scanning.</summary>
    public bool IsExcluded(string? path) => path is not null && Options.Suppressions.ExcludesPath(path);

    public void Add(Severity severity, string category, string title, string detail = "", string recommendation = "",
                    object? evidence = null, string? mitre = null, string? ruleId = null)
    {
        var f = new Finding { Severity = severity, Category = category, Title = title, Detail = detail,
                              Recommendation = recommendation, Evidence = evidence, Mitre = mitre, RuleId = ruleId, Module = _module.Value };
        lock (_lock) _findings.Add(f);
    }

    public IReadOnlyList<Finding> Findings { get { lock (_lock) return _findings.ToList(); } }
}

/// <summary>A unit of collection + analysis. Must be read-only with respect to the inspected machine.</summary>
public interface ICheck
{
    /// <summary>Display name; also the key under which data is stored in results.json.</summary>
    string Name { get; }
    /// <summary>Slow checks are skipped in quick mode.</summary>
    bool IsSlow => false;
    /// <summary>Which module the check belongs to: "security" (the standard scan) or an add-on such as "doctor" / "gaming".</summary>
    string Module => "security";
    /// <summary>Only runs in a deep scan (user opted in).</summary>
    bool DeepOnly => false;
    /// <summary>Checks that depend on the results of others (e.g. VirusTotal) run last.</summary>
    int Order => 0;
    object? Run(CheckContext ctx);
}

public sealed class Scanner
{
    private readonly IReadOnlyList<ICheck> _checks;
    public Scanner(IEnumerable<ICheck> checks) => _checks = checks.OrderBy(c => c.Order).ToList();

    /// <param name="progress">Called when a check finishes: its name, how many have finished, how many there are, and how long it took (ms).</param>
    public ScanResult Run(CheckContext ctx, ScanMeta meta, Action<string, int, int>? progress = null, CancellationToken stop = default, Action<CheckOutcome>? finished = null, Action<string>? starting = null)
    {
        var started = DateTime.Now;
        meta.Started = started.ToString("yyyy-MM-dd HH:mm:ss");
        var result = new ScanResult { Meta = meta };
        var toRun = _checks.Where(c => ctx.Options.Modules.Contains(c.Module) && !(ctx.Options.Quick && c.IsSlow) && (ctx.Options.Deep || !c.DeepOnly)).ToList();
        if (ctx.Options.FileCachePath is not null) ctx.Files.LoadCache(ctx.Options.FileCachePath);
        int done = 0;
        var notes = new System.Collections.Concurrent.ConcurrentDictionary<string, List<string>>();
        var minors = new System.Collections.Concurrent.ConcurrentDictionary<string, List<string>>();
        var moduleOf = toRun.ToDictionary(c => c.Name, c => c.Module);

        void RunOne(ICheck check)
        {
            CheckContext.SetModule(check.Module);   // so timeout/failure notices are attributed to the check's module
            starting?.Invoke(check.Name);
            if (stop.IsCancellationRequested) return;
            var sw = Stopwatch.StartNew();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(stop);
            // No CancelAfter: the token is cancelled only once we have declared the timeout, so a check that stops on it is still reported as timed out.
            var myNotes = notes.GetOrAdd(check.Name, _ => new List<string>());
            var myMinor = minors.GetOrAdd(check.Name, _ => new List<string>());
            object? data;
            try
            {
                // Own task per check, so a hung WMI/COM call can't stall the scan. The token and the notes list are
                // set inside the task (async-local), so checks running side by side don't share them.
                var task = Task.Factory.StartNew(() =>
                {
                    // Invariant culture: titles and numbers must not change with the user's regional format
                    // (they are part of a finding's identity) and must read the same in GUI and service runs.
                    Thread.CurrentThread.CurrentCulture = System.Globalization.CultureInfo.InvariantCulture;
                    ctx.Cancellation = cts.Token; CheckContext.BeginNotes(myNotes, myMinor, check.Module); CheckContext.CurrentContext.Value = ctx;
                    return check.Run(ctx);
                },
                                                 cts.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);   // own thread: checks block on WMI/COM
                if (WaitOrStop(task, ctx.Options.CheckTimeout, stop)) data = task.Result;
                else if (stop.IsCancellationRequested) data = new { Error = "Stopped by user" };
                else
                {
                    cts.Cancel();   // tell the check to stop; well-behaved loops exit at their next item
                    data = new { Error = "Timed out" };
                    ctx.Add(Severity.Info, "Collector", $"Check timed out: {check.Name}", $"Stopped after {ctx.Options.CheckTimeout.TotalMinutes} minutes. Its results are incomplete.", ruleId: "collector.timeout");
                }
            }
            catch (Exception ex)
            {
                var inner = ex is AggregateException ae ? ae.Flatten().InnerException ?? ex : ex;
                data = inner is OperationCanceledException ? new { Error = "Stopped" } : new { Error = inner.Message };
                if (inner is not OperationCanceledException)
                    ctx.Add(Severity.Info, "Collector", $"Check could not complete: {check.Name}", inner.Message, "Results from this check are missing. Re-run as administrator, or report this if it keeps happening.", ruleId: "collector.failed");
            }
            lock (result) { result.Data[check.Name] = data; result.Timings[check.Name] = sw.ElapsedMilliseconds; }
            var n = Interlocked.Increment(ref done);
            finished?.Invoke(CheckOutcome.From(check.Name, sw.ElapsedMilliseconds, data));
            progress?.Invoke(check.Name, n, toRun.Count);
        }

        // Checks with the same Order are independent collectors and run a few at a time; later groups (malware
        // rules, reputation) depend on what the earlier ones found and run after them.
        foreach (var group in toRun.GroupBy(c => c.Order).OrderBy(g => g.Key))
        {
            if (stop.IsCancellationRequested) break;
            var list = group.ToList();
            if (list.Count == 1 || ctx.Options.Parallelism <= 1) foreach (var c in list) { if (stop.IsCancellationRequested) break; RunOne(c); }
            else
            {
                try { Parallel.ForEach(list, new ParallelOptions { MaxDegreeOfParallelism = ctx.Options.Parallelism, CancellationToken = stop }, RunOne); }
                catch (OperationCanceledException) { }
            }
        }
        if (stop.IsCancellationRequested)
        {
            var skipped = toRun.Where(c => !result.Data.ContainsKey(c.Name)).Select(c => c.Name).ToList();
            ctx.Add(Severity.Info, "Collector", "Scan stopped before it finished", skipped.Count > 0 ? $"Stopped by the user before: {string.Join(", ", skipped)}." : "Stopped by the user.",
                    "Run a full scan again for complete results.", ruleId: "collector.stopped");
        }
        // Material gaps (a security check couldn't read its data) block a clean verdict. Add-on modules (PC Doctor,
        // gaming) and minor gaps are listed too, but never change the security verdict.
        bool IsSecurity(string name) => moduleOf.TryGetValue(name, out var m) && string.Equals(m, "security", StringComparison.OrdinalIgnoreCase);
        var partial = notes.Where(kv => kv.Value.Count > 0 && IsSecurity(kv.Key)).OrderBy(kv => kv.Key).ToList();
        var minor = notes.Where(kv => kv.Value.Count > 0 && !IsSecurity(kv.Key))
            .Concat(minors.Where(kv => kv.Value.Count > 0))
            .GroupBy(kv => kv.Key).Select(g => new KeyValuePair<string, List<string>>(g.Key, g.SelectMany(kv => kv.Value).Distinct().ToList()))
            .OrderBy(kv => kv.Key).ToList();
        static string Lines(IEnumerable<KeyValuePair<string, List<string>>> l) =>
            string.Join("\n", l.Select(kv => $"{kv.Key}: {string.Join("; ", kv.Value.Take(3))}{(kv.Value.Count > 3 ? $" (+{kv.Value.Count - 3} more)" : "")}"));
        if (partial.Count > 0)
            ctx.Add(Severity.Info, "Collector", $"Some data couldn't be read ({partial.Count} check(s))", Lines(partial),
                "These parts were not checked, so a clean result there isn't proof. Running as administrator usually helps.", ruleId: "collector.partial");
        if (minor.Count > 0)
            ctx.Add(Severity.Info, "Collector", "Some optional details were skipped", Lines(minor),
                "This doesn't affect the security result. It lists limits that were reached and optional sources that didn't answer.", ruleId: "collector.minor");
        if (partial.Count + minor.Count > 0)
            result.Diagnostics = partial.Concat(minor).GroupBy(kv => kv.Key).ToDictionary(g => g.Key, g => g.SelectMany(kv => kv.Value).ToList());
        if (!ctx.Options.Elevated)
            ctx.Add(Severity.Info, "Collector", "Scan ran without administrator rights", "Some data could not be collected.",
                    "Re-run as administrator for complete results.", ruleId: "collector.not-admin");
        if (ctx.Options.FileCachePath is not null) ctx.Files.SaveCache(ctx.Options.FileCachePath);

        result.Stopped = stop.IsCancellationRequested;
        // Order data by the catalogue order so results.json stays stable even though checks ran in parallel.
        result.Data = toRun.Where(c => result.Data.ContainsKey(c.Name)).ToDictionary(c => c.Name, c => result.Data[c.Name]);
        var applied = ctx.Options.Suppressions.Apply(ctx.Findings);
        int acceptedNow = applied.Count(f => f.Accepted);
        if (acceptedNow > 0)
            // The accept list lives in a file; something else could have written it. Always say how much it hid.
            applied.Add(new Finding { Severity = Severity.Info, Category = "Collector", Title = $"{acceptedNow} finding(s) hidden by your accept list",
                Detail = string.Join("\n", applied.Where(f => f.Accepted).Take(15).Select(f => $"{f.Severity}: {f.Title} ({f.AcceptedReason})")),
                Recommendation = "If you don't remember accepting these, review Settings > Accepted & excluded.", RuleId = "collector.accepted" });
        result.Findings = applied.OrderBy(f => f.Accepted).ThenBy(f => f.Severity).ThenBy(f => f.Category).ThenBy(f => f.Title).ToList();
        // The security score only counts security findings when the security module ran; PC Doctor and gaming
        // findings have their own pages and must not turn a clean security result amber (or the other way round).
        bool securityRun = ctx.Options.Modules.Contains("security");
        var (score, verdict) = Scoring.Calculate(securityRun ? result.Findings.Where(f => f.Module is null || f.Module.Equals("security", StringComparison.OrdinalIgnoreCase)) : result.Findings);
        result.Score = score; result.Verdict = verdict;
        result.Highlights = Highlights.Build(result.Findings);
        foreach (Severity s in Enum.GetValues<Severity>()) result.Counts[s.ToString()] = result.Findings.Count(f => f.Severity == s && !f.Accepted);
        result.Counts["Accepted"] = result.Findings.Count(f => f.Accepted);
        meta.DurationSeconds = (int)(DateTime.Now - started).TotalSeconds;
        return result;
    }
    private static bool WaitOrStop(Task task, TimeSpan timeout, CancellationToken stop)
    {
        try { return task.Wait((int)timeout.TotalMilliseconds, stop); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { return false; }
    }
}

/// <summary>
/// Score 0-100. Repeats of the same rule count once, and each extra distinct issue of a severity adds less than the
/// first (diminishing returns, capped per severity), so 7 browser add-ons don't outweigh one real problem.
/// Any Critical caps the score at 25, any High at 70.
/// </summary>
public static class Scoring
{
    public static readonly IReadOnlyDictionary<Severity, double> Weights = new Dictionary<Severity, double>
    { [Severity.Critical] = 40, [Severity.High] = 15, [Severity.Medium] = 5, [Severity.Low] = 1.5, [Severity.Info] = 0 };
    public static readonly IReadOnlyDictionary<Severity, double> Caps = new Dictionary<Severity, double>
    { [Severity.Critical] = 100, [Severity.High] = 45, [Severity.Medium] = 30, [Severity.Low] = 10, [Severity.Info] = 0 };
    public const double Extra = 0.5;   // each further distinct issue of the same severity adds half the base weight

    /// <summary>Findings that mean part of the check didn't run or couldn't read its data.</summary>
    public static readonly HashSet<string> CoverageGaps = new(StringComparer.OrdinalIgnoreCase)
        { "collector.failed", "collector.timeout", "collector.stopped", "collector.partial", "collector.not-admin", "collector.disabled", "yara.incomplete" };

    public static string GroupKey(Finding f) => string.IsNullOrEmpty(f.RuleId) ? $"t:{f.Title}" : f.RuleId!;

    public static (int Score, string Verdict) Calculate(IEnumerable<Finding> findings)
    {
        var list = findings.Where(f => !f.Accepted).ToList();
        double penalty = 0;
        foreach (var bySev in list.GroupBy(f => f.Severity))
        {
            int distinct = bySev.Select(GroupKey).Distinct().Count();
            if (distinct == 0) continue;
            penalty += Math.Min(Caps[bySev.Key], Weights[bySev.Key] * (1 + Extra * (distinct - 1)));
        }
        int score = (int)Math.Round(Math.Clamp(100 - penalty, 0, 100));
        bool crit = list.Any(f => f.Severity == Severity.Critical);
        bool high = list.Any(f => f.Severity == Severity.High);
        if (crit) score = Math.Min(score, 25); else if (high) score = Math.Min(score, 70);
        // Something worth fixing (Medium) is never "Looks clean", however few points it costs.
        else if (list.Any(f => f.Severity == Severity.Medium)) score = Math.Min(score, 84);
        string verdict = crit ? "Likely compromised" : score < 60 ? "At risk" : score < 85 ? "Needs attention" : "Looks clean";
        // Never show a green all-clear when parts of the check didn't run: say so instead.
        if (verdict == "Looks clean" && list.Any(f => f.RuleId is not null && CoverageGaps.Contains(f.RuleId)))
        {
            verdict = "Incomplete check";
            score = Math.Min(score, 84);
        }
        return (score, verdict);
    }
}

/// <summary>A short, ranked list of what matters most; repeats of one rule folded into one line.</summary>
public sealed record Highlight(Severity Severity, string Category, string Title, string Recommendation, int Count, string? RuleId, string? Mitre);

public static class Highlights
{
    public static List<Highlight> Build(IEnumerable<Finding> findings, int max = 5) =>
        findings.Where(f => f.Severity <= Severity.Medium && !f.Accepted)
            .GroupBy(Scoring.GroupKey)
            .Select(g =>
            {
                var top = g.OrderBy(f => f.Severity).First();
                int n = g.Count();
                var title = n == 1 ? top.Title : $"{top.Title} (+{n - 1} similar)";
                return new Highlight(top.Severity, top.Category, title, top.Recommendation, n, top.RuleId, top.Mitre);
            })
            .OrderBy(h => h.Severity).ThenByDescending(h => h.Count)
            .Take(max).ToList();
}

/// <summary>How a check ended, for the live scan screen: "ok", "skipped" (it chose not to run: switched off or a
/// required tool is missing) or "failed" (error, timeout, stopped). A skipped or failed check must never look checked.</summary>
public sealed record CheckOutcome(string Name, long Ms, string State, string? Note)
{
    public static CheckOutcome From(string name, long ms, object? data)
    {
        if (data is null) return new(name, ms, "ok", null);
        var t = data.GetType();
        if (t.GetProperty("Error")?.GetValue(data) is string err) return new(name, ms, "failed", err);
        if (t.GetProperty("Ran")?.GetValue(data) is false)
            return new(name, ms, "skipped", t.GetProperty("Reason")?.GetValue(data) as string);
        return new(name, ms, "ok", null);
    }
}
