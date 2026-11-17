using System.Runtime.Versioning;
using System.Text.Json;
using TriageKit.Cli.Agent;
using TriageKit.Core.Agent;
using TriageKit.Core.Engine;
using TriageKit.Core.Reporting;

namespace TriageKit.Cli.Ui;

/// <summary>
/// Where the desktop app keeps reports and history: next to the exe for the portable edition, or the protected
/// ProgramData folder when running from the installed location.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class UiStore
{
    public required string ReportsDir { get; init; }
    public required string DbPath { get; init; }
    public required bool Installed { get; init; }
    public required string ConfigPath { get; init; }

    public static UiStore Detect()
    {
        var baseDir = AppContext.BaseDirectory;
        bool installed = string.Equals(Path.GetFullPath(baseDir).TrimEnd('\\'), Path.GetFullPath(AgentPaths.InstallDir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        return installed
            ? new UiStore { ReportsDir = AgentPaths.ReportsDir, DbPath = AgentPaths.HistoryDb, Installed = true, ConfigPath = Path.Combine(baseDir, "config.json") }
            : new UiStore { ReportsDir = Path.Combine(baseDir, "Reports"), DbPath = Path.Combine(baseDir, "Reports", "history.db"), Installed = false, ConfigPath = Path.Combine(baseDir, "config.json") };
    }

    public HistoryStore Open() { Directory.CreateDirectory(ReportsDir); return new HistoryStore(DbPath); }

    /// <summary>Adds report folders that exist on disk but are not in the history yet (e.g. scans made by older versions).</summary>
    public void ImportExisting()
    {
        if (!Directory.Exists(ReportsDir)) return;
        using var h = Open();
        var known = h.Scans(100000).Select(s => s.ReportPath).Where(p => p is not null).Select(p => Path.GetFullPath(p!)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in Directory.GetDirectories(ReportsDir).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
        {
            // PC Doctor runs have their own page; they are not security checks and must never appear as one.
            if (dir.EndsWith("_doctor", StringComparison.OrdinalIgnoreCase)) continue;
            var json = Path.Combine(dir, "results.json"); var html = Path.Combine(dir, "report.html");
            if (!File.Exists(json) || known.Contains(Path.GetFullPath(html))) continue;
            var r = Load(json);
            if (r is null) continue;
            // Re-score with the current rules so old and new scans are comparable.
            (r.Score, r.Verdict) = Scoring.Calculate(r.Findings);
            if (r.Highlights.Count == 0) r.Highlights = Highlights.Build(r.Findings);
            DateTime? started = DateTime.TryParse(r.Meta.Started, out var st) ? st : Directory.GetCreationTime(dir);
            h.Record(r, html, started);
        }
    }

    public static ScanResult? Load(string resultsJson)
    {
        try
        {
            var opts = new JsonSerializerOptions(ReportWriter.JsonOptions) { PropertyNameCaseInsensitive = true };
            var r = JsonSerializer.Deserialize<ScanResult>(File.ReadAllText(resultsJson), opts);
            if (r is null) return null;
            foreach (Severity s in Enum.GetValues<Severity>()) r.Counts[s.ToString()] = r.Findings.Count(f => f.Severity == s && !f.Accepted);
            return r;
        }
        catch { return null; }
    }

    /// <summary>Report folder of a scan, only if it lies inside our reports folder.</summary>
    public string? ReportDirOf(ScanSummary s)
    {
        if (s.ReportPath is null) return null;
        var dir = Path.GetDirectoryName(Path.GetFullPath(s.ReportPath));
        var root = Path.GetFullPath(ReportsDir).TrimEnd('\\') + "\\";
        return dir is not null && (dir + "\\").StartsWith(root, StringComparison.OrdinalIgnoreCase) && Directory.Exists(dir) ? dir : null;
    }
}
