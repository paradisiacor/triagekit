using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using TriageKit.Core.Engine;

namespace TriageKit.Core.Agent;

/// <summary>Stable identity of a finding across scans, so we can tell "new" from "still there" from "fixed".</summary>
public static class FindingFingerprint
{
    // Volatile parts of titles that change between scans without the issue changing (times, PIDs, counts).
    private static readonly Regex Volatile = new(@"(\bat \d{4}-\d{2}-\d{2}T[\d:]+|\(PID \d+\)|\b\d+ (failed sign-in attempts|unsigned program\(s\)|script file\(s\)|antivirus engines)\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MeasuredNumber = new(@"\d+(?:[.,]\d+)?", RegexOptions.Compiled);

    // Rules whose titles contain measurements. Not perf.cpu-hog: its title is a program name ("xmrig64 uses...").
    private static bool Measured(string? id) => id is not null && id != "perf.cpu-hog" &&
        (id.StartsWith("perf.", StringComparison.OrdinalIgnoreCase) || id.StartsWith("stability.", StringComparison.OrdinalIgnoreCase));

    public static string Of(Finding f)
    {
        var title = Volatile.Replace(f.Title, m => Regex.Replace(m.Value, @"\d+", "#"));
        var basis = $"{f.RuleId ?? f.Category}|{title.Trim().ToLowerInvariant()}";
        if (Measured(f.RuleId))
        {
            // PC Doctor titles carry measurements ("reached 95 °C", "x8 of x16", "runs at 60 Hz"). Those numbers
            // change between runs without the issue changing, so they don't count for identity, and "This is fine"
            // keeps working. What it is about (the part after the last ": ", such as a disk or app name) keeps its
            // digits, and the severity is part of the identity, so a much worse reading is a new finding again.
            int cut = title.LastIndexOf(": ", StringComparison.Ordinal);
            var measured = cut < 0 ? title : title[..cut];
            var subject = cut < 0 ? "" : title[cut..];
            basis = $"{f.RuleId}|{MeasuredNumber.Replace(measured, "#").Trim().ToLowerInvariant()}{subject.ToLowerInvariant()}|{f.Severity}";
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(basis)))[..16];
    }
}

public sealed record FindingRecord(string Fingerprint, Severity Severity, string Category, string Title, string? RuleId, string Recommendation);

public sealed class ScanDiff
{
    public List<FindingRecord> New { get; } = new();
    public List<FindingRecord> Resolved { get; } = new();
    public List<FindingRecord> Persisting { get; } = new();
    /// <summary>False for the very first check: there was nothing to compare with, so "new" means "found".</summary>
    public bool HasPrevious { get; init; }
    /// <summary>New findings that deserve a user alert (Medium or worse).</summary>
    public IEnumerable<FindingRecord> Alertable => New.Where(f => f.Severity <= Severity.Medium);
}

public static class FindingDiff
{
    public static ScanDiff Compare(IEnumerable<FindingRecord>? previous, IEnumerable<FindingRecord> current)
    {
        var diff = new ScanDiff { HasPrevious = previous is not null };
        var prev = (previous ?? Enumerable.Empty<FindingRecord>()).Where(f => f.Severity != Severity.Info).GroupBy(f => f.Fingerprint).ToDictionary(g => g.Key, g => g.First());
        var cur = current.Where(f => f.Severity != Severity.Info).GroupBy(f => f.Fingerprint).ToDictionary(g => g.Key, g => g.First());
        foreach (var (fp, f) in cur) (prev.ContainsKey(fp) ? diff.Persisting : diff.New).Add(f);
        foreach (var (fp, f) in prev) if (!cur.ContainsKey(fp)) diff.Resolved.Add(f);
        foreach (var list in new[] { diff.New, diff.Resolved, diff.Persisting }) list.Sort((a, b) => a.Severity.CompareTo(b.Severity));
        return diff;
    }

    public static List<FindingRecord> ToRecords(IEnumerable<Finding> findings) =>
        findings.Where(f => !f.Accepted).Select(f => new FindingRecord(FindingFingerprint.Of(f), f.Severity, f.Category, f.Title, f.RuleId, f.Recommendation)).ToList();
}

public sealed record ScanSummary(long Id, DateTime Started, int Score, string Verdict, Dictionary<string, int> Counts, string? ReportPath, bool Quick,
                                 int NewCount, int ResolvedCount);

/// <summary>Local scan history in SQLite (installed edition).</summary>
public sealed class HistoryStore : IDisposable
{
    private readonly SqliteConnection _db;

    public HistoryStore(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
        _db.Open();
        Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
        Exec("""
            CREATE TABLE IF NOT EXISTS scans (
              id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL,
              counts TEXT NOT NULL, report_path TEXT, quick INTEGER NOT NULL DEFAULT 0, new_count INTEGER NOT NULL DEFAULT 0,
              resolved_count INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS findings (
              scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, severity TEXT NOT NULL,
              category TEXT NOT NULL, title TEXT NOT NULL, rule_id TEXT, recommendation TEXT, is_new INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            """);
        // 0.12.1 and earlier imported PC Doctor runs as if they were security checks. They are not; remove them.
        Exec("DELETE FROM scans WHERE instr(report_path, '_doctor' || char(92) || 'report.html') > 0 OR instr(report_path, '_doctor/report.html') > 0;");
    }

    private void Exec(string sql) { using var c = _db.CreateCommand(); c.CommandText = sql; c.ExecuteNonQuery(); }

    public string? GetMeta(string key)
    {
        using var c = _db.CreateCommand(); c.CommandText = "SELECT value FROM meta WHERE key=$k"; c.Parameters.AddWithValue("$k", key);
        return c.ExecuteScalar() as string;
    }

    public void SetMeta(string key, string value)
    {
        using var c = _db.CreateCommand();
        c.CommandText = "INSERT INTO meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
        c.Parameters.AddWithValue("$k", key); c.Parameters.AddWithValue("$v", value); c.ExecuteNonQuery();
    }

    /// <summary>Stores a scan, compares it with the previous full scan, and returns the diff.</summary>
    public (long ScanId, ScanDiff Diff) Record(ScanResult result, string? reportPath, DateTime? started = null)
    {
        var current = FindingDiff.ToRecords(result.Findings);
        var previous = LatestFindings(fullOnly: !result.Meta.Quick);
        var diff = FindingDiff.Compare(previous, current);
        var newSet = diff.HasPrevious ? diff.New.Select(f => f.Fingerprint).ToHashSet() : new HashSet<string>();

        using var tx = _db.BeginTransaction();
        long id;
        using (var c = _db.CreateCommand())
        {
            c.Transaction = tx;
            c.CommandText = "INSERT INTO scans(started,score,verdict,counts,report_path,quick,new_count,resolved_count) VALUES($s,$sc,$v,$c,$r,$q,$n,$rs); SELECT last_insert_rowid();";
            c.Parameters.AddWithValue("$s", (started ?? DateTime.Now).ToString("s"));
            c.Parameters.AddWithValue("$sc", result.Score);
            c.Parameters.AddWithValue("$v", result.Verdict);
            c.Parameters.AddWithValue("$c", JsonSerializer.Serialize(result.Counts));
            c.Parameters.AddWithValue("$r", (object?)reportPath ?? DBNull.Value);
            c.Parameters.AddWithValue("$q", result.Meta.Quick ? 1 : 0);
            c.Parameters.AddWithValue("$n", diff.HasPrevious ? diff.New.Count : 0);
            c.Parameters.AddWithValue("$rs", diff.Resolved.Count);
            id = (long)c.ExecuteScalar()!;
        }
        foreach (var f in current)
        {
            using var c = _db.CreateCommand(); c.Transaction = tx;
            c.CommandText = "INSERT INTO findings(scan_id,fingerprint,severity,category,title,rule_id,recommendation,is_new) VALUES($i,$f,$s,$c,$t,$r,$rec,$n)";
            c.Parameters.AddWithValue("$i", id); c.Parameters.AddWithValue("$f", f.Fingerprint); c.Parameters.AddWithValue("$s", f.Severity.ToString());
            c.Parameters.AddWithValue("$c", f.Category); c.Parameters.AddWithValue("$t", f.Title); c.Parameters.AddWithValue("$r", (object?)f.RuleId ?? DBNull.Value);
            c.Parameters.AddWithValue("$rec", f.Recommendation); c.Parameters.AddWithValue("$n", newSet.Contains(f.Fingerprint) ? 1 : 0);
            c.ExecuteNonQuery();
        }
        tx.Commit();
        return (id, diff);
    }

    public List<FindingRecord>? LatestFindings(bool fullOnly)
    {
        using var c = _db.CreateCommand();
        c.CommandText = fullOnly ? "SELECT id FROM scans WHERE quick=0 ORDER BY id DESC LIMIT 1" : "SELECT id FROM scans ORDER BY id DESC LIMIT 1";
        if (c.ExecuteScalar() is not long id) return null;
        return FindingsOf(id);
    }

    public List<FindingRecord> FindingsOf(long scanId)
    {
        var list = new List<FindingRecord>();
        using var c = _db.CreateCommand();
        c.CommandText = "SELECT fingerprint,severity,category,title,rule_id,recommendation FROM findings WHERE scan_id=$i";
        c.Parameters.AddWithValue("$i", scanId);
        using var r = c.ExecuteReader();
        while (r.Read())
            list.Add(new FindingRecord(r.GetString(0), Enum.Parse<Severity>(r.GetString(1)), r.GetString(2), r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4), r.IsDBNull(5) ? "" : r.GetString(5)));
        return list;
    }

    public void UpdateScore(long id, int score, string verdict, Dictionary<string, int> counts)
    {
        using var c = _db.CreateCommand();
        c.CommandText = "UPDATE scans SET score=$sc, verdict=$v, counts=$c WHERE id=$i";
        c.Parameters.AddWithValue("$sc", score); c.Parameters.AddWithValue("$v", verdict);
        c.Parameters.AddWithValue("$c", JsonSerializer.Serialize(counts)); c.Parameters.AddWithValue("$i", id);
        c.ExecuteNonQuery();
    }

    public List<ScanSummary> Scans(int limit = 60)
    {
        var list = new List<ScanSummary>();
        using var c = _db.CreateCommand();
        c.CommandText = "SELECT id,started,score,verdict,counts,report_path,quick,new_count,resolved_count FROM scans ORDER BY id DESC LIMIT $l";
        c.Parameters.AddWithValue("$l", limit);
        using var r = c.ExecuteReader();
        while (r.Read())
            list.Add(new ScanSummary(r.GetInt64(0), DateTime.Parse(r.GetString(1)), r.GetInt32(2), r.GetString(3),
                JsonSerializer.Deserialize<Dictionary<string, int>>(r.GetString(4)) ?? new(), r.IsDBNull(5) ? null : r.GetString(5),
                r.GetInt32(6) == 1, r.GetInt32(7), r.GetInt32(8)));
        return list;
    }

    /// <summary>Deletes old scans beyond the retention count and returns their report folders for cleanup.</summary>
    public List<string> Prune(int keep)
    {
        var old = Scans(int.MaxValue).Skip(keep).ToList();
        foreach (var s in old) { using var c = _db.CreateCommand(); c.CommandText = "DELETE FROM scans WHERE id=$i"; c.Parameters.AddWithValue("$i", s.Id); c.ExecuteNonQuery(); }
        return old.Where(s => s.ReportPath is not null).Select(s => Path.GetDirectoryName(s.ReportPath!)!).ToList();
    }

    public void Dispose() => _db.Dispose();
}
