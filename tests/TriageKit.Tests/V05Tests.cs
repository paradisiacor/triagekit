using TriageKit.Core.Agent;
using TriageKit.Core.Engine;
using TriageKit.Core.Rules;
using Xunit;

namespace TriageKit.Tests;

public class FingerprintAndDiffTests
{
    private static Finding F(Severity s, string title, string? rule = "r") => new() { Severity = s, Category = "C", Title = title, RuleId = rule };

    [Fact]
    public void FingerprintIgnoresVolatileParts()
    {
        Assert.Equal(FindingFingerprint.Of(F(Severity.High, "Suspicious script command running (PID 4412)")),
                     FindingFingerprint.Of(F(Severity.High, "Suspicious script command running (PID 980)")));
        Assert.Equal(FindingFingerprint.Of(F(Severity.High, "An event log was cleared (Security) at 2026-11-01T10:00:00")),
                     FindingFingerprint.Of(F(Severity.High, "An event log was cleared (Security) at 2026-11-09T22:15:03")));
        Assert.NotEqual(FindingFingerprint.Of(F(Severity.High, "Risky service: A")), FindingFingerprint.Of(F(Severity.High, "Risky service: B")));
    }

    [Fact]
    public void DiffFindsNewResolvedAndPersisting()
    {
        var prev = FindingDiff.ToRecords(new[] { F(Severity.High, "Old problem"), F(Severity.Low, "Stays"), F(Severity.Info, "Info only") });
        var cur = FindingDiff.ToRecords(new[] { F(Severity.Low, "Stays"), F(Severity.Critical, "Brand new"), F(Severity.Info, "Another info") });
        var d = FindingDiff.Compare(prev, cur);
        Assert.Equal(new[] { "Brand new" }, d.New.Select(f => f.Title));
        Assert.Equal(new[] { "Old problem" }, d.Resolved.Select(f => f.Title));
        Assert.Equal(new[] { "Stays" }, d.Persisting.Select(f => f.Title));
        Assert.Single(d.Alertable);               // Info findings never alert
    }

    [Fact]
    public void FirstScanTreatsEverythingAsNew() => Assert.Single(FindingDiff.Compare(null, FindingDiff.ToRecords(new[] { F(Severity.Medium, "x") })).New);
}

public class HistoryStoreTests
{
    private static ScanResult Scan(int score, bool quick, params Finding[] findings)
    {
        var r = new ScanResult { Meta = new ScanMeta { Quick = quick }, Score = score, Verdict = score > 80 ? "Looks clean" : "At risk" };
        r.Findings.AddRange(findings);
        foreach (Severity s in Enum.GetValues<Severity>()) r.Counts[s.ToString()] = findings.Count(f => f.Severity == s);
        return r;
    }
    private static Finding F(Severity s, string t) => new() { Severity = s, Category = "C", Title = t, RuleId = "r", Recommendation = "fix it" };

    [Fact]
    public void RecordsScansComputesDiffAndPrunes()
    {
        var path = Path.Combine(Path.GetTempPath(), "tk-hist-" + Guid.NewGuid() + ".db");
        try
        {
            using (var h = new HistoryStore(path))
            {
                var (_, d1) = h.Record(Scan(60, false, F(Severity.High, "A"), F(Severity.Medium, "B")), "C:\\r1\\report.html", new DateTime(2026, 11, 1));
                Assert.Equal(2, d1.New.Count);
                var (_, d2) = h.Record(Scan(85, false, F(Severity.Medium, "B"), F(Severity.Low, "C")), "C:\\r2\\report.html", new DateTime(2026, 11, 2));
                Assert.Equal(new[] { "C" }, d2.New.Select(x => x.Title));
                Assert.Equal(new[] { "A" }, d2.Resolved.Select(x => x.Title));
                // Quick scans compare only against... the latest scan of any kind; full scans against the last full scan.
                var (_, d3) = h.Record(Scan(85, true, F(Severity.Medium, "B")), null, new DateTime(2026, 11, 3));
                Assert.Empty(d3.New);
                var scans = h.Scans();
                Assert.Equal(3, scans.Count);
                Assert.Equal(85, scans[0].Score);
                Assert.Equal(1, scans[1].NewCount);
                Assert.Equal(1, scans[1].ResolvedCount);
                h.SetMeta("installed", "2026-11-01");
                var removed = h.Prune(2);
                Assert.Single(removed);
                Assert.Equal(2, h.Scans().Count);
            }
            using var reopened = new HistoryStore(path);
            Assert.Equal("2026-11-01", reopened.GetMeta("installed"));
        }
        finally { foreach (var f in new[] { path, path + "-wal", path + "-shm" }) if (File.Exists(f)) File.Delete(f); }
    }

    [Fact]
    public void HistoryReportEncodesUntrustedText()
    {
        var scans = new List<ScanSummary>
        {
            new(2, new DateTime(2026, 11, 2), 70, "Needs attention", new() { ["High"] = 1 }, null, false, 1, 0),
            new(1, new DateTime(2026, 11, 1), 90, "Looks clean", new(), null, false, 0, 0),
        };
        var diff = new ScanDiff();
        diff.New.Add(new FindingRecord("x", Severity.High, "Browser", "Extension <script>alert(1)</script>", "r", "Remove it"));
        var html = HistoryReport.Render("PC<1>", scans, diff);
        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("PC&lt;1&gt;", html);
        Assert.Contains("<polyline", html);       // trend drawn with 2+ scans
    }
}

public class ScheduleTests
{
    private static readonly TimeSpan Delay = TimeSpan.FromMinutes(5);

    [Fact] public void NoPreviousScanCatchesUpSoon() => Assert.Equal(new DateTime(2026, 11, 14, 9, 5, 0), Schedule.NextRun(new DateTime(2026, 11, 14, 9, 0, 0), null, "12:30", Delay));
    [Fact] public void StaleScanCatchesUp() => Assert.Equal(new DateTime(2026, 11, 14, 9, 5, 0), Schedule.NextRun(new DateTime(2026, 11, 14, 9, 0, 0), new DateTime(2026, 11, 12, 12, 30, 0), "12:30", Delay));
    [Fact] public void BeforeTodaysSlot() => Assert.Equal(new DateTime(2026, 11, 14, 12, 30, 0), Schedule.NextRun(new DateTime(2026, 11, 14, 9, 0, 0), new DateTime(2026, 11, 13, 12, 31, 0), "12:30", Delay));
    [Fact] public void AfterTodaysSlotWaitsForTomorrow() => Assert.Equal(new DateTime(2026, 11, 15, 12, 30, 0), Schedule.NextRun(new DateTime(2026, 11, 14, 15, 0, 0), new DateTime(2026, 11, 14, 12, 31, 0), "12:30", Delay));
    [Fact] public void InvalidTimeFallsBackToDefault() => Assert.Equal(new DateTime(2026, 11, 14, 12, 30, 0), Schedule.NextRun(new DateTime(2026, 11, 14, 9, 0, 0), new DateTime(2026, 11, 13, 13, 0, 0), "25:99", Delay));
}
