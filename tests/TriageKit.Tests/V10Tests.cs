using System.IO.Compression;
using System.Text;
using TriageKit.Core.Agent;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Yara;
using TriageKit.Core.Reporting;
using Xunit;

namespace TriageKit.Tests;

public class V10ScannerTests
{
    private sealed class Probe : ICheck
    {
        private readonly Func<CheckContext, object?> _run;
        public Probe(string n, Func<CheckContext, object?> run, int order = 0) { Name = n; _run = run; Order = order; }
        public string Name { get; }
        public int Order { get; }
        public object? Run(CheckContext ctx) => _run(ctx);
    }
    private static CheckContext Ctx(ScanOptions? o = null) => new(o ?? new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());

    [Fact]
    public void IndependentChecksRunSideBySideAndKeepCatalogueOrder()
    {
        var checks = Enumerable.Range(1, 6).Select(i => (ICheck)new Probe("c" + i, _ => { Thread.Sleep(300); return i; })).ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = new Scanner(checks).Run(Ctx(new ScanOptions { Parallelism = 3 }), new ScanMeta());
        Assert.True(sw.ElapsedMilliseconds < 1500, $"took {sw.ElapsedMilliseconds} ms");
        Assert.Equal(new[] { "c1", "c2", "c3", "c4", "c5", "c6" }, r.Data.Keys);
    }

    [Fact]
    public void EachCheckGetsItsOwnTokenAndLaterGroupsWait()
    {
        var order = new List<string>();
        var checks = new ICheck[]
        {
            new Probe("slow", ctx => { Thread.Sleep(200); lock (order) order.Add("slow"); return ctx.Cancellation.CanBeCanceled; }),
            new Probe("fast", ctx => { lock (order) order.Add("fast"); return ctx.Cancellation.CanBeCanceled; }),
            new Probe("late", ctx => { lock (order) order.Add("late"); return true; }, order: 50),
        };
        var r = new Scanner(checks).Run(Ctx(), new ScanMeta());
        Assert.Equal("late", order.Last());
        Assert.Equal(true, r.Data["slow"]); Assert.Equal(true, r.Data["fast"]);
    }

    [Fact]
    public void PartlyFailedChecksAreReportedNotShownAsClean()
    {
        var checks = new ICheck[] { new Probe("reader", _ => { CheckContext.Note("Event log 'Security' could not be read", new UnauthorizedAccessException("denied")); return 1; }) };
        var r = new Scanner(checks).Run(Ctx(), new ScanMeta());
        var f = Assert.Single(r.Findings, x => x.RuleId == "collector.partial");
        Assert.Contains("Security", f.Detail);
        Assert.Contains("reader", r.Diagnostics!.Keys);
    }

    [Fact]
    public void TimedOutCheckIsToldToStop()
    {
        bool sawCancel = false;
        var checks = new ICheck[] { new Probe("hang", ctx => { for (int i = 0; i < 100 && !ctx.Cancellation.IsCancellationRequested; i++) Thread.Sleep(20); sawCancel = ctx.Cancellation.IsCancellationRequested; return 0; }) };
        var r = new Scanner(checks).Run(Ctx(new ScanOptions { CheckTimeout = TimeSpan.FromMilliseconds(150) }), new ScanMeta());
        Thread.Sleep(200);
        Assert.Contains(r.Findings, f => f.RuleId == "collector.timeout");
        Assert.True(sawCancel);
    }
}

public class SuppressionTests
{
    private static Finding F(Severity s, string rule, string title, string detail = "") => new() { Severity = s, Category = "X", Title = title, RuleId = rule, Detail = detail };

    [Fact]
    public void AcceptedFindingsDontCountButStayVisible()
    {
        var mine = F(Severity.High, "defender.exclusion", "Defender exclusion: D:\\Games");
        var set = new SuppressionSet { Items = { new Suppression { Fingerprint = FindingFingerprint.Of(mine), Reason = "My games folder" } } };
        var applied = set.Apply(new[] { mine, F(Severity.Medium, "x.y", "Other") });
        var a = applied.Single(f => f.RuleId == "defender.exclusion");
        Assert.True(a.Accepted); Assert.Equal("My games folder", a.AcceptedReason);
        var (score, verdict) = Scoring.Calculate(applied);
        Assert.Equal(Scoring.Calculate(new[] { F(Severity.Medium, "x.y", "Other") }).Score, score);
        Assert.DoesNotContain(Highlights.Build(applied), h => h.RuleId == "defender.exclusion");
    }

    [Fact]
    public void WideExclusionsNeverHideCriticalFindings()
    {
        var set = new SuppressionSet { Items = { new Suppression { RuleId = "yara.*" }, new Suppression { Path = @"C:\Users\B\Tools" } } };
        var applied = set.Apply(new[]
        {
            F(Severity.Critical, "yara.stealer", "Stealer", @"C:\Users\B\Tools\x.exe"),
            F(Severity.High, "yara.generic", "Generic"),
            F(Severity.Medium, "persistence.run", "Run key", @"C:\Users\B\Tools\helper.exe"),
        });
        Assert.False(applied[0].Accepted);
        Assert.True(applied[1].Accepted);
        Assert.True(applied[2].Accepted);
        Assert.True(set.ExcludesPath(@"C:\Users\B\Tools\sub\a.exe") || !OperatingSystem.IsWindows());
    }

    [Fact]
    public void ExpiredAcceptanceComesBack()
    {
        var f = F(Severity.Low, "a.b", "Thing");
        var set = new SuppressionSet { Items = { new Suppression { RuleId = "a.b", Until = DateTime.UtcNow.AddDays(-1) } } };
        Assert.False(set.Apply(new[] { f })[0].Accepted);
    }

    [Fact]
    public void SaveAndLoadRoundTrip()
    {
        var path = Path.Combine(Path.GetTempPath(), "tk-supp-" + Guid.NewGuid().ToString("N") + ".json");
        new SuppressionSet { Items = { new Suppression { RuleId = "a.b", Title = "T", Reason = "R" } } }.Save(path);
        var back = SuppressionSet.Load(path);
        Assert.Equal("a.b", Assert.Single(back.Items).RuleId);
        File.WriteAllText(path, "{broken");
        Assert.Empty(SuppressionSet.Load(path).Items);
        File.Delete(path);
    }
}

public class ContainerTests
{
    private static List<YaraRule> Rules() => YaraParser.Parse("rule Evil { meta: description = \"Evil test\" severity = \"high\" strings: $a = \"evil-marker-123\" condition: $a }", "t").ToList();

    private static string TempZip(Action<ZipArchive> fill)
    {
        var path = Path.Combine(Path.GetTempPath(), "tk-" + Guid.NewGuid().ToString("N") + ".zip");
        using (var z = ZipFile.Open(path, ZipArchiveMode.Create)) fill(z);
        return path;
    }
    private static void Add(ZipArchive z, string name, byte[] data, CompressionLevel level = CompressionLevel.Optimal) { using var s = z.CreateEntry(name, level).Open(); s.Write(data); }

    [Fact]
    public void MalwareInsideZipAndNestedZipIsFound()
    {
        var innerMs = new MemoryStream();
        using (var inner = new ZipArchive(innerMs, ZipArchiveMode.Create, true)) Add(inner, "deep/run.js", Encoding.ASCII.GetBytes("var x='evil-marker-123';"));
        var path = TempZip(z => { Add(z, "readme.txt", Encoding.ASCII.GetBytes("hello evil-marker-123")); Add(z, "inner.zip", innerMs.ToArray()); });
        var ctx = new CheckContext(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());
        new YaraCheck(Rules(), new[] { path }).Run(ctx);
        var f = Assert.Single(ctx.Findings, x => x.RuleId == "yara.Evil");
        Assert.Contains("inner.zip » deep/run.js", f.Detail);   // .txt entries are not scanned, the nested script is
        File.Delete(path);
    }

    [Fact]
    public void ZipBombIsNotExpanded()
    {
        var path = TempZip(z => Add(z, "big.js", new byte[40 * 1024 * 1024]));
        var ctx = new CheckContext(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());
        new YaraCheck(Rules(), new[] { path }).Run(ctx);
        Assert.Contains(ctx.Findings, f => f.RuleId == "archive.unreadable");
        File.Delete(path);
    }

    [Fact]
    public void ExcludedPathsAreScannedButAccepted()
    {
        var path = TempZip(z => Add(z, "a.js", Encoding.ASCII.GetBytes("evil-marker-123")));
        var opts = new ScanOptions { Suppressions = new SuppressionSet { Items = { new Suppression { Path = Path.GetDirectoryName(path) } } } };
        var ctx = new CheckContext(opts, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());
        new YaraCheck(Rules(), new[] { path }).Run(ctx);
        // Excluded folders are still scanned; the accept list hides the (non-critical) result afterwards.
        var applied = opts.Suppressions.Apply(ctx.Findings);
        Assert.True(applied.Single(f => f.RuleId == "yara.Evil").Accepted);
        File.Delete(path);
    }

    [Fact]
    public void RuleBudgetStopsSlowFiles()
    {
        var scanner = new YaraScanner(Rules());
        scanner.Scan(Encoding.ASCII.GetBytes("evil-marker-123"), TimeSpan.Zero, default, out var incomplete);
        Assert.True(incomplete);
        Assert.Single(scanner.Scan(Encoding.ASCII.GetBytes("evil-marker-123"), TimeSpan.FromSeconds(5), default, out incomplete));
        Assert.False(incomplete);
    }

    [Fact]
    public void OvbaSpecExampleDecompresses()
    {
        // MS-OVBA 3.2.3 example
        var hex = "01 2F B0 00 23 61 61 61 62 63 64 65 82 66 00 70 61 67 68 69 6A 01 38 08 61 6B 6C 00 30 6D 6E 6F 70 06 71 02 70 04 10 72 73 74 75 76 10 77 78 79 7A 00 3C";
        var bytes = hex.Split(' ').Select(h => Convert.ToByte(h, 16)).ToArray();
        Assert.Equal("#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa", VbaMacros.Decompress(bytes, 0));
    }

    private static byte[] LiteralContainer(string text)
    {
        var body = new List<byte>();
        var src = Encoding.ASCII.GetBytes(text);
        for (int i = 0; i < src.Length; i += 8) { body.Add(0); body.AddRange(src.Skip(i).Take(8)); }
        int header = 0x8000 | (0b011 << 12) | (body.Count + 2 - 3);
        return new byte[] { 0x01, (byte)(header & 0xFF), (byte)(header >> 8) }.Concat(body).ToArray();
    }

    [Fact]
    public void MacroDocumentWithAutoOpenAndShellIsFlagged()
    {
        var vba = new byte[64].Concat(LiteralContainer("Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\nCreateObject(\"WScript.Shell\").Run \"powershell -enc AAAA\"\r\nEnd Sub\r\n")).Concat(new byte[32]).ToArray();
        var src = VbaMacros.ExtractSources(vba);
        Assert.Contains("Sub AutoOpen()", Assert.Single(src));
        var dir = Path.Combine(Path.GetTempPath(), "tk-" + Guid.NewGuid().ToString("N"), "Downloads");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "invoice.docm");
        using (var z = ZipFile.Open(path, ZipArchiveMode.Create)) { Add(z, "word/document.xml", Encoding.ASCII.GetBytes("<w/>")); Add(z, "word/vbaProject.bin", vba); }
        var ctx = new CheckContext(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());
        new YaraCheck(Rules(), new[] { path }).Run(ctx);
        var f = Assert.Single(ctx.Findings, x => x.RuleId == "office.macro-autoexec-suspicious");
        Assert.Equal(OperatingSystem.IsWindows() ? Severity.High : Severity.Medium, f.Severity);   // "\Downloads\" folder test needs Windows paths
        Assert.Contains("AutoOpen", f.Detail);
        Directory.Delete(Path.GetDirectoryName(dir)!, true);
    }

    [Fact]
    public void ShortcutWithHiddenPowerShellIsFlagged()
    {
        static byte[] Str(string s) => BitConverter.GetBytes((ushort)s.Length).Concat(Encoding.Unicode.GetBytes(s)).ToArray();
        var header = new byte[0x4C];
        BitConverter.GetBytes(0x4C).CopyTo(header, 0);
        BitConverter.GetBytes(0x8u | 0x20u | 0x80u).CopyTo(header, 0x14);   // relative path, arguments, unicode
        var lnk = header.Concat(Str(@"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")).Concat(Str("-w hidden -enc " + new string('A', 40))).ToArray();
        var info = Shortcut.Parse(lnk)!;
        Assert.EndsWith("powershell.exe", info.Target);
        Assert.NotNull(Shortcut.Assess(info));
        Assert.Null(Shortcut.Assess(new Shortcut.Info(@"C:\Program Files\App\app.exe", "--profile 2", null, null)));
    }
}

public class RedactorTests
{
    [Fact]
    public void ShareableReportHidesPersonalDetails()
    {
        var r = new ScanResult { Meta = new ScanMeta { ComputerName = "DESKTOP-SPOOKY", Operator = "WORKGROUP\\marko" }, Score = 60, Verdict = "At risk" };
        r.Findings.Add(new Finding { Severity = Severity.High, Category = "Persistence", Title = "Run key: updater", RuleId = "persistence.run",
            Detail = "C:\\Users\\marko\\AppData\\Roaming\\upd.exe connects to 203.0.113.9 from DESKTOP-SPOOKY; mail marko@example.com; SID S-1-5-21-1111-2222-3333-1001; MAC 00:1A:2B:3C:4D:5E; device TK-AAAA-BBBB-CCCC-DDDD",
            Evidence = new { Path = "C:\\Users\\marko\\AppData\\Roaming\\upd.exe", SerialNumber = "ABC123456" } });
        r.Data["Running processes"] = new[] { new { Name = "secret.exe" } };
        var red = Redactor.Redact(r);
        var json = TriageKit.Core.Reporting.ReportWriter.ToJson(red);
        foreach (var leak in new[] { "marko", "DESKTOP-SPOOKY", "203.0.113.9", "example.com", "1111-2222", "00:1A:2B", "TK-AAAA", "ABC123456", "secret.exe" })
            Assert.DoesNotContain(leak, json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("upd.exe", json);                 // still useful
        Assert.True(red.Meta.Redacted);
        Assert.Equal(Severity.High, red.Findings[0].Severity);
    }
}
