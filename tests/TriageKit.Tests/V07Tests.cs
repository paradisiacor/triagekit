using System.Formats.Asn1;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using Xunit;

namespace TriageKit.Tests;

public class V07Tests
{
    [Fact]
    public void CtlWalkerFindsThumbprintsAtAnyDepth()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            w.WriteInteger(1);
            using (w.PushSequence())
            {
                using (w.PushSequence()) { w.WriteOctetString(Enumerable.Repeat((byte)0xAB, 20).ToArray()); using (w.PushSetOf()) { w.WriteOctetString(new byte[] { 1, 2, 3 }); } }
                using (w.PushSequence()) { w.WriteOctetString(Enumerable.Range(0, 20).Select(i => (byte)i).ToArray()); }
            }
            w.WriteOctetString(new byte[32]);   // a SHA-256 sized value must be ignored
        }
        var found = new List<string>();
        CertificateCheck.Walk(w.Encode(), found, 0);
        Assert.Equal(2, found.Count);
        Assert.Contains(new string('A', 0) + "ABABABABABABABABABABABABABABABABABABABAB", found);
        Assert.Contains("000102030405060708090A0B0C0D0E0F10111213", found);
    }

    [Fact]
    public void CtlWalkerSurvivesGarbage()
    {
        var found = new List<string>();
        CertificateCheck.Walk(new byte[] { 0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 }, found, 0);
        Assert.Empty(found);
    }

    [Fact]
    public void DeepOnlyChecksAreSkippedUnlessDeep()
    {
        var checks = new ICheck[] { new Probe("normal", false), new Probe("deep", true) };
        foreach (var deep in new[] { false, true })
        {
            var ctx = new CheckContext(new ScanOptions { Deep = deep }, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());
            var r = new Scanner(checks).Run(ctx, new ScanMeta());
            Assert.True(r.Data.ContainsKey("normal"));
            Assert.Equal(deep, r.Data.ContainsKey("deep"));
        }
    }

    [Fact]
    public void ScanCanBeStoppedBetweenChecks()
    {
        using var cts = new CancellationTokenSource();
        var checks = new ICheck[] { new Probe("a", false, () => cts.Cancel()), new Probe("b", false) };
        var ctx = new CheckContext(new ScanOptions { Parallelism = 1 }, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());
        var r = new Scanner(checks).Run(ctx, new ScanMeta(), null, cts.Token);
        Assert.True(r.Stopped);
        Assert.False(r.Data.ContainsKey("b"));
        Assert.Contains(r.Findings, f => f.RuleId == "collector.stopped");
    }

    [Fact]
    public void AddOnModulesOnlyRunWhenSelected()
    {
        var checks = new ICheck[] { new Probe("sec", false), new Probe("doc", false, null, "doctor") };
        var opts = new ScanOptions();
        var r1 = new Scanner(checks).Run(new CheckContext(opts, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService()), new ScanMeta());
        Assert.True(r1.Data.ContainsKey("sec")); Assert.False(r1.Data.ContainsKey("doc"));
        opts = new ScanOptions { Modules = new(StringComparer.OrdinalIgnoreCase) { "doctor" } };
        var r2 = new Scanner(checks).Run(new CheckContext(opts, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService()), new ScanMeta());
        Assert.False(r2.Data.ContainsKey("sec")); Assert.True(r2.Data.ContainsKey("doc"));
    }

    [Fact]
    public void DoctorChecksAreNotInTheStandardScan()
    {
        var mods = TriageKit.Core.Checks.CheckCatalog.All().ToDictionary(c => c.Name, c => c.Module);
        Assert.Equal("doctor", mods["Stability & crashes"]);
        Assert.Equal("doctor", mods["Gaming & performance"]);
        Assert.Equal("gaming", mods["Gamer account protection"]);
        Assert.Equal("security", mods["Drivers"]);
    }

    private sealed class Probe : ICheck
    {
        private readonly Action? _a; private readonly bool _deep; private readonly string _mod;
        public Probe(string n, bool deep, Action? a = null, string module = "security") { Name = n; _deep = deep; _a = a; _mod = module; }
        public string Name { get; }
        public string Module => _mod;
        public bool DeepOnly => _deep;
        public object? Run(CheckContext ctx) { _a?.Invoke(); return true; }
    }
}

public class CompressedRuleTests
{
    [Fact]
    public void CompressedBuiltInRulesMatchTheSource()
    {
        // rules-src/core.yar is the editable source; Resources/rules/core.yar.gz is what ships. Regenerate with:
        //   python3 -c "import gzip;open('src/TriageKit.Core/Resources/rules/core.yar.gz','wb').write(gzip.compress(open('rules-src/core.yar','rb').read(),mtime=0))"
        var root = AppContext.BaseDirectory;
        while (!File.Exists(Path.Combine(root, "TriageKit.sln"))) root = Path.GetDirectoryName(root)!;
        var source = File.ReadAllText(Path.Combine(root, "rules-src", "core.yar"));
        using var gz = new System.IO.Compression.GZipStream(File.OpenRead(Path.Combine(root, "src", "TriageKit.Core", "Resources", "rules", "core.yar.gz")), System.IO.Compression.CompressionMode.Decompress);
        Assert.Equal(source, new StreamReader(gz).ReadToEnd());
        Assert.True(TriageKit.Core.Yara.YaraRuleSet.LoadBuiltIn().Count >= 15);
    }
}
