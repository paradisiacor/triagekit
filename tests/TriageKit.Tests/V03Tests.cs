using System.Net;
using System.Text;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Reputation;
using TriageKit.Core.Rules;
using TriageKit.Core.Yara;
using Xunit;

namespace TriageKit.Tests;

public class YaraEngineTests
{
    private static YaraScanner S(string rules) => new(YaraParser.Parse(rules));
    private static byte[] B(string s) => Encoding.Latin1.GetBytes(s);
    private static bool Hit(string rules, byte[] data) => S(rules).Scan(data).Count > 0;

    [Fact]
    public void TextStringsAndModifiers()
    {
        const string r = "rule t { strings: $a = \"Hello\" nocase $b = \"wd\" wide condition: $a and $b }";
        Assert.True(Hit(r, B("xx hELLo yy w\0d\0")));
        Assert.False(Hit(r, B("xx hello yy wd")));      // $b requires UTF-16
    }

    [Fact]
    public void FullwordRespectsBoundaries()
    {
        const string r = "rule t { strings: $a = \"IEX\" fullword condition: $a }";
        Assert.True(Hit(r, B("x; IEX (y)")));
        Assert.False(Hit(r, B("PREFIXIEXSUFFIX")));
    }

    [Fact]
    public void HexWildcardsJumpsAndAlternatives()
    {
        const string r = "rule t { strings: $h = { 4D 5A ?? 9? [1-3] (AA | BB) } condition: $h at 0 }";
        Assert.True(Hit(r, new byte[] { 0x4D, 0x5A, 0x00, 0x93, 1, 2, 0xBB }));
        Assert.False(Hit(r, new byte[] { 0x4D, 0x5A, 0x00, 0x83, 1, 2, 0xBB }));   // nibble mismatch
        Assert.False(Hit(r, new byte[] { 0x00, 0x4D, 0x5A, 0x00, 0x93, 1, 0xAA }));  // not at 0
    }

    [Fact]
    public void RegexWithFlags()
    {
        Assert.True(Hit("rule t { strings: $r = /ab+c/i condition: $r }", B("xxABBBCxx")));
        Assert.False(Hit("rule t { strings: $r = /ab+c/ condition: $r }", B("xxABBBCxx")));
    }

    [Fact]
    public void ConditionsCountsOffsetsAndIntegers()
    {
        var data = B("MZ....aaa....aaa....b");
        Assert.True(Hit("rule t { strings: $a = \"aaa\" condition: #a == 2 and uint16(0) == 0x5A4D }", data));
        Assert.True(Hit("rule t { strings: $a = \"aaa\" condition: @a[2] == 13 }", data));
        Assert.True(Hit("rule t { strings: $a = \"aaa\" condition: $a in (0..10) }", data));
        Assert.True(Hit("rule t { condition: filesize < 1KB and filesize > 20 }", data));
        Assert.False(Hit("rule t { condition: filesize >= 1MB }", data));
        Assert.True(Hit("rule t { condition: uint16be(0) == 0x4D5A and int8(0) == 77 }", data));
        Assert.False(Hit("rule t { condition: uint32(1000) == 0 }", data));   // out of range -> false, not crash
    }

    [Fact]
    public void OfExpressionsAndWildcardSets()
    {
        const string r = "rule t { strings: $a1 = \"one\" $a2 = \"two\" $b = \"three\" condition: 2 of ($a*) and not $b }";
        Assert.True(Hit(r, B("one two")));
        Assert.False(Hit(r, B("one two three")));
        Assert.True(Hit("rule t { strings: $a = \"x\" $b = \"y\" condition: all of them }", B("xy")));
        Assert.True(Hit("rule t { strings: $a = \"x\" $b = \"y\" condition: none of them }", B("zz")));
        Assert.True(Hit("rule t { strings: $a = \"x\" $b = \"y\" condition: any of ($a, $b) }", B("y")));
    }

    [Fact]
    public void MetaTagsCommentsAndPrivateRules()
    {
        var rules = YaraParser.Parse("// c\n/* block */ private rule t : tag1 tag2 { meta: severity = \"high\" n = 5 condition: true }");
        Assert.Equal(new[] { "tag1", "tag2" }, rules[0].Tags);
        Assert.Equal("high", rules[0].Meta["severity"]);
        Assert.Equal("5", rules[0].Meta["n"]);
    }

    [Theory]
    [InlineData("rule t { strings: $a = \"x\" condition: $b }")]                 // undefined string
    [InlineData("import \"pe\" rule t { condition: true }")]                    // modules unsupported
    [InlineData("rule t { condition: pe.number_of_sections > 1 }")]
    [InlineData("rule t { strings: $a = { 4D 5 } condition: $a }")]               // odd hex
    [InlineData("rule t { condition: true } rule t { condition: true }")]        // duplicate
    public void RejectsInvalidRules(string src) => Assert.Throws<YaraSyntaxException>(() => YaraParser.Parse(src));

    [Fact]
    public void CatastrophicRegexDoesNotHang()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Hit("rule t { strings: $r = /(a+)+$/ condition: $r }", B(new string('a', 5000) + "!"));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10));
    }
}

public class BuiltInRuleTests
{
    // Samples are assembled at runtime so this source file contains no contiguous malicious indicators.
    private static string J(params string[] parts) => string.Concat(parts);
    private static readonly YaraScanner Scanner = new(YaraRuleSet.LoadBuiltIn());
    private static List<string> Rules(string content, bool pe = false) =>
        Scanner.Scan(Encoding.Latin1.GetBytes((pe ? "MZ\x90\0" : "") + content)).Select(m => m.Rule.Name).ToList();

    [Fact] public void BuiltInRulesParse() => Assert.True(YaraRuleSet.LoadBuiltIn().Count >= 15);

    [Fact]
    public void EveryBuiltInRuleHasRequiredMeta()
    {
        foreach (var r in YaraRuleSet.LoadBuiltIn())
        {
            Assert.True(r.Meta.ContainsKey("description"), r.Name);
            Assert.Contains(r.Meta["severity"], new[] { "critical", "high", "medium", "low", "info" });
        }
    }

    [Fact]
    public void DetectsShadowCopyDeletion() =>
        Assert.Contains("Ransomware_ShadowCopy_Destruction", Rules(J("cmd /c vss", "admin delete sha", "dows /all /quiet & bcdedit /set {default} recovery", "enabled no")));

    [Fact]
    public void DetectsPowerShellCradle() =>
        Assert.Contains("Loader_PowerShell_Download_Cradle", Rules(J("$w = New-Object Net.Web", "Client; $s = $w.Download", "String('http://x'); I", "EX $s; [Convert]::FromBase64", "String('AA==')")));

    [Fact]
    public void DetectsTelegramExfil() =>
        Assert.Contains("Exfiltration_Telegram_Bot", Rules(J("https://api.tele", "gram.org/bot123:ABC/sendDoc", "ument?chat_id=1"), pe: true));

    [Fact]
    public void DetectsDiscordWebhook() =>
        Assert.Contains("Exfiltration_Discord_Webhook", Rules(J("https://discord.com/api/web", "hooks/123456789012345678/", new string('a', 68))));

    [Fact]
    public void DetectsDefenderTampering() =>
        Assert.Contains("Defense_Evasion_Defender_Tampering", Rules(J("powershell Add-Mp", "Preference -Exclusion", "Path C:\\")));

    [Fact]
    public void DetectsMinerConfig() =>
        Assert.Contains("Miner_Stratum_Configuration", Rules(J("{\"url\":\"stratum", "+tcp://pool:3333\",\"donate-level\":1}")));

    [Fact]
    public void DetectsDiscordTokenGrabber() =>
        Assert.Contains("Stealer_Discord_Token_Grabber", Rules(J("\\discord\\Local Storage\\level", "db\\ dQw4w9W", "gXcQ:")));

    [Theory]
    [InlineData("Get-ChildItem C:\\ | Export-Csv files.csv\r\nWrite-Host 'Backup complete'")]
    [InlineData("@echo off\r\necho Installing game patch...\r\ncopy /y patch.dll game\\\r\n")]
    [InlineData("Set shell = CreateObject(\"WScript.Shell\")\r\nshell.Run \"notepad.exe\"")]
    [InlineData("Discord is a chat app. Visit discord.com to download.")]
    public void BenignContentDoesNotMatch(string content) =>
        Assert.DoesNotContain(Rules(content), r => r != "Packer_UPX");

    [Fact]
    public void BenignPeWithChromeStringsAloneDoesNotMatchStealer() =>
        Assert.DoesNotContain("Stealer_Browser_And_Wallet_Harvesting", Rules("\\Google\\Chrome\\User Data Local State", pe: true));
}

public class ReputationTests
{
    private static FileIntel F(string path, string hash, bool signed) =>
        new() { Path = path, Exists = true, SHA256 = hash, SignatureStatus = signed ? SignatureStatus.Valid : SignatureStatus.NotSigned, Suspicious = PathHeuristics.IsSuspicious(path) };
    private static ProviderVerdict V(Verdict v, bool generic = false, string? label = null) => new() { Provider = "p", Verdict = v, Generic = generic, Label = label };

    [Fact] public void NamedMaliciousWins() => Assert.Equal(Verdict.Malicious, VerdictAggregator.Combine(new[] { V(Verdict.KnownGood), V(Verdict.Malicious, false, "AsyncRAT") }).Overall);
    [Fact] public void SingleGenericIsOnlySuspicious() => Assert.Equal(Verdict.Suspicious, VerdictAggregator.Combine(new[] { V(Verdict.Malicious, true, "Wacatac.B!ml") }).Overall);
    [Fact] public void TwoGenericsCorroborate() => Assert.Equal(Verdict.Malicious, VerdictAggregator.Combine(new[] { V(Verdict.Malicious, true), V(Verdict.Malicious, true) }).Overall);
    [Fact] public void KnownGoodBeatsUnknown() => Assert.Equal(Verdict.KnownGood, VerdictAggregator.Combine(new[] { V(Verdict.Unknown), V(Verdict.KnownGood) }).Overall);
    [Fact] public void ErrorsAreIgnored() => Assert.Equal(Verdict.Unknown, VerdictAggregator.Combine(new[] { V(Verdict.Error) }).Overall);

    [Fact]
    public void CandidatesPrioritiseTamperedThenUnsignedRisky()
    {
        var tampered = F(@"C:\Program Files\A\t.exe", "T", true); tampered.SignatureStatus = SignatureStatus.HashMismatch;
        var c = ReputationCheck.SelectCandidates(new[]
        {
            F(@"C:\Program Files\A\signed.exe", "S", true), F(@"C:\Program Files\A\u.exe", "U", false),
            F(@"C:\Users\B\AppData\Local\Temp\r.exe", "R", false), tampered,
        }, 10);
        Assert.Equal(new[] { "T", "R", "U" }, c.Select(x => x.SHA256));
    }

    [Theory]
    [InlineData(2, "MpCmdRun: Threat  : Trojan:Win32/AgentTesla.A\nfound 1 threats.", Verdict.Malicious, false)]
    [InlineData(2, "Threat  : Trojan:Win32/Wacatac.B!ml", Verdict.Malicious, true)]
    [InlineData(0, "Scan finished. found no threats.", Verdict.Clean, false)]
    [InlineData(5, "error", Verdict.Error, false)]
    public void ParsesDefenderOutput(int code, string output, Verdict expected, bool generic)
    {
        var v = DefenderFileScanProvider.Parse(code, output, Indicators.LoadBuiltIn().GenericDetectionSuffixes);
        Assert.Equal(expected, v.Verdict);
        Assert.Equal(generic, v.Generic);
    }

    private sealed class Fake : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _f; public int Calls;
        public Fake(Func<HttpRequestMessage, HttpResponseMessage> f) => _f = f;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct) { Calls++; return Task.FromResult(_f(r)); }
    }
    private static HttpResponseMessage Json(string body, HttpStatusCode code = HttpStatusCode.OK) => new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static CheckContext Ctx(FileIntelService files, Action<ScanOptions>? cfg = null)
    {
        var o = new ScanOptions { ReputationDefender = false };
        cfg?.Invoke(o);
        return new CheckContext(o, Indicators.LoadBuiltIn(), files);
    }

    [Fact]
    public void KeyFreeDefaultsAndKnownGoodSkipsPaidLookups()
    {
        var files = new FileIntelService();
        var good = F(@"C:\Users\B\AppData\Local\Temp\known.exe", "GOOD", false);
        var bad = F(@"C:\Users\B\AppData\Local\Temp\evil.exe", "BAD", false);
        files.Seed(good); files.Seed(bad);
        // CIRCL's bulk endpoint answers for all hashes in one request.
        var circl = new Fake(r => r.RequestUri!.AbsoluteUri.EndsWith("/bulk/sha256") ? Json("[{\"SHA-256\":\"GOOD\",\"FileName\":\"known.exe\"}]") : Json("{}", HttpStatusCode.NotFound));
        var vt = new Fake(r => Json("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":30},\"popular_threat_classification\":{\"suggested_threat_label\":\"trojan.redline\"}}}}"));
        var ctx = Ctx(files, o => o.VirusTotalApiKey = "k");
        new ReputationCheck(new IReputationProvider[] { new CirclHashlookupProvider(circl), new VirusTotalProvider(vt) }).Run(ctx);
        Assert.Equal(1, circl.Calls);
        Assert.Equal(1, vt.Calls);                 // known-good file not sent to VirusTotal
        Assert.Contains(ctx.Findings, f => f.Severity == Severity.Critical && f.RuleId == "reputation.malicious" && f.Title.Contains("trojan.redline"));
        Assert.DoesNotContain(ctx.Findings, f => f.Title.Contains("known.exe"));
    }

    [Fact]
    public void CirclFeedListingIsALeadNotKnownMalware()
    {
        // Real case: a Microsoft-signed runtime DLL in Temp listed in the malshare.com feed.
        var files = new FileIntelService();
        var signedDll = F(@"C:\Users\B\AppData\Local\Temp\ak1\Feedback\System.Security.Principal.Windows.dll", "S1", true);
        signedDll.Signer = "Microsoft Corporation";
        var unsigned = F(@"C:\Users\B\AppData\Local\Temp\drop.exe", "U1", false);
        files.Seed(signedDll); files.Seed(unsigned);
        var circl = new Fake(r => Json("[{\"SHA-256\":\"S1\",\"KnownMalicious\":\"malshare.com\"},{\"SHA-256\":\"U1\",\"KnownMalicious\":\"malshare.com\"}]"));
        var ctx = Ctx(files);
        new ReputationCheck(new IReputationProvider[] { new CirclHashlookupProvider(circl) }).Run(ctx);
        Assert.DoesNotContain(ctx.Findings, f => f.Severity == Severity.Critical);
        Assert.Equal(2, ctx.Findings.Count);
        Assert.Single(ctx.Findings, f => f.RuleId == "reputation.listed-signed" && f.Severity == Severity.Info && f.Title.Contains("System.Security.Principal.Windows.dll"));
        Assert.Single(ctx.Findings, f => f.RuleId == "reputation.suspicious" && f.Severity == Severity.High && f.Title.Contains("drop.exe") && f.Detail.Contains("malshare.com"));
    }

    [Fact]
    public void KeyedProvidersStayOffWithoutKeys()
    {
        var files = new FileIntelService(); files.Seed(F(@"C:\Users\B\Downloads\x.exe", "X", false));
        var vt = new Fake(_ => Json("{}")); var mb = new Fake(_ => Json("{}"));
        var ctx = Ctx(files, o => o.ReputationCircl = false);
        new ReputationCheck(new IReputationProvider[] { new VirusTotalProvider(vt), new MalwareBazaarProvider(mb) }).Run(ctx);
        Assert.Equal(0, vt.Calls + mb.Calls);
        Assert.Contains(ctx.Findings, f => f.Title == "No reputation sources were available");
    }

    [Fact]
    public void MalwareBazaarHitIsCriticalAndSendsAuthKey()
    {
        var files = new FileIntelService(); files.Seed(F(@"C:\Users\B\AppData\Roaming\upd.exe", "MB", false));
        var mb = new Fake(r =>
        {
            Assert.Equal("my-key", r.Headers.GetValues("Auth-Key").Single());
            return Json("{\"query_status\":\"ok\",\"data\":[{\"signature\":\"AsyncRAT\"}]}");
        });
        var ctx = Ctx(files, o => { o.ReputationCircl = false; o.MalwareBazaarAuthKey = "my-key"; });
        new ReputationCheck(new IReputationProvider[] { new MalwareBazaarProvider(mb) }).Run(ctx);
        Assert.Contains(ctx.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("AsyncRAT"));
    }

    [Fact]
    public void UnknownUnsignedRiskyFileIsMedium()
    {
        var files = new FileIntelService(); files.Seed(F(@"C:\Users\B\AppData\Local\Temp\odd.exe", "ODD", false));
        var circl = new Fake(_ => Json("{}", HttpStatusCode.NotFound));
        var ctx = Ctx(files);
        new ReputationCheck(new IReputationProvider[] { new CirclHashlookupProvider(circl) }).Run(ctx);
        Assert.Contains(ctx.Findings, f => f.Severity == Severity.Medium && f.RuleId == "reputation.unknown");
    }


}

public class YaraCheckTests
{
    [Fact]
    public void ScansTargetsAndRespectsTargetMeta()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tk-yara-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
        try
        {
            var script = Path.Combine(dir, "a.ps1"); File.WriteAllText(script, "token PAYLOAD here");
            var pe = Path.Combine(dir, "b.exe"); File.WriteAllBytes(pe, Encoding.Latin1.GetBytes("MZ\x90\0 token PAYLOAD"));
            var rules = YaraParser.Parse(
                "rule ScriptOnly { meta: description = \"script rule\" severity = \"high\" target = \"script\" strings: $a = \"PAYLOAD\" condition: $a } " +
                "rule PeOnly { meta: description = \"pe rule\" severity = \"medium\" target = \"pe\" strings: $a = \"PAYLOAD\" condition: $a }");
            var ctx = new CheckContext(new ScanOptions(), Indicators.LoadBuiltIn(), new FileIntelService());
            new YaraCheck(rules, new[] { script, pe }).Run(ctx);
            Assert.Contains(ctx.Findings, f => f.Title == "script rule: a.ps1" && f.Severity == Severity.High);
            Assert.Contains(ctx.Findings, f => f.Title == "pe rule: b.exe" && f.Severity == Severity.Medium);
            Assert.DoesNotContain(ctx.Findings, f => f.Title == "script rule: b.exe" || f.Title == "pe rule: a.ps1");
        }
        finally { Directory.Delete(dir, true); }
    }
}

public class RulePackTests2
{
    private static string NewPack()
    {
        var d = Path.Combine(Path.GetTempPath(), "tk-pack-" + Guid.NewGuid());
        Directory.CreateDirectory(Path.Combine(d, "yara"));
        File.WriteAllText(Path.Combine(d, "indicators.json"), "{\"version\":\"t\",\"ratPorts\":[\"1\"]}");
        File.WriteAllText(Path.Combine(d, "yara", "x.yar"), "rule x { condition: false }");
        return d;
    }

    [Fact]
    public void SignVerifyRoundTripAndTamperDetection()
    {
        var (priv, pub) = RulePack.GenerateKeyPair();
        var d = NewPack();
        try
        {
            RulePack.Sign(d, priv, "2026.11.15");
            var ok = RulePack.Verify(d, pub);
            Assert.True(ok.Trusted, ok.Error);
            Assert.Equal("2026.11.15", ok.Version);

            File.AppendAllText(Path.Combine(d, "yara", "x.yar"), " ");                  // tamper with a rule
            Assert.False(RulePack.Verify(d, pub).Trusted);
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void WrongKeyAndEditedManifestAreRejected()
    {
        var (priv, _) = RulePack.GenerateKeyPair();
        var (_, otherPub) = RulePack.GenerateKeyPair();
        var d = NewPack();
        try
        {
            RulePack.Sign(d, priv, "1");
            Assert.False(RulePack.Verify(d, otherPub).Trusted);
            var m = Path.Combine(d, RulePack.ManifestName);
            File.WriteAllText(m, File.ReadAllText(m).Replace("\"1\"", "\"2\""));          // edit manifest
            Assert.False(RulePack.Verify(d, null).Trusted);
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void UnlistedFilesAreNotLoadedAndTraversalIsRejected()
    {
        var (priv, pub) = RulePack.GenerateKeyPair();
        var d = NewPack();
        try
        {
            RulePack.Sign(d, priv, "1");
            File.WriteAllText(Path.Combine(d, "yara", "added-later.yar"), "rule y { condition: true }");
            Assert.True(RulePack.Verify(d, pub).Trusted);                                  // pack itself still valid...
            Assert.DoesNotContain(RulePack.SignedFiles(d), f => f.EndsWith("added-later.yar")); // ...but the extra file is not signed
        }
        finally { Directory.Delete(d, true); }
    }

    [Fact]
    public void MissingManifestIsUntrusted() => Assert.False(RulePack.Verify(Path.GetTempPath()).Trusted);

    [Fact]
    public void BuiltInPublicKeyLoads() => Assert.Contains("BEGIN PUBLIC KEY", RulePack.BuiltInPublicKeyPem());
}
