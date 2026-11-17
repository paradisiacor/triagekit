using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.SafeStart;
using Xunit;

namespace TriageKit.Tests;

public class SafeStartDownloadTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tk-safestart").FullName;
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static CheckContext Ctx() => new(new ScanOptions { ReputationCircl = false, ReputationDefender = false }, TriageKit.Core.Rules.Indicators.LoadBuiltIn(), new FileIntelService());
    private DownloadCheck.Result Check(string path) => new DownloadCheck(Ctx()).Run(path);

    /// <summary>A minimal, valid-looking PE: MZ header, PE signature, optional header, one section. Never executed.</summary>
    internal static byte[] FakePe(int sectionSize = 1024, byte[]? overlay = null, string? marker = null)
    {
        var pe = new byte[0x200 + sectionSize];
        pe[0] = (byte)'M'; pe[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(pe, 0x3C);
        BitConverter.GetBytes(0x00004550u).CopyTo(pe, 0x80);
        BitConverter.GetBytes((ushort)1).CopyTo(pe, 0x80 + 6);            // one section
        BitConverter.GetBytes((ushort)0xF0).CopyTo(pe, 0x80 + 20);        // size of optional header (PE32+)
        BitConverter.GetBytes((ushort)0x20B).CopyTo(pe, 0x80 + 24);       // PE32+
        int sec = 0x80 + 24 + 0xF0;
        Encoding.ASCII.GetBytes(".text").CopyTo(pe, sec);
        BitConverter.GetBytes((uint)sectionSize).CopyTo(pe, sec + 16);   // raw size
        BitConverter.GetBytes(0x200u).CopyTo(pe, sec + 20);               // raw pointer
        if (marker is not null) Encoding.ASCII.GetBytes(marker).CopyTo(pe, 0x200 + 16);
        return overlay is null ? pe : pe.Concat(overlay).ToArray();
    }

    private string Zip(string name, params (string Entry, byte[] Data)[] files)
    {
        var path = Path.Combine(_dir, name);
        using var z = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entry, data) in files) { using var s = z.CreateEntry(entry).Open(); s.Write(data); }
        return path;
    }

    [Fact]
    public void CleanFolderHasNoThreats()
    {
        var game = Directory.CreateDirectory(Path.Combine(_dir, "Game")).FullName;
        File.WriteAllBytes(Path.Combine(game, "game.exe"), FakePe());
        File.WriteAllText(Path.Combine(game, "readme.txt"), "Thanks for playing! Press F1 for help.");
        File.WriteAllBytes(Path.Combine(game, "data.pak"), new byte[4096]);
        var r = Check(game);
        Assert.True(r.Verdict == DownloadCheck.Verdict.NoThreatsFound, string.Join(" | ", r.Findings.Select(f => f.RuleId + ":" + f.Title)));
        Assert.Equal(3, r.Files);
        Assert.Equal(1, r.Programs);
        Assert.Empty(r.Findings);
    }

    [Fact]
    public void DisguisedProgramIsDangerous()
    {
        var p = Path.Combine(_dir, "Invoice_2026.pdf.exe");
        File.WriteAllBytes(p, FakePe());
        var r = Check(p);
        Assert.Equal(DownloadCheck.Verdict.Dangerous, r.Verdict);
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.double-extension");
    }

    [Fact]
    public void ReadmeTellingYouToDisableAntivirusIsDangerous()
    {
        var zip = Zip("Cool-Game-Repack.zip",
            ("Cool Game/setup.exe", FakePe()),
            ("Cool Game/README.txt", Encoding.UTF8.GetBytes("IMPORTANT!!\r\nBefore installing please disable Windows Defender real-time protection, the crack is a false positive.")));
        var r = Check(zip);
        Assert.Equal(DownloadCheck.Verdict.Dangerous, r.Verdict);
        var f = Assert.Single(r.Findings, x => x.RuleId == "safestart.disable-av-instructions");
        Assert.Contains("Cool-Game-Repack.zip » Cool Game/README.txt", f.Detail);
        Assert.Equal(1, r.Archives);
        Assert.Equal(3, r.Files);   // the archive and the two files in it
    }

    [Theory]
    [InlineData("Add the game folder to the exclusions of your antivirus", true)]
    [InlineData("Turn off your antivirus before extracting", true)]
    [InlineData("Your AV will detect the crack, it's a false positive", true)]
    [InlineData("Please pause Windows Security while installing", true)]
    [InlineData("This game requires DirectX 12 and 8 GB of RAM", false)]
    [InlineData("Disable V-Sync in the options if you see tearing", false)]
    [InlineData("Run as administrator if the launcher doesn't start", false)]
    public void AntivirusInstructionsAreRecognised(string text, bool flagged) => Assert.Equal(flagged, RedFlags.DisableAntivirus.IsMatch(text));

    [Fact]
    public void NestedArchivesAreOpenedAndShortcutsJudged()
    {
        var lnk = new byte[0x4C + 8]; lnk[0] = 0x4C; lnk[4] = 0x01; lnk[5] = 0x14;   // shortcut header only (no target)
        var inner = new MemoryStream();
        using (var z = new ZipArchive(inner, ZipArchiveMode.Create, true)) { using var s = z.CreateEntry("docs/Photo.jpg.lnk").Open(); s.Write(lnk); }
        var outer = Zip("pack.zip", ("inner.zip", inner.ToArray()));
        var r = Check(outer);
        Assert.Equal(2, r.Archives);
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.double-extension" && f.Detail.Contains("pack.zip » inner.zip » docs/Photo.jpg.lnk"));
    }

    [Fact]
    public void TarGzIsReadToo()
    {
        var tar = new MemoryStream();
        using (var w = new TarWriter(tar, TarEntryFormat.Pax, leaveOpen: true))
        {
            var e = new PaxTarEntry(TarEntryType.RegularFile, "tool/update.pdf.scr") { DataStream = new MemoryStream(FakePe()) };
            w.WriteEntry(e);
        }
        var path = Path.Combine(_dir, "tool.tar.gz");
        using (var fs = File.Create(path)) using (var gz = new GZipStream(fs, CompressionLevel.Fastest)) gz.Write(tar.ToArray());
        var r = Check(path);
        Assert.True(r.Archives >= 2, $"archives {r.Archives}, files {r.Files}, not checked: {string.Join(" | ", r.NotChecked)}, items: {string.Join(" | ", r.Items.Select(i => i.Path + ":" + i.Kind))}");
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.double-extension");
    }

    [Fact]
    public void PaddedLoaderInsideAnArchiveIsCaught()
    {
        var padded = FakePe(overlay: new byte[DownloadCheck.MaxInspectBytes + 1024 * 1024]);   // ~97 MB of zeros after the image
        var zip = Zip("Game-Setup.zip", ("Setup.exe", padded));
        var r = Check(zip);
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.padded");
        Assert.Equal(DownloadCheck.Verdict.Dangerous, r.Verdict);
    }

    [Fact]
    public void PackedScriptStealerShapeIsSuspicious()
    {
        var p = Path.Combine(_dir, "FPS-Booster.exe");
        File.WriteAllBytes(p, FakePe(marker: "PYZ-00.pyz"));
        var r = Check(p);
        Assert.True(r.Findings.Exists(f => f.RuleId == "safestart.packed-script"), string.Join(" | ", r.Findings.Select(f => f.RuleId + ":" + f.Severity)));
        Assert.Equal(DownloadCheck.Verdict.Suspicious, r.Verdict);
    }

    [Fact]
    public void FakeInstallerNameIsCaught()
    {
        var p = Path.Combine(_dir, "SteamSetup.exe");
        File.WriteAllBytes(p, FakePe());
        var r = Check(p);
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.fake-installer");
    }

    [Fact]
    public void PasswordProtectedProgramsAreReportedAsNotChecked()
    {
        // A ZIP whose entry has the "encrypted" flag set (general purpose bit 0).
        var path = Zip("locked.zip", ("crack/loader.exe", FakePe()));
        var bytes = File.ReadAllBytes(path);
        for (int i = 0; i + 4 < bytes.Length; i++)
        {
            if (bytes[i] == 'P' && bytes[i + 1] == 'K' && bytes[i + 2] == 3 && bytes[i + 3] == 4) bytes[i + 6] |= 1;   // local header flags
            if (bytes[i] == 'P' && bytes[i + 1] == 'K' && bytes[i + 2] == 1 && bytes[i + 3] == 2) bytes[i + 8] |= 1;   // central directory flags
        }
        File.WriteAllBytes(path, bytes);
        var r = Check(path);
        Assert.Contains(r.NotChecked, n => n.Contains("password-protected"));
        Assert.Contains(r.Findings, f => f.RuleId == "safestart.encrypted-programs");
        Assert.NotEqual(DownloadCheck.Verdict.NoThreatsFound, r.Verdict);
    }

    [Fact]
    public void ArchiveBombIsCutOffNotFollowed()
    {
        var zip = Zip("bomb.zip", ("big.bin", new byte[300 * 1024 * 1024]));   // 300 MB of zeros packs to ~300 KB
        var r = Check(zip);
        Assert.Contains(r.NotChecked, n => n.Contains("packed size") || n.Contains("size limit"));
    }

    [Fact]
    public void MissingPathThrows() => Assert.Throws<FileNotFoundException>(() => Check(Path.Combine(_dir, "nope.exe")));

    [Theory]
    [InlineData("setup.exe", "Program")]
    [InlineData("README.txt", "Text")]
    [InlineData("game.iso", "Disk image")]
    [InlineData("invoice.docm", "Document")]
    [InlineData("run.ps1", "Script")]
    public void ClassifiesByName(string name, string kind) => Assert.Equal(kind, DownloadCheck.Classify(name, "xx"u8));

    [Fact]
    public void ClassifiesByContentFirst()
    {
        Assert.Equal("Program", DownloadCheck.Classify("photo.jpg", FakePe()));                    // a renamed program is still a program
        Assert.Equal("Archive", DownloadCheck.Classify("data.bin", "Rar!\u001a\u0007\u0000xx"u8));
        Assert.Equal("Document", DownloadCheck.Classify("report.docx", "PK\u0003\u0004xxxx"u8));  // Office files are ZIPs, but documents
    }
}

public class PeSignatureTests
{
    [Fact]
    public void UnsignedProgramIsNotSigned() => Assert.Equal(PeSignature.State.NotSigned, PeSignature.Verify(SafeStartDownloadTests.FakePe()).State);

    [Fact]
    public void GarbageIsUnreadable() => Assert.Equal(PeSignature.State.Unreadable, PeSignature.Verify(Encoding.ASCII.GetBytes("hello")).State);

    /// <summary>Uses a real Microsoft-signed program when one is available on the test machine (it isn't committed).</summary>
    [Fact]
    public void RealSignatureVerifiesAndDetectsTampering()
    {
        var sample = Environment.GetEnvironmentVariable("TK_SIGNED_PE");
        if (sample is null || !File.Exists(sample)) return;
        var pe = File.ReadAllBytes(sample);
        var ok = PeSignature.Verify(pe, checkTrust: false);
        Assert.Equal(PeSignature.State.Valid, ok.State);
        Assert.Contains("Microsoft", ok.Signer);
        pe[0x400] ^= 0xFF;   // flip one byte of code
        Assert.Equal(PeSignature.State.Modified, PeSignature.Verify(pe, checkTrust: false).State);
    }
}

public class InstallWatchTests
{
    private static ScanResult Scan(object autostarts, object certs, object defender, params Finding[] findings) => new()
    {
        Meta = new ScanMeta(),
        Findings = findings.ToList(),
        Data = new Dictionary<string, object?>
        {
            ["Autostarts & persistence"] = autostarts,
            ["Root certificates"] = certs,
            ["Antivirus & Defender"] = defender,
            ["Running processes"] = new[] { new { Name = "game.exe", Pid = 4242 } },   // volatile: never compared
        },
    };

    [Fact]
    public void ReportsWhatAnInstallChanged()
    {
        var before = InstallWatch.FromScan(Scan(
            new { Entries = new[] { new { Location = "HKCU Run", Name = "Discord", Command = "Update.exe --processStart Discord.exe", Risk = "Info" } } },
            new { Certificates = new object[0] },
            new { Status = new { RealTimeProtectionEnabled = true, AMProductVersion = "4.18.1" }, Exclusions = new object[0] }), "test");
        var after = InstallWatch.FromScan(Scan(
            new { Entries = new[] {
                new { Location = "HKCU Run", Name = "Discord", Command = "Update.exe --processStart Discord.exe", Risk = "Info" },
                new { Location = "HKCU Run", Name = "svc", Command = @"C:\Users\a\AppData\Roaming\svc\svc.exe", Risk = "High" } } },
            new { Certificates = new[] { new { Subject = "Totally Legit CA", Thumbprint = "ABCD", Risk = "Medium" } } },
            new { Status = new { RealTimeProtectionEnabled = false, AMProductVersion = "4.18.2" }, Exclusions = new[] { new { Type = "Path", Value = @"C:\Games" } } },
            new Finding { Severity = Severity.High, Category = "Defender", Title = "Defender real-time protection is OFF", RuleId = "defender.rtp-off" }), "test");

        var c = InstallWatch.Compare(before, after);
        Assert.Equal(InstallWatch.Verdict.Dangerous, c.Verdict);
        Assert.Single(c.NewFindings, f => f.RuleId == "defender.rtp-off");
        Assert.Contains(c.Added, x => x.Category == "Startup entry, task or service" && x.Text.Contains("svc.exe") && x.Severity == "High");
        Assert.Contains(c.Added, x => x.Category == "Trusted root certificate" && x.Severity == "High");
        Assert.Contains(c.Added, x => x.Category == "Defender exclusion" && x.Text.Contains(@"C:\Games") && x.Severity == "High");
        Assert.Contains(c.Added, x => x.Category == "Setting" && x.Text.Contains("RealTimeProtectionEnabled") && x.Severity == "High");
        Assert.DoesNotContain(c.Added, x => x.Text.Contains("Discord"));          // unchanged
        Assert.DoesNotContain(c.Added, x => x.Text.Contains("AMProductVersion")); // versions aren't settings
        Assert.DoesNotContain(c.Added, x => x.Text.Contains("game.exe"));          // volatile list
    }

    [Fact]
    public void NothingChangedIsSaidPlainly()
    {
        var s = Scan(new { Entries = new[] { new { Location = "HKCU Run", Name = "A", Command = "a.exe" } } }, new { Certificates = new object[0] }, new { Exclusions = new object[0] });
        var c = InstallWatch.Compare(InstallWatch.FromScan(s, "t"), InstallWatch.FromScan(s, "t"));
        Assert.Equal(InstallWatch.Verdict.NothingWorrying, c.Verdict);
        Assert.Equal("Nothing changed.", c.Headline);
        Assert.Empty(c.Added);
    }

    [Fact]
    public void SnapshotSurvivesSavingAndLoading()
    {
        var s = InstallWatch.FromScan(Scan(new { Entries = new[] { new { Location = "Run", Name = "A", Command = "a.exe" } } }, new { Certificates = new object[0] }, new { Exclusions = new object[0] },
            new Finding { Severity = Severity.Low, Category = "X", Title = "t", RuleId = "x.y" }), "t");
        var back = JsonSerializer.Deserialize<InstallWatch.Snapshot>(JsonSerializer.Serialize(s, InstallWatch.Json), InstallWatch.Json)!;
        var c = InstallWatch.Compare(back, s);
        Assert.Empty(c.Added); Assert.Empty(c.NewFindings); Assert.Empty(c.Removed);
    }

    [Fact]
    public void ANormalInstallIsNotWorrying()
    {
        var before = InstallWatch.FromScan(Scan(new { Entries = new object[0] }, new { Certificates = new object[0] }, new { Exclusions = new object[0] }), "t");
        var afterScan = Scan(new { Entries = new[] { new { Location = "Scheduled task", Name = "GoogleUpdater", Command = "updater.exe --wake", Risk = "Info" } } }, new { Certificates = new object[0] }, new { Exclusions = new object[0] });
        afterScan.Data["Installed software"] = new { Installed = new[] { new { Name = "Some Game", Version = "1.0", Publisher = "Studio" } } };
        var c = InstallWatch.Compare(before, InstallWatch.FromScan(afterScan, "t"));
        Assert.Equal(InstallWatch.Verdict.NothingWorrying, c.Verdict);
        Assert.Contains(c.Added, x => x.Category == "Installed program" && x.Text.Contains("Some Game"));
    }
}
