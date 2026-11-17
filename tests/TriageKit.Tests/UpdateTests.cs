using System.IO.Compression;
using System.Security.Cryptography;
using TriageKit.Core.Agent;
using Xunit;

namespace TriageKit.Tests;

public class UpdateTests
{
    private static string Fx(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void SignedManifestFromServerVerifies()
    {
        using var d = System.Text.Json.JsonDocument.Parse(Fx("server-update.json"));
        var m = d.RootElement.GetProperty("manifest").GetString(); var s = d.RootElement.GetProperty("signature").GetString();
        var info = Updates.VerifyManifest(m, s, Fx("server-release-public.pem"));
        Assert.NotNull(info);
        Assert.Equal("0.10.0", info!.Version);
        Assert.Null(Updates.VerifyManifest(m!.Replace("0.10.0", "9.9.9"), s, Fx("server-release-public.pem")));
        Assert.Null(Updates.VerifyManifest(m, s, TriageKit.Core.Rules.RulePack.GenerateKeyPair().PublicPem));   // wrong key
    }

    [Theory]
    [InlineData("0.10.0", "0.9.0", true)]
    [InlineData("0.9.1", "0.9.0", true)]
    [InlineData("0.9.0", "0.9.0", false)]
    [InlineData("0.8.9", "0.9.0", false)]
    [InlineData("1.0.0", "0.9.0+abc", true)]
    public void OnlyMovesForward(string candidate, string current, bool newer) => Assert.Equal(newer, Updates.IsNewer(candidate, current));

    private static byte[] FakeExe() { var b = new byte[4096]; b[0] = (byte)'M'; b[1] = (byte)'Z'; RandomNumberGenerator.Fill(b.AsSpan(2)); return b; }

    [Fact]
    public void DownloadMustMatchPublishedHash()
    {
        var exe = FakeExe();
        var sha = Convert.ToHexString(SHA256.HashData(exe));
        Assert.Equal(exe, Updates.ExtractVerified(exe, sha));
        Assert.Throws<InvalidOperationException>(() => Updates.ExtractVerified(exe, new string('0', 64)));
        var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true)) { using var s = z.CreateEntry("TriageKit.exe").Open(); s.Write(exe); }
        var zip = ms.ToArray();
        Assert.Equal(exe, Updates.ExtractVerified(zip, Convert.ToHexString(SHA256.HashData(zip))));
        Assert.Throws<InvalidOperationException>(() => Updates.ExtractVerified(new byte[] { 1, 2, 3 }, Convert.ToHexString(SHA256.HashData(new byte[] { 1, 2, 3 }))));
    }

    [Fact]
    public void InstallSwapsTheExeAndKeepsTheOldOne()
    {
        var dir = Path.Combine(Path.GetTempPath(), "tk-upd-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
        var exe = Path.Combine(dir, "TriageKit.exe");
        File.WriteAllBytes(exe, new byte[] { (byte)'M', (byte)'Z', 1 });
        var next = FakeExe();
        Updates.Install(exe, next);
        Assert.Equal(next, File.ReadAllBytes(exe));
        Assert.True(File.Exists(Path.Combine(dir, "TriageKit.exe.old")));
        Updates.CleanupOld(exe);
        Assert.False(File.Exists(Path.Combine(dir, "TriageKit.exe.old")));
        Directory.Delete(dir, true);
    }

    [Fact]
    public void ShippedKeysAreNotTestKeys()
    {
        // Guard against releasing with the throw-away keys used by the local server tests.
        foreach (var (res, fx) in new[] { ("release-public.pem", "server-release-public.pem") })
        {
            using var s = typeof(Updates).Assembly.GetManifestResourceStream(res)!;
            Assert.NotEqual(Fx(fx).Trim(), new StreamReader(s).ReadToEnd().Trim());
        }
    }
}
