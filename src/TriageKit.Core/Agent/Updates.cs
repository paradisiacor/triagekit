using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TriageKit.Core.Agent;

public sealed record UpdateInfo(string Version, string Channel, string Url, string Sha256, long Size, string Notes, DateTime Published);

/// <summary>
/// Update channel. The server publishes a manifest signed with the release key (kept inside Cloudflare); the app
/// only trusts a manifest whose signature verifies with the release key built into this exe, only moves to a
/// higher version, and only installs a download whose SHA-256 matches the manifest.
/// </summary>
public static class Updates
{
    /// <summary>Signed release announcements (no data about the PC is sent).</summary>
    public const string DefaultUrl = "https://triagekit-api.paradisiac.workers.dev";

    public static string ReleasePublicKeyPem()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("release-public.pem") ?? throw new InvalidOperationException("Release key missing");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    public static UpdateInfo? VerifyManifest(string? manifest, string? signatureB64, string? publicKeyPem = null)
    {
        if (string.IsNullOrEmpty(manifest) || string.IsNullOrEmpty(signatureB64)) return null;
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem ?? ReleasePublicKeyPem());
            if (!ecdsa.VerifyData(Encoding.UTF8.GetBytes(manifest), Convert.FromBase64String(signatureB64), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return null;
            using var d = JsonDocument.Parse(manifest);
            var r = d.RootElement;
            if (r.GetProperty("product").GetString() != "TriageKit") return null;
            var url = r.GetProperty("url").GetString()!;
            if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return null;
            var sha = r.GetProperty("sha256").GetString()!;
            if (sha.Length != 64 || !sha.All(Uri.IsHexDigit)) return null;
            return new UpdateInfo(r.GetProperty("version").GetString()!, r.GetProperty("channel").GetString()!, url, sha.ToUpperInvariant(),
                r.TryGetProperty("size", out var sz) ? sz.GetInt64() : 0, r.TryGetProperty("notes", out var n) ? n.GetString() ?? "" : "",
                r.GetProperty("published").GetDateTime().ToUniversalTime());
        }
        catch { return null; }
    }

    public static bool IsNewer(string candidate, string current) =>
        Version.TryParse(candidate, out var a) && Version.TryParse(current.Split('+', '-')[0], out var b) && a > b;

    /// <summary>Asks the server for the latest release. Returns null when there is nothing newer or the answer isn't genuine.</summary>
    public static async Task<UpdateInfo?> CheckAsync(string baseUrl, string currentVersion, string channel = "beta", CancellationToken ct = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("TriageKit");
            var json = await http.GetStringAsync($"{baseUrl.TrimEnd('/')}/v1/update?channel={(channel == "stable" ? "stable" : "beta")}", ct);
            using var d = JsonDocument.Parse(json);
            var m = d.RootElement.TryGetProperty("manifest", out var mm) && mm.ValueKind == JsonValueKind.String ? mm.GetString() : null;
            var s = d.RootElement.TryGetProperty("signature", out var ss) && ss.ValueKind == JsonValueKind.String ? ss.GetString() : null;
            var info = VerifyManifest(m, s);
            return info is not null && IsNewer(info.Version, currentVersion) ? info : null;
        }
        catch { return null; }
    }

    public const long MaxDownload = 300L * 1024 * 1024;

    /// <summary>Downloads the update and returns the bytes of TriageKit.exe, verified against the manifest hash.</summary>
    public static async Task<byte[]> DownloadAsync(UpdateInfo info, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("TriageKit");
        using var resp = await http.GetAsync(info.Url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        if (resp.RequestMessage?.RequestUri?.Scheme != Uri.UriSchemeHttps) throw new InvalidOperationException("The download was redirected to an insecure address.");
        var total = resp.Content.Headers.ContentLength ?? info.Size;
        if (total > MaxDownload) throw new InvalidOperationException("The update is unexpectedly large.");
        using var src = await resp.Content.ReadAsStreamAsync(ct);
        using var ms = new MemoryStream();
        var buf = new byte[1 << 16]; int n;
        while ((n = await src.ReadAsync(buf, ct)) > 0)
        {
            ms.Write(buf, 0, n);
            if (ms.Length > MaxDownload) throw new InvalidOperationException("The update is unexpectedly large.");
            if (total > 0) progress?.Report(Math.Min(1, ms.Length / (double)total));
        }
        return ExtractVerified(ms.ToArray(), info.Sha256);
    }

    /// <summary>Checks the hash of the downloaded file, then returns the exe (unpacked from a .zip if needed).</summary>
    public static byte[] ExtractVerified(byte[] download, string expectedSha256)
    {
        var actual = Convert.ToHexString(SHA256.HashData(download));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(expectedSha256.ToUpperInvariant())))
            throw new InvalidOperationException("The downloaded file doesn't match the published fingerprint. Nothing was changed.");
        byte[] exe = download;
        if (download.Length > 4 && download[0] == 'P' && download[1] == 'K')
        {
            using var zip = new ZipArchive(new MemoryStream(download), ZipArchiveMode.Read);
            var entry = zip.Entries.FirstOrDefault(e => e.Name.Equals("TriageKit.exe", StringComparison.OrdinalIgnoreCase)) ?? throw new InvalidOperationException("The update package has no TriageKit.exe.");
            using var es = entry.Open(); using var outp = new MemoryStream(); es.CopyTo(outp); exe = outp.ToArray();
        }
        if (exe.Length < 2 || exe[0] != 'M' || exe[1] != 'Z') throw new InvalidOperationException("The update is not a Windows program.");
        return exe;
    }

    /// <summary>
    /// Replaces the running exe: writes the new one next to it, renames the running file to .old (Windows allows
    /// renaming a running exe) and moves the new one into place. Rolls back if anything fails.
    /// </summary>
    public static void Install(string exePath, byte[] newExe)
    {
        var dir = Path.GetDirectoryName(exePath)!;
        var tmp = Path.Combine(dir, "TriageKit.exe.new");
        var old = Path.Combine(dir, "TriageKit.exe.old");
        File.WriteAllBytes(tmp, newExe);
        try { if (File.Exists(old)) File.Delete(old); } catch { old = Path.Combine(dir, $"TriageKit.exe.{DateTime.Now:yyyyMMddHHmmss}.old"); }
        File.Move(exePath, old);
        try { File.Move(tmp, exePath); }
        catch { File.Move(old, exePath); try { File.Delete(tmp); } catch { } throw; }
    }

    /// <summary>Removes the previous exe left behind by an update (it can't be deleted while it was running).</summary>
    public static void CleanupOld(string exePath)
    {
        try { foreach (var f in Directory.GetFiles(Path.GetDirectoryName(exePath)!, "TriageKit.exe*.old")) try { File.Delete(f); } catch { } } catch { }
    }
}
