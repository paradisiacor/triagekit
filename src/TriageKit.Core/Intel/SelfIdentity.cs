using System.Security.Cryptography;

namespace TriageKit.Core.Intel;

/// <summary>
/// Recognises TriageKit's own files so the scanner never reports itself (or an older TriageKit release lying in
/// Downloads) as suspicious. Matching is by exact path of the running exe or by SHA-256 of published releases -
/// never by file name, which malware could copy.
/// </summary>
public static class SelfIdentity
{
    private static readonly HashSet<string> KnownReleaseHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        // v0.1 PowerShell kit
        "4b28380a67dfbdc2d6caf458a979da16e3a12e98de75aff0a817e6229976c688", // TriageKit.ps1
        "73092a4b984acc9f56a6c569e16a1c52e0faadb191614988de0608a3bdb5769f", // lib\Checks.ps1 (contains detection strings)
        "01d13f87f963d83bcc13c93c896d56a34d003d3a8a24a3f39ac14537619042a7", // lib\Common.ps1
        "e43e9e7496b0a21c01e26281cf36697a714d23fcf9dee280d023c052e8985508", // lib\Report.ps1
        "0fdef272df31a235ea22bad69bc335ebbfeca45cc43dd4d5669549946a9e29cb", // Start.cmd
        // TriageKit.exe releases
        "ae78c57722c51966762acb057497d1d4e0916d33e0d9b78b7eef0d208b238483", // 0.2.0
        "b2dc13079ca7566aa1626b764f626800f330a24f5e1a71a9d7204850575c4af2", // 0.3.0
        "adc77465988e2107c57b701bf3dd5ebb011d62e576f7bd1b357025bea0054eff", // 0.5.0
        "838213ef5aafd2a141d3f620d6aa70f980f8d5e9dbe12d37a31b8a7a5b7decdc", // 0.6.0
    };

    private static readonly string? ProcessPath = SafeFull(Environment.ProcessPath);

    public static bool IsSelf(string? path, string? sha256 = null, bool hashIfUnknown = false)
    {
        if (string.IsNullOrEmpty(path)) return false;
        if (ProcessPath is not null && string.Equals(SafeFull(path), ProcessPath, StringComparison.OrdinalIgnoreCase)) return true;
        if (InOwnExtractionDir(path)) return true;
        if (sha256 is null && hashIfUnknown) sha256 = HashIfSmall(path);
        return sha256 is not null && KnownReleaseHashes.Contains(sha256);
    }

    // The single-file exe unpacks its native libraries (SQLite, WebView2 loader) to %TEMP%\.net\TriageKit\<id>\.
    private static readonly string[] ExtractionRoots = new[]
    {
        Environment.GetEnvironmentVariable("DOTNET_BUNDLE_EXTRACT_BASE_DIR"),
        Path.Combine(Path.GetTempPath(), ".net"),
    }.Where(d => !string.IsNullOrEmpty(d)).Select(d => Path.Combine(SafeFull(d!) ?? d!, "TriageKit") + Path.DirectorySeparatorChar).ToArray();

    // The folder name under .net\TriageKit\ is a per-build id. Temp paths can come back in short 8.3 form
    // (C:\Users\WDAGU~1\...), so match on that unique folder rather than on the whole temp path.
    private static readonly string? ExtractionId = FindExtractionId();

    private static string? FindExtractionId()
    {
        try
        {
            foreach (System.Diagnostics.ProcessModule m in System.Diagnostics.Process.GetCurrentProcess().Modules)
            {
                var mm = System.Text.RegularExpressions.Regex.Match(m.FileName ?? "", @"[\\/]\.net[\\/]TriageKit[\\/]([^\\/]+)[\\/]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (mm.Success) return mm.Groups[1].Value;
            }
        }
        catch { }
        return null;
    }

    private static bool InOwnExtractionDir(string path)
    {
        var full = SafeFull(path);
        if (full is null) return false;
        if (ExtractionRoots.Any(r => full.StartsWith(r, StringComparison.OrdinalIgnoreCase))) return true;
        return ExtractionId is not null && System.Text.RegularExpressions.Regex.IsMatch(full, @"[\\/]\.net[\\/]TriageKit[\\/]" + System.Text.RegularExpressions.Regex.Escape(ExtractionId) + @"[\\/]", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    internal static bool IsKnownReleaseHash(string sha256) => KnownReleaseHashes.Contains(sha256);

    private static string? HashIfSmall(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length > 120_000_000) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(fs));
        }
        catch { return null; }
    }

    private static string? SafeFull(string? p) { try { return p is null ? null : Path.GetFullPath(p); } catch { return p; } }
}
