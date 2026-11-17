using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace TriageKit.Core.Intel;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SignatureStatus { Unknown, Valid, NotSigned, HashMismatch, Untrusted, Expired, Revoked, Error, NotFound }

public sealed class FileIntel
{
    public required string Path { get; init; }
    public bool Exists { get; set; }
    public string? SHA256 { get; set; }
    public long? Size { get; set; }
    public string? Created { get; set; }
    public string? Modified { get; set; }
    public SignatureStatus SignatureStatus { get; set; } = SignatureStatus.Unknown;
    public string? Signer { get; set; }
    /// <summary>"Embedded" or "Catalog" (Windows system files are usually catalog-signed).</summary>
    public string? SignatureType { get; set; }
    public string? Company { get; set; }
    public string? Product { get; set; }
    public string? Description { get; set; }
    public bool Suspicious { get; set; }
    [JsonIgnore] public long? Mtime { get; set; }

    [JsonIgnore] public bool IsSigned => SignatureStatus == SignatureStatus.Valid;
    /// <summary>Signed by Microsoft: the name starts with "Microsoft" and the certificate was issued by a Microsoft CA
    /// (Authenticode marks other certificates that merely call themselves Microsoft).</summary>
    [JsonIgnore] public bool IsMicrosoft => IsSigned && (Signer?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false)
                                            && !(Signer?.Contains(Authenticode.NotMicrosoftIssued, StringComparison.Ordinal) ?? false);
}

/// <summary>Thread-safe cache: each file is hashed and signature-checked once per scan.</summary>
public sealed class FileIntelService
{
    private readonly ConcurrentDictionary<string, FileIntel> _cache = new(StringComparer.OrdinalIgnoreCase);
    private const long MaxHashBytes = 300L * 1024 * 1024;

    public IEnumerable<FileIntel> All => _cache.Values;

    /// <summary>Test hook: pre-populate the cache.</summary>
    internal void Seed(FileIntel f) => _cache[f.Path] = f;

    // ------------------------------------------------------------------ persistent cache (between scans)
    // Only files under folders that need administrator rights to change are cached, and the cache file itself is
    // kept in an admin-only folder. A file in AppData, Downloads, Temp etc. is always re-hashed and re-verified.
    private sealed record Cached(long Size, long Mtime, string Sha256, SignatureStatus Sig, string? Signer, string? Type, string? Company, string? Product, string? Description, DateTime Checked);
    private ConcurrentDictionary<string, Cached> _persist = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan CacheMaxAge = TimeSpan.FromDays(7);
    public int CacheHits;

    public static bool IsProtectedLocation(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        string[] roots = { Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) };
        string full; try { full = System.IO.Path.GetFullPath(path); } catch { return false; }
        // Folders inside Windows that ordinary users can write to.
        if (full.Contains(@"\Temp", StringComparison.OrdinalIgnoreCase) || full.Contains(@"\Tasks", StringComparison.OrdinalIgnoreCase) || full.Contains(@"\spool", StringComparison.OrdinalIgnoreCase) || full.Contains(@"\Debug", StringComparison.OrdinalIgnoreCase)) return false;
        return roots.Any(r => !string.IsNullOrEmpty(r) && full.StartsWith(r.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
    }

    public void LoadCache(string file)
    {
        try
        {
            if (!File.Exists(file)) return;
            var d = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, Cached>>(File.ReadAllText(file));
            if (d is null) return;
            _persist = new(d.Where(kv => DateTime.UtcNow - kv.Value.Checked < CacheMaxAge && IsProtectedLocation(kv.Key)), StringComparer.OrdinalIgnoreCase);
        }
        catch { _persist = new(StringComparer.OrdinalIgnoreCase); }
    }

    public void SaveCache(string file)
    {
        try
        {
            foreach (var f in _cache.Values)
            {
                if (!f.Exists || f.SHA256 is null || f.Size is null || f.Mtime is null || !IsProtectedLocation(f.Path)) continue;
                if (f.SignatureStatus is SignatureStatus.Unknown or SignatureStatus.Error) continue;
                if (_persist.TryGetValue(f.Path, out var old) && old.Mtime == f.Mtime && old.Size == f.Size) continue;   // keep original check time
                _persist[f.Path] = new Cached(f.Size.Value, f.Mtime.Value, f.SHA256, f.SignatureStatus, f.Signer, f.SignatureType, f.Company, f.Product, f.Description, DateTime.UtcNow);
            }
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(file)!);
            var tmp = file + ".tmp";
            File.WriteAllText(tmp, System.Text.Json.JsonSerializer.Serialize(_persist.Take(20000).ToDictionary(kv => kv.Key, kv => kv.Value)));
            File.Move(tmp, file, true);
        }
        catch { }
    }

    public FileIntel? Get(string? path, bool hash = true)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        path = path.Trim().Trim('"');
        var fi = _cache.GetOrAdd(path, p => FromPersist(p) ?? Inspect(p, hash));
        if (hash && fi.SHA256 is null && fi.Exists && fi.Size <= MaxHashBytes)
            try { fi.SHA256 = Sha256(path); } catch { }
        return fi;
    }

    private FileIntel? FromPersist(string path)
    {
        if (_persist.IsEmpty || !_persist.TryGetValue(path, out var c)) return null;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length != c.Size || info.LastWriteTimeUtc.Ticks != c.Mtime) return null;
            Interlocked.Increment(ref CacheHits);
            return new FileIntel
            {
                Path = path, Exists = true, Size = c.Size, Mtime = c.Mtime, SHA256 = c.Sha256, SignatureStatus = c.Sig, Signer = c.Signer, SignatureType = c.Type,
                Company = c.Company, Product = c.Product, Description = c.Description, Suspicious = PathHeuristics.IsSuspicious(path),
                Created = info.CreationTime.ToString("s"), Modified = info.LastWriteTime.ToString("s"),
            };
        }
        catch { return null; }
    }

    private static FileIntel Inspect(string path, bool hash)
    {
        var fi = new FileIntel { Path = path, Suspicious = PathHeuristics.IsSuspicious(path) };
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) { fi.SignatureStatus = SignatureStatus.NotFound; return fi; }
            fi.Exists = true;
            fi.Size = info.Length;
            fi.Created = info.CreationTime.ToString("s");
            fi.Modified = info.LastWriteTime.ToString("s");
            fi.Mtime = info.LastWriteTimeUtc.Ticks;
            try
            {
                var v = FileVersionInfo.GetVersionInfo(path);
                fi.Company = Clean(v.CompanyName); fi.Product = Clean(v.ProductName); fi.Description = Clean(v.FileDescription);
            } catch { }
            if (hash && info.Length <= MaxHashBytes) fi.SHA256 = Sha256(path);
            if (OperatingSystem.IsWindows())
            {
                var sig = Authenticode.Verify(path);
                fi.SignatureStatus = sig.Status; fi.Signer = sig.Signer; fi.SignatureType = sig.Type;
            }
        }
        catch (Exception) { fi.SignatureStatus = SignatureStatus.Error; }
        return fi;
    }

    private static string? Clean(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    public static string Sha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
