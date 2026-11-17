using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TriageKit.Core.Rules;

/// <summary>
/// Signed rule packs. A pack is a folder containing rule files, a manifest.json listing every file's SHA-256,
/// and manifest.sig - an ECDSA P-256 / SHA-256 signature over manifest.json made with the publisher's private key.
/// The matching public key is compiled into TriageKit, so a tampered or unofficial pack is refused.
/// </summary>
public static class RulePack
{
    public sealed class Manifest
    {
        public string Version { get; set; } = "";
        public string Created { get; set; } = "";
        public Dictionary<string, string> Files { get; set; } = new();
    }

    public readonly record struct Result(bool Trusted, string? Version, string? Error);

    public const string ManifestName = "manifest.json";
    public const string SignatureName = "manifest.sig";

    public static string BuiltInPublicKeyPem()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("rulepack-public.pem")
                      ?? throw new InvalidOperationException("Rule pack public key missing");
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }

    /// <summary>Checks the signature and every listed file hash. Files present but not listed are ignored by loaders.</summary>
    public static Result Verify(string dir, string? publicKeyPem = null)
    {
        try
        {
            var mPath = Path.Combine(dir, ManifestName); var sPath = Path.Combine(dir, SignatureName);
            if (!File.Exists(mPath) || !File.Exists(sPath)) return new(false, null, "no signed manifest");
            var manifestBytes = File.ReadAllBytes(mPath);
            var sig = Convert.FromBase64String(File.ReadAllText(sPath).Trim());
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(publicKeyPem ?? BuiltInPublicKeyPem());
            if (!ecdsa.VerifyData(manifestBytes, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                return new(false, null, "signature does not match");
            var manifest = JsonSerializer.Deserialize<Manifest>(manifestBytes, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                           ?? throw new InvalidDataException("empty manifest");
            foreach (var (rel, hash) in manifest.Files)
            {
                if (rel.Contains("..") || Path.IsPathRooted(rel)) return new(false, null, $"invalid path in manifest: {rel}");
                var full = Path.Combine(dir, rel.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(full)) return new(false, null, $"missing file: {rel}");
                if (!string.Equals(Sha256(full), hash, StringComparison.OrdinalIgnoreCase)) return new(false, null, $"file changed after signing: {rel}");
            }
            return new(true, manifest.Version, null);
        }
        catch (Exception ex) { return new(false, null, ex.Message); }
    }

    /// <summary>Lists rule files in a pack folder that are covered by the manifest (used after Verify succeeds).</summary>
    public static HashSet<string> SignedFiles(string dir)
    {
        var m = JsonSerializer.Deserialize<Manifest>(File.ReadAllBytes(Path.Combine(dir, ManifestName)), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        return m.Files.Keys.Select(k => Path.GetFullPath(Path.Combine(dir, k.Replace('/', Path.DirectorySeparatorChar)))).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Creates manifest.json + manifest.sig for every rule file in the folder (publisher side).</summary>
    public static Manifest Sign(string dir, string privateKeyPem, string version)
    {
        var files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories)
            .Where(f => Path.GetFileName(f) is not (ManifestName or SignatureName))
            .Where(f => f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToDictionary(f => Path.GetRelativePath(dir, f).Replace('\\', '/'), Sha256);
        var manifest = new Manifest { Version = version, Created = DateTime.UtcNow.ToString("s") + "Z", Files = files };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllBytes(Path.Combine(dir, ManifestName), bytes);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privateKeyPem);
        File.WriteAllText(Path.Combine(dir, SignatureName), Convert.ToBase64String(ecdsa.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)));
        return manifest;
    }

    public static (string PrivatePem, string PublicPem) GenerateKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ecdsa.ExportPkcs8PrivateKeyPem(), ecdsa.ExportSubjectPublicKeyInfoPem());
    }

    private static string Sha256(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs));
    }
}
