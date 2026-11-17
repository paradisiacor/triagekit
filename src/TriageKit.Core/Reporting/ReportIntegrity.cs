using System.Security.Cryptography;

namespace TriageKit.Core.Reporting;

/// <summary>Checks a report file against the manifest.sha256 written next to it at scan time.</summary>
public static class ReportIntegrity
{
    public static bool Matches(string reportPath)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(reportPath))!;
            var manifest = Path.Combine(dir, "manifest.sha256");
            if (!File.Exists(manifest)) return false;
            var name = Path.GetFileName(reportPath);
            var line = File.ReadLines(manifest).FirstOrDefault(l => l.EndsWith("  " + name, StringComparison.OrdinalIgnoreCase));
            if (line is null) return false;
            using var f = File.OpenRead(reportPath);
            return string.Equals(line[..64], Convert.ToHexString(SHA256.HashData(f)), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
