using System.Text.Json;
using TriageKit.Core.Agent;

namespace TriageKit.Core.Engine;

/// <summary>
/// One thing the user said "this is fine" about. Exactly one of the match fields is normally set:
/// Fingerprint (this one finding), RuleId (every finding of a rule), Path (a file or folder: excluded from file scans
/// and findings that mention it are accepted) or Sha256 (one exact file, wherever it is).
/// </summary>
public sealed class Suppression
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..12];
    public string? Fingerprint { get; set; }
    public string? RuleId { get; set; }
    public string? Path { get; set; }
    public string? Sha256 { get; set; }
    /// <summary>What the user saw when they accepted it (for the list in Settings).</summary>
    public string Title { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTime Created { get; set; } = DateTime.UtcNow;
    /// <summary>Optional: comes back automatically after this date.</summary>
    public DateTime? Until { get; set; }

    public string Kind => Fingerprint is not null ? "finding" : RuleId is not null ? "rule" : Path is not null ? "path" : Sha256 is not null ? "file" : "none";
}

public sealed class SuppressionSet
{
    public List<Suppression> Items { get; set; } = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static SuppressionSet Load(string? path)
    {
        try
        {
            if (path is not null && File.Exists(path))
            {
                var set = JsonSerializer.Deserialize<SuppressionSet>(File.ReadAllText(path)) ?? new();
                set.Items.RemoveAll(i => i.Kind == "none");
                return set;
            }
        }
        catch { /* a damaged file must never stop a scan; treat as empty */ }
        return new();
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, true);
    }

    private IEnumerable<Suppression> Active => Items.Where(i => i.Until is null || i.Until > DateTime.UtcNow);

    private static string Norm(string p)
    {
        p = p.Trim().Trim('"');
        if (OperatingSystem.IsWindows()) try { p = System.IO.Path.GetFullPath(p); } catch { }
        return p.Replace('/', '\\').TrimEnd('\\');
    }

    /// <summary>True when a file is inside an excluded folder (or is an excluded file).</summary>
    public bool ExcludesPath(string path)
    {
        var n = Norm(path);
        foreach (var s in Active)
        {
            if (s.Path is null) continue;
            var e = Norm(s.Path);
            if (n.Equals(e, StringComparison.OrdinalIgnoreCase) || n.StartsWith(e + "\\", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// Marks matching findings as accepted. Safety rule: a Critical finding is only accepted by its exact fingerprint,
    /// never by a rule-, path- or hash-wide exclusion, so a planted exclusion can't silently hide something new.
    /// </summary>
    public List<Finding> Apply(IEnumerable<Finding> findings)
    {
        var active = Active.ToList();
        if (active.Count == 0) return findings.ToList();
        bool wantText = active.Any(s => s.Path is not null || s.Sha256 is not null);
        var result = new List<Finding>();
        foreach (var f in findings)
        {
            Suppression? hit = null;
            var fp = FindingFingerprint.Of(f);
            string? text = null;
            List<string>? paths = null;
            foreach (var s in active)
            {
                if (s.Fingerprint is not null) { if (s.Fingerprint == fp) { hit = s; break; } continue; }
                if (f.Severity == Severity.Critical) continue;
                if (s.RuleId is not null)
                {
                    bool m = s.RuleId.EndsWith('*') ? (f.RuleId ?? "").StartsWith(s.RuleId[..^1], StringComparison.OrdinalIgnoreCase) : string.Equals(s.RuleId, f.RuleId, StringComparison.OrdinalIgnoreCase);
                    if (m) { hit = s; break; }
                    continue;
                }
                if (!wantText) continue;
                paths ??= PathsOf(f);
                if (s.Path is not null)
                {
                    var e = Norm(s.Path);
                    if (paths.Any(p => p.Equals(e, StringComparison.OrdinalIgnoreCase) || p.StartsWith(e + "\\", StringComparison.OrdinalIgnoreCase))) { hit = s; break; }
                    continue;
                }
                text ??= f.Title + "\n" + f.Detail + "\n" + (f.Evidence is null ? "" : SafeJson(f.Evidence));
                if (s.Sha256 is not null && System.Text.RegularExpressions.Regex.IsMatch(text, @"(?<![0-9A-Fa-f])" + s.Sha256 + "(?![0-9A-Fa-f])", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) { hit = s; break; }
            }
            result.Add(hit is null || f.Severity == Severity.Info ? f : f with { Accepted = true, AcceptedReason = string.IsNullOrWhiteSpace(hit.Reason) ? "Accepted by you" : hit.Reason });
        }
        return result;
    }

    private static readonly System.Text.RegularExpressions.Regex PathKey = new(@"(?i)(path|file|target|image|location|binary|folder)$");
    private static readonly System.Text.RegularExpressions.Regex FullPath = new(@"^(?:[A-Za-z]:\\|\\\\|/)[^\r\n""<>|?*]+$");

    /// <summary>
    /// The file paths a finding is about: path-like evidence fields and detail lines that are a full path by themselves.
    /// A path merely mentioned inside a command line doesn't count.
    /// </summary>
    private static List<string> PathsOf(Finding f)
    {
        var list = new List<string>();
        foreach (var line in (f.Detail ?? "").Split('\n')) { var t = line.Trim().Split(" » ")[0]; if (FullPath.IsMatch(t)) list.Add(Norm(t)); }
        if (f.Evidence is not null)
        {
            try
            {
                using var d = JsonDocument.Parse(JsonSerializer.Serialize(f.Evidence));
                void Walk(JsonElement e, string? key)
                {
                    switch (e.ValueKind)
                    {
                        case JsonValueKind.Object: foreach (var p in e.EnumerateObject()) Walk(p.Value, p.Name); break;
                        case JsonValueKind.Array: foreach (var x in e.EnumerateArray()) Walk(x, key); break;
                        case JsonValueKind.String:
                            var v = e.GetString()!.Trim().Trim('"');
                            if (key is not null && PathKey.IsMatch(key) && FullPath.IsMatch(v)) list.Add(Norm(v.Split(" » ")[0]));
                            break;
                    }
                }
                Walk(d.RootElement, null);
            }
            catch { }
        }
        return list;
    }

    private static string SafeJson(object o)
    {
        try { return JsonSerializer.Serialize(o).Replace("\\\\", "\\"); } catch { return ""; }
    }
}
