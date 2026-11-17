using System.Text.Json.Serialization;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;

namespace TriageKit.Core.Reputation;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Verdict { Unknown, KnownGood, Clean, Suspicious, Malicious, Error }

/// <summary>One provider's opinion about one file.</summary>
public sealed class ProviderVerdict
{
    public required string Provider { get; init; }
    public Verdict Verdict { get; set; }
    /// <summary>Malware family / detection name, if any.</summary>
    public string? Label { get; set; }
    /// <summary>Number of engines that flagged the file (VirusTotal-style providers).</summary>
    public int? Detections { get; set; }
    public string? Detail { get; set; }
    public string? Link { get; set; }
    /// <summary>True for heuristic / machine-learning / reputation detections that are prone to false positives.</summary>
    public bool Generic { get; set; }
    /// <summary>Set when the verdict only means "this hash appeared in a malware-sharing feed".</summary>
    public string? Feed { get; set; }
}

/// <summary>
/// A source of file reputation. Providers must be safe to run on a compromised machine:
/// hash lookups only, never uploading file contents.
/// </summary>
public interface IReputationProvider
{
    string Name { get; }
    /// <summary>Whether the provider is usable in this scan (e.g. key configured, tool present).</summary>
    bool IsAvailable(CheckContext ctx);
    /// <summary>Maximum number of lookups per scan (rate limits / time budget).</summary>
    int MaxLookups(CheckContext ctx);
    /// <summary>Pause between lookups (free API rate limits).</summary>
    TimeSpan Delay(CheckContext ctx) => TimeSpan.Zero;
    ProviderVerdict Lookup(FileIntel file, CheckContext ctx);
    /// <summary>Optional batch lookup; return null to fall back to one-by-one.</summary>
    IReadOnlyDictionary<string, ProviderVerdict>? LookupBatch(IReadOnlyList<FileIntel> files, CheckContext ctx) => null;
}

public sealed class ReputationSummary
{
    public required string Path { get; init; }
    public string? SHA256 { get; init; }
    public bool Signed { get; init; }
    public string? Signer { get; init; }
    public Verdict Overall { get; set; }
    public string? Label { get; set; }
    public List<ProviderVerdict> Sources { get; } = new();
}

/// <summary>Combines provider verdicts. Pure logic, unit tested.</summary>
public static class VerdictAggregator
{
    public static (Verdict Overall, string? Label) Combine(IEnumerable<ProviderVerdict> sources)
    {
        var list = sources.Where(s => s.Verdict != Verdict.Error).ToList();
        var malicious = list.Where(s => s.Verdict == Verdict.Malicious).ToList();
        // A specific (non-generic) malicious verdict from any source wins.
        var named = malicious.FirstOrDefault(s => !s.Generic);
        if (named is not null) return (Verdict.Malicious, named.Label);
        // Generic-only detections are downgraded to Suspicious unless corroborated by two or more sources.
        if (malicious.Count >= 2) return (Verdict.Malicious, malicious.First().Label);
        if (malicious.Count == 1) return (Verdict.Suspicious, malicious[0].Label);
        if (list.Any(s => s.Verdict == Verdict.Suspicious)) return (Verdict.Suspicious, list.First(s => s.Verdict == Verdict.Suspicious).Label);
        if (list.Any(s => s.Verdict == Verdict.KnownGood)) return (Verdict.KnownGood, null);
        if (list.Any(s => s.Verdict == Verdict.Clean)) return (Verdict.Clean, null);
        return (Verdict.Unknown, null);
    }
}
