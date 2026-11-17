using System.Text.Json.Serialization;

namespace TriageKit.Core.Engine;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Severity { Critical = 0, High = 1, Medium = 2, Low = 3, Info = 4 }

/// <summary>A single issue the user should know about, written in plain language.</summary>
public sealed record Finding
{
    public required Severity Severity { get; init; }
    public required string Category { get; init; }
    public required string Title { get; init; }
    public string Detail { get; init; } = "";
    public string Recommendation { get; init; } = "";
    /// <summary>MITRE ATT&amp;CK technique ID when applicable, e.g. T1547.001.</summary>
    public string? Mitre { get; init; }
    /// <summary>Stable identifier for suppression/baselining in the console, e.g. persistence.run-key.</summary>
    public string? RuleId { get; init; }
    public object? Evidence { get; init; }
    /// <summary>The user accepted this finding (or excluded its path). Shown, but not counted in the score.</summary>
    public bool Accepted { get; init; }
    public string? AcceptedReason { get; init; }
    /// <summary>Module of the check that raised it ("security", "doctor", ...). Null for scanner-level notices.</summary>
    public string? Module { get; init; }
}

public sealed class ScanMeta
{
    public string KitVersion { get; set; } = "";
    public string Edition { get; set; } = "Portable";
    public string ComputerName { get; set; } = Environment.MachineName;
    public string Operator { get; set; } = $"{Environment.UserDomainName}\\{Environment.UserName}";
    public string Started { get; set; } = "";
    public int DurationSeconds { get; set; }
    public bool Elevated { get; set; }
    public bool Quick { get; set; }
    public string? CaseId { get; set; }
    public string? Technician { get; set; }
    public string RulePackVersion { get; set; } = "";
    public string SchemaVersion { get; set; } = "1.0";
    public bool Redacted { get; set; }
}

public sealed class ScanResult
{
    public required ScanMeta Meta { get; init; }
    public int Score { get; set; }
    public string Verdict { get; set; } = "";
    public Dictionary<string, int> Counts { get; set; } = new();
    public List<Finding> Findings { get; set; } = new();
    public Dictionary<string, object?> Data { get; set; } = new();
    public Dictionary<string, long> Timings { get; set; } = new();
    public bool Stopped { get; set; }
    public List<Highlight> Highlights { get; set; } = new();
    /// <summary>Per check: parts that couldn't be read (permissions, missing logs, WMI errors).</summary>
    public Dictionary<string, List<string>>? Diagnostics { get; set; }
}

/// <summary>Risk level assigned to an individual item (process, autostart, file) in data tables.</summary>
public static class Risk
{
    public const string Critical = "Critical", High = "High", Medium = "Medium", Low = "Low", Info = "Info";
    public static Severity ToSeverity(string risk) => Enum.TryParse<Severity>(risk, out var s) ? s : Severity.Info;
}
