using System.Reflection;
using System.Text.Json;

namespace TriageKit.Core.Rules;

/// <summary>
/// Detection content kept separate from code ("rule pack"). The built-in pack is embedded in the binary;
/// a newer signed pack can be dropped next to the executable (rules\indicators.json) without a new release.
/// </summary>
public sealed class Indicators
{
    public string Version { get; set; } = "builtin";
    public List<string> RatPorts { get; set; } = new();
    public List<string> MinerProcessPatterns { get; set; } = new();
    public List<RemoteTool> RemoteAccessTools { get; set; } = new();
    public List<string> DualUseToolPatterns { get; set; } = new();
    public List<string> HostsSensitiveDomains { get; set; } = new();
    public Dictionary<string, List<string>> SystemProcessLocations { get; set; } = new();
    public List<string> GenericDetectionSuffixes { get; set; } = new();
    public List<string> SuspiciousPowerShellPatterns { get; set; } = new();
    public List<string> BrowserStoreUpdateUrls { get; set; } = new();
    public List<string> KnownGoodWmiConsumers { get; set; } = new();

    public sealed class RemoteTool { public string Name { get; set; } = ""; public string Pattern { get; set; } = ""; public string Process { get; set; } = ""; }

    private static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public static Indicators LoadBuiltIn()
    {
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("indicators.json")
                      ?? throw new InvalidOperationException("Built-in rule pack missing");
        return JsonSerializer.Deserialize<Indicators>(s, Json)!;
    }

    /// <summary>Uses an external pack if present and valid, otherwise the built-in one.</summary>
    public static Indicators Load(string? externalPath, Action<string>? log = null)
    {
        var builtIn = LoadBuiltIn();
        if (string.IsNullOrEmpty(externalPath) || !File.Exists(externalPath)) return builtIn;
        try
        {
            var ext = JsonSerializer.Deserialize<Indicators>(File.ReadAllText(externalPath), Json);
            if (ext is null || ext.RatPorts.Count == 0) { log?.Invoke("External rule pack invalid; using built-in."); return builtIn; }
            return ext;
        }
        catch (Exception ex) { log?.Invoke($"External rule pack unreadable ({ex.Message}); using built-in."); return builtIn; }
    }
}
