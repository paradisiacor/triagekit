using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Reputation;

internal static class Http
{
    public static HttpClient Create(HttpMessageHandler? handler)
    {
        var c = handler is null ? new HttpClient() : new HttpClient(handler, false);
        c.Timeout = TimeSpan.FromSeconds(12);
        c.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("TriageKit", typeof(Http).Assembly.GetName().Version?.ToString(3) ?? "0"));
        return c;
    }
}

/// <summary>
/// Asks the PC's own Microsoft Defender to scan one file with remediation disabled (nothing is quarantined or changed).
/// Free, needs no key, and uses Microsoft's cloud intelligence. Windows only.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DefenderFileScanProvider : IReputationProvider
{
    public string Name => "Microsoft Defender";
    private static string Exe => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
    public bool IsAvailable(CheckContext ctx) => ctx.Options.ReputationDefender && File.Exists(Exe);
    public int MaxLookups(CheckContext ctx) => 40;

    public ProviderVerdict Lookup(FileIntel file, CheckContext ctx)
    {
        // -DisableRemediation: report only, take no action on detections.
        var started = DateTime.UtcNow;
        var (code, output) = Proc.Run(Exe, $"-Scan -ScanType 3 -File \"{file.Path}\" -DisableRemediation", TimeSpan.FromMinutes(2));
        var v = Parse(code, output, ctx.Indicators.GenericDetectionSuffixes);
        // MpCmdRun's text can be translated. When it signals a detection (exit code 2) but the English wording isn't
        // there, ask Defender's own detection list instead, which doesn't depend on the language.
        if (v.Verdict == Verdict.Error && code == 2 && DefenderDetections.Since(started, file.Path).FirstOrDefault() is { } hit)
        {
            v.Verdict = Verdict.Malicious; v.Label = hit; v.Detail = null;
            v.Generic = ctx.Indicators.GenericDetectionSuffixes.Any(s => hit.EndsWith(s, StringComparison.OrdinalIgnoreCase));
        }
        return v;
    }

    internal static ProviderVerdict Parse(int exitCode, string output, IEnumerable<string> genericSuffixes)
    {
        var v = new ProviderVerdict { Provider = "Microsoft Defender" };
        // Exit code 2 also means "Defender couldn't scan" (for example when Defender is switched off or replaced by
        // another antivirus). Only call a file malicious when Defender actually names a threat.
        bool named = Regex.IsMatch(output, @"found [1-9]\d* threats?", RegexOptions.IgnoreCase) || Regex.IsMatch(output, @"Threat\s*:\s*\S+", RegexOptions.IgnoreCase);
        if (named && !Regex.IsMatch(output, @"found no threats", RegexOptions.IgnoreCase))
        {
            var m = Regex.Match(output, @"Threat\s*:\s*(\S+)", RegexOptions.IgnoreCase);
            v.Verdict = Verdict.Malicious;
            v.Label = m.Success ? m.Groups[1].Value : "threat detected";
            v.Generic = genericSuffixes.Any(s => v.Label.EndsWith(s, StringComparison.OrdinalIgnoreCase));
        }
        else if (exitCode == 0) v.Verdict = Verdict.Clean;
        else { v.Verdict = Verdict.Error; v.Detail = $"MpCmdRun exit code {exitCode}"; }
        return v;
    }
}

/// <summary>Defender's detection history (root\Microsoft\Windows\Defender), independent of the Windows language.</summary>
[SupportedOSPlatform("windows")]
internal static class DefenderDetections
{
    /// <summary>Names of threats Defender detected since <paramref name="sinceUtc"/>, optionally only for one file.</summary>
    public static List<string> Since(DateTime sinceUtc, string? path = null)
    {
        const string ns = @"root\Microsoft\Windows\Defender";
        var names = new List<string>();
        foreach (var d in Platform.Wmi.Query("SELECT ThreatID, Resources, InitialDetectionTime FROM MSFT_MpThreatDetection", ns, TimeSpan.FromSeconds(20), optional: true))
        {
            DateTime when;
            try { when = System.Management.ManagementDateTimeConverter.ToDateTime(d.S("InitialDetectionTime") ?? "").ToUniversalTime(); } catch { continue; }
            if (when < sinceUtc.AddMinutes(-1)) continue;
            if (path is not null && !(d.GetValueOrDefault("Resources") is string[] res && res.Any(r => r.Contains(path, StringComparison.OrdinalIgnoreCase)))) continue;
            var id = d.GetValueOrDefault("ThreatID");
            var name = id is null ? null : Platform.Wmi.Query($"SELECT ThreatName FROM MSFT_MpThreat WHERE ThreatID = {Convert.ToInt64(id)}", ns, TimeSpan.FromSeconds(10), optional: true).FirstOrDefault()?.S("ThreatName");
            names.Add(name ?? "threat detected");
        }
        return names;
    }
}

/// <summary>
/// CIRCL hashlookup: a free public database of known files (NSRL and others). Used to recognise legitimate files
/// and avoid false alarms. A hit means "this file is known", not "this file is safe" - malicious files can be listed
/// with a KnownMalicious marker, which we honour.
/// </summary>
public sealed class CirclHashlookupProvider : IReputationProvider
{
    private readonly HttpMessageHandler? _handler;
    public CirclHashlookupProvider(HttpMessageHandler? handler = null) => _handler = handler;
    public string Name => "CIRCL hashlookup";
    public bool IsAvailable(CheckContext ctx) => ctx.Options.ReputationCircl;
    public int MaxLookups(CheckContext ctx) => 200;

    /// <summary>One request for all hashes (CIRCL's bulk endpoint). Falls back to single lookups if it fails.</summary>
    public IReadOnlyDictionary<string, ProviderVerdict>? LookupBatch(IReadOnlyList<FileIntel> files, CheckContext ctx)
    {
        if (files.Count < 2) return null;
        try
        {
            using var http = Http.Create(_handler);
            var body = System.Text.Json.JsonSerializer.Serialize(new { hashes = files.Select(f => f.SHA256).Where(h => h is not null).ToArray() });
            using var resp = http.PostAsync("https://hashlookup.circl.lu/bulk/sha256", new StringContent(body, System.Text.Encoding.UTF8, "application/json"), ctx.Cancellation).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return null;
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            var map = new Dictionary<string, ProviderVerdict>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in files) if (f.SHA256 is not null) map[f.SHA256] = new ProviderVerdict { Provider = Name, Verdict = Verdict.Unknown };
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                var sha = e.TryGetProperty("SHA-256", out var h) ? h.GetString() : null;
                if (sha is null || !map.ContainsKey(sha)) continue;
                var v = new ProviderVerdict { Provider = Name };
                if (e.TryGetProperty("KnownMalicious", out var km) && km.ValueKind == JsonValueKind.String && km.GetString()!.Length > 0) Listed(v, km.GetString()!);
                else { v.Verdict = Verdict.KnownGood; v.Detail = e.TryGetProperty("FileName", out var fn) && fn.ValueKind == JsonValueKind.String ? $"Known file: {fn.GetString()}" : "Known file"; }
                map[sha] = v;
            }
            return map;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    /// <summary>CIRCL's KnownMalicious names the sharing feed the hash appeared in (for example "malshare.com"), not a
    /// detection. Those feeds also collect harmless files that were bundled with malware, so one listing is a lead
    /// (generic), never "known malware" on its own.</summary>
    internal static void Listed(ProviderVerdict v, string feed)
    {
        v.Verdict = Verdict.Malicious; v.Generic = true; v.Label = null; v.Feed = feed;
        v.Detail = $"Listed in the {feed} malware-sharing feed (via CIRCL)";
    }

    public ProviderVerdict Lookup(FileIntel file, CheckContext ctx)
    {
        var v = new ProviderVerdict { Provider = Name };
        try
        {
            using var http = Http.Create(_handler);
            using var resp = http.GetAsync($"https://hashlookup.circl.lu/lookup/sha256/{file.SHA256}", ctx.Cancellation).GetAwaiter().GetResult();
            if (resp.StatusCode == HttpStatusCode.NotFound) { v.Verdict = Verdict.Unknown; return v; }
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            var root = doc.RootElement;
            if (root.TryGetProperty("KnownMalicious", out var km) && km.ValueKind == JsonValueKind.String && km.GetString()!.Length > 0)
                Listed(v, km.GetString()!);
            else
            {
                v.Verdict = Verdict.KnownGood;
                v.Detail = root.TryGetProperty("FileName", out var fn) && fn.ValueKind == JsonValueKind.String ? $"Known file: {fn.GetString()}" : "Known file";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { v.Verdict = Verdict.Error; v.Detail = ex.Message; }
        return v;
    }
}

/// <summary>abuse.ch MalwareBazaar: confirmed malware samples. Requires the user's own free Auth-Key.</summary>
public sealed class MalwareBazaarProvider : IReputationProvider
{
    private readonly HttpMessageHandler? _handler;
    public MalwareBazaarProvider(HttpMessageHandler? handler = null) => _handler = handler;
    public string Name => "MalwareBazaar";
    public bool IsAvailable(CheckContext ctx) => !string.IsNullOrWhiteSpace(ctx.Options.MalwareBazaarAuthKey);
    public int MaxLookups(CheckContext ctx) => 100;

    public ProviderVerdict Lookup(FileIntel file, CheckContext ctx)
    {
        var v = new ProviderVerdict { Provider = Name };
        try
        {
            using var http = Http.Create(_handler);
            using var req = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/")
            { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["query"] = "get_info", ["hash"] = file.SHA256! }) };
            req.Headers.Add("Auth-Key", ctx.Options.MalwareBazaarAuthKey);
            using var resp = http.SendAsync(req, ctx.Cancellation).GetAwaiter().GetResult();
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            var status = doc.RootElement.TryGetProperty("query_status", out var qs) ? qs.GetString() : null;
            switch (status)
            {
                case "ok":
                    v.Verdict = Verdict.Malicious;
                    var d = doc.RootElement.GetProperty("data")[0];
                    v.Label = d.TryGetProperty("signature", out var sig) && sig.ValueKind == JsonValueKind.String ? sig.GetString() : "known malware sample";
                    v.Link = $"https://bazaar.abuse.ch/sample/{file.SHA256}/";
                    v.Detail = "Confirmed malware sample in MalwareBazaar";
                    break;
                case "hash_not_found": case "no_results": v.Verdict = Verdict.Unknown; break;
                default: v.Verdict = Verdict.Error; v.Detail = $"MalwareBazaar: {status}"; break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { v.Verdict = Verdict.Error; v.Detail = ex.Message; }
        return v;
    }
}

/// <summary>VirusTotal with the user's OWN key (free tier is for personal, non-commercial use).</summary>
public sealed class VirusTotalProvider : IReputationProvider
{
    private readonly HttpMessageHandler? _handler;
    public VirusTotalProvider(HttpMessageHandler? handler = null) => _handler = handler;
    public string Name => "VirusTotal";
    public bool IsAvailable(CheckContext ctx) => !string.IsNullOrWhiteSpace(ctx.Options.VirusTotalApiKey);
    public int MaxLookups(CheckContext ctx) => ctx.Options.VirusTotalMaxLookups;
    public TimeSpan Delay(CheckContext ctx) => _handler is null ? TimeSpan.FromSeconds(ctx.Options.VirusTotalDelaySeconds) : TimeSpan.Zero;

    public ProviderVerdict Lookup(FileIntel file, CheckContext ctx)
    {
        var v = new ProviderVerdict { Provider = Name };
        try
        {
            using var http = Http.Create(_handler);
            http.DefaultRequestHeaders.Add("x-apikey", ctx.Options.VirusTotalApiKey);
            using var resp = http.GetAsync($"https://www.virustotal.com/api/v3/files/{file.SHA256}", ctx.Cancellation).GetAwaiter().GetResult();
            if (resp.StatusCode == HttpStatusCode.NotFound) { v.Verdict = Verdict.Unknown; return v; }
            if (resp.StatusCode == HttpStatusCode.TooManyRequests) { v.Verdict = Verdict.Error; v.Detail = "quota"; return v; }
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { v.Verdict = Verdict.Error; v.Detail = "key rejected"; return v; }
            resp.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            var attr = doc.RootElement.GetProperty("data").GetProperty("attributes");
            var stats = attr.GetProperty("last_analysis_stats");
            int mal = stats.GetProperty("malicious").GetInt32();
            v.Detections = mal;
            v.Link = $"https://www.virustotal.com/gui/file/{file.SHA256}";
            if (attr.TryGetProperty("popular_threat_classification", out var ptc) && ptc.TryGetProperty("suggested_threat_label", out var lbl)) v.Label = lbl.GetString();
            v.Verdict = mal >= 5 ? Verdict.Malicious : mal >= 2 ? Verdict.Suspicious : Verdict.Clean;
            v.Detail = $"{mal} engines flagged this file";
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { v.Verdict = Verdict.Error; v.Detail = ex.Message; }
        return v;
    }
}
