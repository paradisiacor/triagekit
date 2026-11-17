using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using TriageKit.Core.Engine;

namespace TriageKit.Core.SafeStart;

/// <summary>
/// Safe Start › Install Watch: a "before" snapshot of everything programs use to stay on a PC or weaken it (startup
/// entries, tasks, services, drivers, Defender settings and exclusions, root certificates, browser extensions, hosts,
/// proxy, DNS, security settings, installed programs), then an "after" snapshot once something was installed or run.
/// The comparison shows exactly what changed and judges it: new findings use TriageKit's normal rules, and each added
/// item is rated by what kind of change it is. Read-only like everything else.
/// </summary>
public static class InstallWatch
{
    /// <summary>The checks a snapshot runs: fast, and together they cover the places installers change.</summary>
    public static readonly string[] SnapshotChecks =
    {
        "System posture", "Antivirus & Defender", "Autostarts & persistence", "Hidden persistence & accounts", "Root certificates",
        "Drivers", "Browser extensions", "Installed software", "Network", "Windows hardening", "Running processes", "Accounts, sessions & downloads",
    };

    /// <summary>Lists that change on their own from minute to minute; they are judged through findings only.</summary>
    private static readonly HashSet<string> Volatile = new(StringComparer.OrdinalIgnoreCase)
    {
        "Network/Established", "Network/Listening", "Running processes", "Accounts, sessions & downloads",
    };

    /// <summary>Fields that change without the item changing (timestamps, counters, live state).</summary>
    private static readonly HashSet<string> NoiseFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "Risk", "Created", "Modified", "LastUsed", "LastWrite", "LastSeen", "Time", "Pid", "ProcessId", "Started", "StartTime", "Size", "Count",
        "Cpu", "CPU", "Memory", "WorkingSet", "Uptime", "Seen", "State", "Status", "Running", "Elapsed", "Ms",
    };

    public sealed class Snapshot
    {
        public int Format { get; set; } = 1;
        public required string Machine { get; init; }
        public required string User { get; init; }
        public DateTime Taken { get; init; }
        public string AppVersion { get; init; } = "";
        public List<Finding> Findings { get; init; } = new();
        /// <summary>Category → canonical item keys → display text.</summary>
        public Dictionary<string, Dictionary<string, ItemInfo>> Inventory { get; init; } = new();
    }

    public sealed record ItemInfo(string Text, string? Risk);

    public enum Verdict { NothingWorrying, Review, Dangerous }

    public sealed record Change(string Category, string Kind, string Text, string Severity, string Why);

    public sealed class Comparison
    {
        public DateTime Before { get; init; }
        public DateTime After { get; init; }
        public Verdict Verdict { get; set; }
        public string Headline { get; set; } = "";
        public string Summary { get; set; } = "";
        public List<Finding> NewFindings { get; init; } = new();
        public List<Finding> GoneFindings { get; init; } = new();
        public List<Change> Added { get; init; } = new();
        public List<Change> Removed { get; init; } = new();
        public int Unchanged { get; set; }
        public List<string> Notes { get; init; } = new();
    }

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = false, Converters = { new JsonStringEnumConverter() } };
    /// <summary>Check data keeps its original property names, so changes read like "RealTimeProtectionEnabled = false".</summary>
    private static readonly JsonSerializerOptions DataJson = new() { Converters = { new JsonStringEnumConverter() }, MaxDepth = 64 };

    /// <summary>Builds a snapshot from a finished scan of <see cref="SnapshotChecks"/>.</summary>
    public static Snapshot FromScan(ScanResult scan, string appVersion)
    {
        var snap = new Snapshot { Machine = Environment.MachineName, User = Environment.UserName, Taken = DateTime.Now, AppVersion = appVersion,
                                  Findings = scan.Findings.Where(f => f.Category != "Collector").ToList() };
        foreach (var (check, data) in scan.Data)
        {
            if (Volatile.Contains(check) || data is null) continue;
            JsonNode? node;
            try { node = JsonSerializer.SerializeToNode(data, DataJson); } catch { continue; }
            Collect(snap.Inventory, check, check, node, 0);
        }
        return snap;
    }

    private static void Collect(Dictionary<string, Dictionary<string, ItemInfo>> inv, string check, string path, JsonNode? node, int depth)
    {
        if (node is null || depth > 3 || Volatile.Contains(path)) return;
        switch (node)
        {
            case JsonArray arr:
                var cat = Category(path);
                foreach (var el in arr)
                {
                    if (el is JsonObject o)
                    {
                        var (key, text, risk) = Canonical(o);
                        if (key.Length > 2) Bucket(inv, cat).TryAdd(key, new ItemInfo(text, risk));
                    }
                    else if (el is JsonValue v && v.ToString() is { Length: > 0 } s) Bucket(inv, cat).TryAdd(s, new ItemInfo(s, null));
                }
                break;
            case JsonObject obj:
                foreach (var (k, v) in obj)
                {
                    if (v is JsonArray or JsonObject) Collect(inv, check, $"{path}/{k}", v, depth + 1);
                    else if (depth <= 1 && v is JsonValue val && !NoiseFields.Contains(k) && Setting(path, k))
                        Bucket(inv, "Setting").TryAdd($"{path}/{k}", new ItemInfo($"{Label(path)}: {k} = {val}", null));
                }
                break;
        }
    }

    /// <summary>Single values worth comparing: security switches (Defender, posture, hardening). Counters aren't.</summary>
    private static bool Setting(string path, string key) =>
        (path.StartsWith("Antivirus & Defender", StringComparison.OrdinalIgnoreCase) || path.StartsWith("System posture", StringComparison.OrdinalIgnoreCase) || path.StartsWith("Windows hardening", StringComparison.OrdinalIgnoreCase))
        && !key.Contains("Version", StringComparison.OrdinalIgnoreCase) && !key.Contains("Age", StringComparison.OrdinalIgnoreCase) && !key.Contains("Updated", StringComparison.OrdinalIgnoreCase)
        && !key.Contains("Date", StringComparison.OrdinalIgnoreCase) && !key.EndsWith("Count", StringComparison.OrdinalIgnoreCase) && !key.Contains("Last", StringComparison.OrdinalIgnoreCase);

    private static Dictionary<string, ItemInfo> Bucket(Dictionary<string, Dictionary<string, ItemInfo>> inv, string cat)
    {
        if (!inv.TryGetValue(cat, out var b)) inv[cat] = b = new(StringComparer.OrdinalIgnoreCase);
        return b;
    }

    internal static (string Key, string Text, string? Risk) Canonical(JsonObject o)
    {
        var parts = o.Where(kv => !NoiseFields.Contains(kv.Key) && kv.Value is not JsonArray and not JsonObject && kv.Value is not null)
                     .OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={kv.Value}");
        var key = string.Join("|", parts);
        string? Get(string k) => o.FirstOrDefault(kv => kv.Key.Equals(k, StringComparison.OrdinalIgnoreCase)).Value?.ToString();
        var main = Get("Command") ?? Get("Target") ?? Get("Path") ?? Get("Value") ?? Get("Subject") ?? Get("Display") ?? Get("DisplayName") ?? Get("Name") ?? key;
        var name = Get("Name") ?? Get("Location") ?? Get("Type");
        var text = name is not null && !main.Contains(name, StringComparison.OrdinalIgnoreCase) ? $"{name}: {main}" : main;
        return (key, text.Length > 400 ? text[..400] + "…" : text, Get("Risk"));
    }

    /// <summary>Friendly category for a data list, e.g. "Autostarts & persistence/Entries" → "Startup entry".</summary>
    internal static string Category(string path) => path switch
    {
        _ when path.EndsWith("/WmiSubscriptions", StringComparison.OrdinalIgnoreCase) => "WMI event subscription",
        _ when path.StartsWith("Autostarts & persistence", StringComparison.OrdinalIgnoreCase) => "Startup entry, task or service",
        _ when path.StartsWith("Hidden persistence", StringComparison.OrdinalIgnoreCase) && path.EndsWith("/Accounts", StringComparison.OrdinalIgnoreCase) => "User account",
        _ when path.StartsWith("Hidden persistence", StringComparison.OrdinalIgnoreCase) => "Hidden startup hook",
        _ when path.StartsWith("Root certificates", StringComparison.OrdinalIgnoreCase) => "Trusted root certificate",
        _ when path.StartsWith("Drivers", StringComparison.OrdinalIgnoreCase) => "Driver",
        _ when path.StartsWith("Antivirus & Defender", StringComparison.OrdinalIgnoreCase) && path.Contains("Exclusion", StringComparison.OrdinalIgnoreCase) => "Defender exclusion",
        _ when path.StartsWith("Antivirus & Defender", StringComparison.OrdinalIgnoreCase) && path.Contains("Antivirus", StringComparison.OrdinalIgnoreCase) => "Antivirus product",
        _ when path.StartsWith("Browser extensions", StringComparison.OrdinalIgnoreCase) => "Browser extension",
        _ when path.StartsWith("Installed software", StringComparison.OrdinalIgnoreCase) && path.Contains("Remote", StringComparison.OrdinalIgnoreCase) => "Remote-access tool",
        _ when path.StartsWith("Installed software", StringComparison.OrdinalIgnoreCase) => "Installed program",
        _ when path.EndsWith("/HostsEntries", StringComparison.OrdinalIgnoreCase) => "hosts file entry",
        _ when path.EndsWith("/Proxies", StringComparison.OrdinalIgnoreCase) => "Proxy setting",
        _ when path.EndsWith("/DnsServers", StringComparison.OrdinalIgnoreCase) => "DNS server",
        _ => Label(path),
    };

    private static string Label(string path) => path.Replace("/", " › ");

    /// <summary>How worrying a newly added item is, by kind (the item's own Risk rating can raise it).</summary>
    internal static (Severity Severity, string Why) Judge(string category, string? itemRisk)
    {
        var (sev, why) = category switch
        {
            "Defender exclusion" => (Severity.High, "Microsoft Defender now skips this location. Installers almost never need this; malware always wants it."),
            "Trusted root certificate" => (Severity.High, "A new root certificate lets its owner impersonate any website to this PC, including banks."),
            "WMI event subscription" => (Severity.High, "WMI subscriptions run code invisibly; they're a classic hiding place for malware."),
            "Hidden startup hook" => (Severity.High, "This hooks into Windows itself (logon, security packages or system DLL loading)."),
            "User account" => (Severity.High, "A new user account appeared."),
            "hosts file entry" => (Severity.Medium, "The hosts file now sends a website name somewhere else. Cracks use this to block activation; malware to redirect logins."),
            "Proxy setting" => (Severity.Medium, "Web traffic now goes through a proxy, which can read and change it."),
            "DNS server" => (Severity.Medium, "The PC now asks a different server where websites are."),
            "Remote-access tool" => (Severity.Medium, "A remote-control program was added. If you didn't install one, someone else could control this PC."),
            "Driver" => (Severity.Low, "A new driver runs inside Windows' core. Games' anti-cheat and hardware tools add these legitimately."),
            "Browser extension" => (Severity.Low, "A new browser extension appeared without you adding it from the store."),
            "Startup entry, task or service" => (Severity.Low, "This now starts automatically."),
            "Antivirus product" => (Severity.Low, "A different antivirus product registered itself."),
            "Setting" => (Severity.Low, "A security setting changed."),
            "Installed program" => (Severity.Info, "Installed."),
            _ => (Severity.Info, "Added."),
        };
        var risk = itemRisk switch { "Critical" => Severity.Critical, "High" => Severity.High, "Medium" => Severity.Medium, _ => Severity.Info };
        if (risk < sev) sev = risk;   // Severity: Critical = 0 … Info = 4
        return (sev, why);
    }

    public static Comparison Compare(Snapshot before, Snapshot after)
    {
        var c = new Comparison { Before = before.Taken, After = after.Taken };
        if (!before.Machine.Equals(after.Machine, StringComparison.OrdinalIgnoreCase)) c.Notes.Add($"The \"before\" snapshot was taken on {before.Machine}, not on this PC.");
        var beforeKeys = before.Findings.Select(Fingerprint.Of).ToHashSet();
        var afterKeys = after.Findings.Select(Fingerprint.Of).ToHashSet();
        c.NewFindings.AddRange(after.Findings.Where(f => !beforeKeys.Contains(Fingerprint.Of(f))).OrderByDescending(f => f.Severity));
        c.GoneFindings.AddRange(before.Findings.Where(f => !afterKeys.Contains(Fingerprint.Of(f))).OrderByDescending(f => f.Severity));

        foreach (var cat in before.Inventory.Keys.Union(after.Inventory.Keys))
        {
            var b = before.Inventory.GetValueOrDefault(cat) ?? new();
            var a = after.Inventory.GetValueOrDefault(cat) ?? new();
            if (cat == "Setting")
            {
                // A changed value shows up as one key with a different text: report it as "changed", not add + remove.
                foreach (var (k, v) in a)
                    if (b.TryGetValue(k, out var old) && old.Text != v.Text)
                    {
                        var weaker = v.Text.EndsWith("= false", StringComparison.OrdinalIgnoreCase) && old.Text.EndsWith("= true", StringComparison.OrdinalIgnoreCase);
                        c.Added.Add(new Change("Setting", "Changed", $"{old.Text} → {v.Text[(v.Text.LastIndexOf('=') + 1)..].Trim()}", (weaker ? Severity.High : Severity.Low).ToString(),
                                               weaker ? "A protection was switched off." : "A security setting changed."));
                    }
                continue;
            }
            foreach (var (k, v) in a)
                if (!b.ContainsKey(k)) { var (sev, why) = Judge(cat, v.Risk); c.Added.Add(new Change(cat, "Added", v.Text, sev.ToString(), why)); }
                else c.Unchanged++;
            foreach (var (k, v) in b)
                if (!a.ContainsKey(k)) c.Removed.Add(new Change(cat, "Removed", v.Text, "Info", "Removed."));
        }
        c.Added.Sort((x, y) => DownloadCheck.Rank(y.Severity).CompareTo(DownloadCheck.Rank(x.Severity)));

        var worst = c.NewFindings.Select(f => f.Severity).Concat(c.Added.Select(x => Enum.Parse<Severity>(x.Severity))).DefaultIfEmpty(Severity.Info).Min();
        c.Verdict = worst <= Severity.High ? Verdict.Dangerous : worst == Severity.Medium ? Verdict.Review : Verdict.NothingWorrying;
        int changes = c.Added.Count + c.NewFindings.Count;
        (c.Headline, c.Summary) = c.Verdict switch
        {
            Verdict.Dangerous => ("Dangerous changes found.", "What was installed changed things that malware changes. Look at the red items below. If you don't recognise them, uninstall the program, run a full check and change important passwords from another device."),
            Verdict.Review => ("Some changes need a look.", "Nothing clearly malicious, but some changes are worth checking. Make sure you recognise each one."),
            _ => changes == 0 ? ("Nothing changed.", "No startup entries, settings, certificates, extensions or programs were added.")
                              : ("Nothing worrying changed.", "The changes below are the kind normal programs make."),
        };
        return c;
    }
}

/// <summary>Stable identity of a finding for "new since" comparisons (numbers in measurements don't count).</summary>
public static class Fingerprint
{
    public static string Of(Finding f) => $"{f.RuleId}|{f.Severity}|{System.Text.RegularExpressions.Regex.Replace(f.Title, @"\d+", "#")}";
}
