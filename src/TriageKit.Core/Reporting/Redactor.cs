using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TriageKit.Core.Engine;

namespace TriageKit.Core.Reporting;

/// <summary>
/// Makes a copy of a scan that is safe to send to a helper or post in a forum: no PC name, user names, e-mail
/// addresses, IP/MAC addresses, account SIDs, device IDs or serial numbers, and without the raw collector data.
/// Findings, severities and advice stay intact, so the report is still useful.
/// </summary>
public static class Redactor
{
    private static readonly Regex UserPath = new(@"(?i)(\\Users\\|/home/|/Users/)([^\\/""\s:*?<>|]+)", RegexOptions.Compiled);
    private static readonly Regex Email = new(@"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);
    private static readonly Regex Ipv4 = new(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.Compiled);
    private static readonly Regex Ipv6 = new(@"\b(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}\b", RegexOptions.Compiled);
    private static readonly Regex Mac = new(@"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", RegexOptions.Compiled);
    private static readonly Regex Sid = new(@"\bS-1-5-21(-\d+){3,4}\b", RegexOptions.Compiled);
    private static readonly Regex DeviceId = new(@"\bTK-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}\b", RegexOptions.Compiled);
    private static readonly Regex Serial = new(@"(?i)\b(serial(\s*number)?|SerialNumber|UUID|MachineGuid|ProductId)\b(\W{1,4})([A-Za-z0-9-]{6,})", RegexOptions.Compiled);
    private static readonly Regex SensitiveKey = new(@"(?i)^(serial(number)?|uuid|machineguid|productid|deviceid|mac(address)?|email|user(name)?|owner|registeredowner|computername|hostname|ssid|wifi|profilename|networkname|password|token|secret|apikey)$", RegexOptions.Compiled);
    // Everything after the host in a URL can carry tokens (webhooks, signed links): keep scheme and host only.
    private static readonly Regex UrlTail = new(@"(?i)\b((?:https?|ftp|wss?)://[^/\s""'<>?#]+)[/?#][^\s""'<>]*", RegexOptions.Compiled);
    private static readonly Regex Unc = new(@"\\\\[A-Za-z0-9._$-]+\\[^\\\s""']+", RegexOptions.Compiled);
    private static readonly Regex Secrets = new(@"(?i)(/user:\S+(\s+[^\s/-]\S*)?|(?:--?|/)(?:p|pw|pwd|pass|password|token|key|secret|apikey)(?:[:=]|\s+)\S+|\b(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*\S+)", RegexOptions.Compiled);
    private static readonly HashSet<string> GenericUsers = new(StringComparer.OrdinalIgnoreCase) { "Public", "Default", "Default User", "All Users", "defaultuser0", "WDAGUtilityAccount" };

    public static ScanResult Redact(ScanResult r)
    {
        var json = ReportWriter.ToJson(r);
        var root = JsonNode.Parse(json)!.AsObject();
        root.Remove("Data");          // raw collector output: process lists, network connections, event messages
        root.Remove("Timings");

        // Names we know up front, plus every profile name seen in a path.
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Name(string? v, string label) { if (!string.IsNullOrWhiteSpace(v) && v.Length >= 2 && !names.ContainsKey(v)) names[v] = label; }
        Name(r.Meta.ComputerName, "<PC>");
        foreach (var part in (r.Meta.Operator ?? "").Split('\\')) Name(part, "<user>");
        Name(Environment.UserName, "<user>"); Name(Environment.MachineName, "<PC>"); Name(Environment.UserDomainName, "<domain>");
        int n = 0;
        foreach (Match m in UserPath.Matches(json))
        {
            var u = m.Groups[2].Value;
            if (!GenericUsers.Contains(u) && !names.ContainsKey(u)) names[u] = $"<user{++n}>";
        }
        var nameRx = names.Count == 0 ? null : new Regex(@"(?<![A-Za-z0-9])(" + string.Join("|", names.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape)) + @")(?![A-Za-z0-9])", RegexOptions.IgnoreCase);

        string Clean(string s)
        {
            s = Email.Replace(s, "<email>");
            s = UrlTail.Replace(s, m => m.Groups[1].Value + "/<redacted>");
            s = Unc.Replace(s, @"\\<host>\<share>");
            s = Secrets.Replace(s, "<secret>");
            s = UserPath.Replace(s, m => m.Groups[1].Value + (GenericUsers.Contains(m.Groups[2].Value) ? m.Groups[2].Value : names.GetValueOrDefault(m.Groups[2].Value, "<user>")));
            if (nameRx is not null) s = nameRx.Replace(s, m => names.GetValueOrDefault(m.Value, "<redacted>"));
            s = Sid.Replace(s, "<account-sid>");
            s = DeviceId.Replace(s, "<device-id>");
            s = Mac.Replace(s, "<mac>");
            s = Ipv6.Replace(s, "<ip>");
            s = Ipv4.Replace(s, m => m.Value is "127.0.0.1" or "0.0.0.0" ? m.Value : "<ip>");
            s = Serial.Replace(s, m => m.Groups[1].Value + m.Groups[3].Value + "<redacted>");
            return s;
        }
        void Walk(JsonNode? node)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (var key in o.Select(kv => kv.Key).ToList())
                    {
                        var v = o[key];
                        if (v is JsonValue jv && jv.TryGetValue<string>(out var str)) o[key] = SensitiveKey.IsMatch(key) ? "<redacted>" : Clean(str);
                        else Walk(v);
                    }
                    break;
                case JsonArray a:
                    for (int i = 0; i < a.Count; i++)
                    {
                        if (a[i] is JsonValue jv && jv.TryGetValue<string>(out var str)) a[i] = Clean(str);
                        else Walk(a[i]);
                    }
                    break;
            }
        }
        Walk(root);
        var meta = root["Meta"]!.AsObject();
        meta["ComputerName"] = "<PC>"; meta["Operator"] = "<user>"; meta["CaseId"] = null; meta["Technician"] = null;
        meta["Redacted"] = true;
        return JsonSerializer.Deserialize<ScanResult>(root.ToJsonString(), ReportWriter.JsonOptions)!;
    }
}
