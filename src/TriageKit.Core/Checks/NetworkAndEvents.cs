using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

[SupportedOSPlatform("windows")]
public sealed class NetworkCheck : ICheck
{
    public string Name => "Network";

    public object? Run(CheckContext ctx)
    {
        var procs = Wmi.Query("SELECT ProcessId, Name, ExecutablePath FROM Win32_Process")
            .GroupBy(p => p.L("ProcessId") ?? -1).ToDictionary(g => g.Key, g => g.First());
        var conns = Wmi.Query("SELECT LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess FROM MSFT_NetTCPConnection", @"root\StandardCimv2");
        var ratPorts = ctx.Indicators.RatPorts.ToHashSet();

        (string Name, string? Path) Owner(long pid) => procs.TryGetValue(pid, out var p) ? (p.S("Name") ?? $"PID {pid}", p.S("ExecutablePath")) : ($"PID {pid}", null);

        var established = new List<object>();
        foreach (var c in conns.Where(c => c.L("State") == 5))
        {
            var remote = c.S("RemoteAddress") ?? "";
            if (Regex.IsMatch(remote, @"^(127\.|::1$|0\.0\.0\.0|::$)")) continue;
            var pid = c.L("OwningProcess") ?? 0; var (name, path) = Owner(pid);
            var intel = ctx.Files.Get(path);
            var risk = PathHeuristics.ExecutableRisk(intel);
            var rport = c.S("RemotePort") ?? "";
            if (ratPorts.Contains(rport) && intel is not { IsSigned: true }) risk = PathHeuristics.Max(risk, Risk.High);
            var row = new { Risk = risk, Process = name, PID = pid, Remote = $"{remote}:{rport}", Local = $"{c.S("LocalAddress")}:{c.S("LocalPort")}", Signer = intel?.Signer, Path = path };
            established.Add(row);
            if (risk is Risk.High or Risk.Critical)
                ctx.Add(Severity.High, "Network", $"Unsigned or risky program talking to the internet: {name}", $"{row.Remote} from {path}",
                        "Identify the program. If unknown, block it (e.g. in Portmaster or Windows Firewall) and check it on VirusTotal.", row, "T1071", "network.risky-connection");
        }

        var listening = new List<object>();
        foreach (var c in conns.Where(c => c.L("State") == 2 && (c.S("LocalAddress") is "0.0.0.0" or "::")).GroupBy(c => c.S("LocalPort")).Select(g => g.First()))
        {
            var pid = c.L("OwningProcess") ?? 0; var (name, path) = Owner(pid);
            var intel = ctx.Files.Get(path);
            var row = new { Risk = PathHeuristics.ExecutableRisk(intel), Port = c.L("LocalPort"), Process = name, PID = pid, Signer = intel?.Signer, Path = path };
            listening.Add(row);
            if (intel is { Exists: true, IsSigned: false })
                ctx.Add(Severity.Medium, "Network", $"Unsigned program accepting connections on port {row.Port}: {name}", path ?? "",
                        "Programs listening on all network interfaces can be reached by other devices. Make sure this is expected.", row, "T1571", "network.unsigned-listener");
        }

        var hostsPath = Path.Combine(Sys.SystemRoot, @"System32\drivers\etc\hosts");
        var hosts = new List<string>();
        try { hosts = File.ReadAllLines(hostsPath).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList(); } catch { }
        var sensitive = new Regex(string.Join("|", ctx.Indicators.HostsSensitiveDomains), RegexOptions.IgnoreCase);
        // Entries written by Docker Desktop / WSL / Kubernetes tooling are expected and not reported.
        var benign = new Regex(@"\s(host|gateway|kubernetes)\.docker\.internal$|\s(localhost|localhost\.localdomain|ip6-localhost|ip6-loopback)$", RegexOptions.IgnoreCase);
        // Lines about game, chat and account sites are judged (and grouped) by the "Accounts, sessions & downloads" check.
        foreach (var h in hosts.Where(x => (sensitive.IsMatch(x) || !benign.IsMatch(x)) && !GamingAccounts.MentionsPlatform(x)))
            ctx.Add(sensitive.IsMatch(h) ? Severity.High : Severity.Low, "Network", $"Hosts file entry: {h}",
                    "The hosts file can silently redirect websites (fake banking/login pages) or block security updates.",
                    "Remove entries you did not add yourself (C:\\Windows\\System32\\drivers\\etc\\hosts).", new { Entry = h }, "T1565.001", "network.hosts");

        var proxies = new List<object>();
        foreach (var sid in Reg.LoadedUserSids())
        {
            var k = $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
            var enabled = Reg.Value(Registry.Users, k, "ProxyEnable") as int?;
            var server = Reg.Value(Registry.Users, k, "ProxyServer") as string;
            var pac = Reg.Value(Registry.Users, k, "AutoConfigURL") as string;
            if (enabled == 1 || !string.IsNullOrEmpty(pac))
            {
                var row = new { User = sid, ProxyServer = server, AutoConfigURL = pac };
                proxies.Add(row);
                ctx.Add(Severity.Medium, "Network", "A web proxy is configured", $"Proxy: {server}  PAC: {pac}",
                        "A proxy can read and change your web traffic. Remove it unless your employer or you set it up (Settings > Network > Proxy).", row, "T1090", "network.proxy");
            }
        }

        var dns = Wmi.Query("SELECT Description, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")
            .Where(a => a.A("DNSServerSearchOrder").Length > 0)
            .Select(a => new { Adapter = a.S("Description"), Servers = string.Join(", ", a.A("DNSServerSearchOrder")) }).ToList();

        return new { Established = established, Listening = listening, HostsEntries = hosts, Proxies = proxies, DnsServers = dns };
    }
}

[SupportedOSPlatform("windows")]
public sealed class EventLogCheck : ICheck
{
    public string Name => "Event logs";

    private static IEnumerable<EventRecord> Read(string log, string ids, TimeSpan window, int max)
    {
        var xpath = $"*[System[({ids}) and TimeCreated[timediff(@SystemTime) <= {(long)window.TotalMilliseconds}]]]";
        EventLogReader? reader = null;
        try { reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true }); }
        catch (EventLogNotFoundException) { yield break; }
        catch (Exception ex) { CheckContext.Note($"Event log '{log}' could not be read", ex); yield break; }
        using (reader)
        {
            for (int i = 0; i < max; i++)
            {
                if (CheckContext.CurrentContext.Value?.Cancellation.IsCancellationRequested == true) yield break;
                EventRecord? r;
                try { r = reader.ReadEvent(); } catch (Exception ex) { CheckContext.Note($"Reading '{log}' stopped early", ex); yield break; }
                if (r is null) yield break;
                yield return r;
            }
        }
    }

    private static string? Prop(EventRecord r, int i) { try { return r.Properties.Count > i ? r.Properties[i].Value?.ToString() : null; } catch { return null; } }
    private static string Msg(EventRecord r) { try { return r.FormatDescription() ?? ""; } catch { return ""; } }

    public object? Run(CheckContext ctx)
    {
        var window = TimeSpan.FromDays(ctx.Options.EventLogDays);

        var services = new List<object>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Read("System", "EventID=7045", window, 300))
            using (r)
            {
                var row = new { Time = r.TimeCreated?.ToString("s"), Service = Prop(r, 0), Path = Prop(r, 1), Account = Prop(r, 4) };
                services.Add(row);
                var target = CommandLine.ExtractTarget(row.Path, resolve: Sys.ResolveProgram);
                if (!(PathHeuristics.IsSuspicious(target) || CommandLine.IsSuspiciousScriptHost(row.Path))) continue;
                if (!reported.Add($"{row.Service}|{row.Path}")) continue;   // the same install logged twice is one finding
                // Portable hardware tools (HWiNFO, CPU-Z, GPU-Z, ThrottleStop...) unpack their signed driver to %TEMP% and
                // load it from there. A validly signed driver, or a known tool whose temp copy is already gone, is Low.
                var fi = target is not null && File.Exists(target) ? ctx.Files.Get(target, hash: false) : null;
                bool knownTool = Regex.IsMatch($"{row.Service} {row.Path}", @"HWiNFO|CPUID|cpuz|GPU-?Z|TechPowerUp|ThrottleStop|RwDrv|RWEverything|AIDA64|OpenHardwareMonitor|LibreHardwareMonitor|PawnIO|WinRing0|HWMonitor", RegexOptions.IgnoreCase);
                if (fi?.IsSigned == true || (fi is null && knownTool))
                {
                    ctx.Add(Severity.Low, "Events", $"Driver loaded from a temporary folder: {row.Service}",
                        $"{row.Path}\n{(fi?.IsSigned == true ? $"Signed by {fi.Signer}." : "The file is gone now.")} Portable hardware tools such as HWiNFO, CPU-Z or GPU-Z load their driver this way.",
                        "Nothing to do if you ran such a tool. If you don't recognise the name, run a full check.", row, "T1543.003", "events.service-temp-driver");
                    continue;
                }
                ctx.Add(Severity.High, "Events", $"Service installed from a risky location: {row.Service}", row.Path ?? "",
                        "Attackers install services for persistence and privilege. Investigate this service.", row, "T1543.003", "events.service-risky");
            }

        var cleared = new List<object>();
        foreach (var (log, id) in new[] { ("Security", 1102), ("System", 104) })
            foreach (var r in Read(log, $"EventID={id}", window, 20))
                using (r)
                {
                    var row = new { Time = r.TimeCreated?.ToString("s"), Log = log, Id = id };
                    cleared.Add(row);
                    ctx.Add(Severity.High, "Events", $"An event log was cleared ({log}) at {row.Time}", "Attackers clear logs to hide what they did.",
                            "Find out who cleared the log and why.", row, "T1070.001", "events.log-cleared");
                }

        int failed = Read("Security", "EventID=4625", TimeSpan.FromDays(7), 5000).Count();
        if (failed >= 50)
            ctx.Add(Severity.Medium, "Events", $"{failed} failed sign-in attempts in the last 7 days", "This may be someone guessing passwords.",
                    "Check where the attempts come from and turn off Remote Desktop/file sharing exposed to the internet.", new { FailedLogons7d = failed }, "T1110", "events.bruteforce");

        const string def = "Microsoft-Windows-Windows Defender/Operational";
        var rtp = new List<object>(); string? last = null;
        foreach (var r in Read(def, "EventID=5001 or EventID=5010 or EventID=5012", window, 50))
            using (r) { var t = r.TimeCreated?.ToString("s"); last ??= t; rtp.Add(new { Time = t, Id = r.Id, Message = Sys.Trunc(Msg(r), 300) }); }
        if (rtp.Count > 0)
        {
            bool? rtpOnNow = null;
            try { rtpOnNow = Wmi.Query("SELECT RealTimeProtectionEnabled FROM MSFT_MpComputerStatus", @"root\Microsoft\Windows\Defender").FirstOrDefault()?.B("RealTimeProtectionEnabled"); } catch { }
            var times = rtp.Count == 1 ? $"once (at {last})" : $"{rtp.Count} times (last at {last})";
            if (rtpOnNow == true)
                ctx.Add(Severity.Medium, "Events", $"Defender real-time protection was switched off {times}; it is on again now",
                        "Turning protection off temporarily is common when installing games or tools, but malware does it too.",
                        "If you don't remember switching it off, run a full Defender scan and check Defender's protection history.", rtp, "T1562.001", "events.defender-disabled");
            else
                ctx.Add(Severity.High, "Events", $"Defender real-time protection was switched off {times}", "Protection does not appear to be on right now.",
                        "Turn real-time protection back on in Windows Security. If you didn't switch it off, assume something else did.", rtp, "T1562.001", "events.defender-disabled");
        }

        // Exclusions: only real antivirus exclusions (paths / extensions / processes). Microsoft's own feature flags
        // (EcsConfigs) and ASR-only exclusions don't stop antivirus scanning, and tools like ConfigureDefender add them.
        var exclusionChanges = new List<object>();
        var addedExclusions = new List<string>();
        foreach (var r in Read(def, "EventID=5007", window, 500))
            using (r)
            {
                var m = Msg(r);
                if (!m.Contains("Exclusions", StringComparison.OrdinalIgnoreCase)) continue;
                var nv = Regex.Match(m, @"New value:\s*(.+)").Groups[1].Value.Trim();
                var ov = Regex.Match(m, @"Old value:\s*(.*?)\s*(New value|$)", RegexOptions.Singleline).Groups[1].Value.Trim();
                bool added = nv.Length > 0 && ov.Length == 0;
                bool avExclusion = Regex.IsMatch(added ? nv : ov, @"\\Windows Defender\\Exclusions\\(Paths|Extensions|Processes|IpAddresses)\\", RegexOptions.IgnoreCase);
                var row = new { Time = r.TimeCreated?.ToString("s"), Added = added, Antivirus = avExclusion, Change = Sys.Trunc(added ? nv : $"removed: {ov}", 400) };
                exclusionChanges.Add(row);
                if (added && avExclusion)
                {
                    var what = Regex.Match(nv, @"\\Exclusions\\\w+\\(.+?)\s*=\s*\S+\s*$").Groups[1].Value;
                    addedExclusions.Add($"{(what.Length > 0 ? what : nv)} ({row.Time})");
                }
            }
        try
        {
            var current = Wmi.Query("SELECT ExclusionPath, ExclusionExtension, ExclusionProcess FROM MSFT_MpPreference", @"root\Microsoft\Windows\Defender").FirstOrDefault();
            var configured = new[] { "ExclusionPath", "ExclusionExtension", "ExclusionProcess" }
                .SelectMany(k => current?.A(k) ?? Enumerable.Empty<string>()).Where(x => x.Length > 0).ToList();
            addedExclusions.RemoveAll(a => configured.Any(c => a.StartsWith(c + " (", StringComparison.OrdinalIgnoreCase)));
        }
        catch { }
        if (addedExclusions.Count > 0)
            ctx.Add(Severity.Medium, "Events", addedExclusions.Count == 1 ? "A Defender exclusion was added recently" : $"{addedExclusions.Count} Defender exclusions were added recently",
                    string.Join("\n", addedExclusions.Distinct().Take(20)),
                    "Make sure you (or your IT) added these on purpose; malware adds exclusions to hide from antivirus.", exclusionChanges, "T1562.001", "events.exclusion-added");

        var ps = new List<object>();
        var psPattern = new Regex(string.Join("|", ctx.Indicators.SuspiciousPowerShellPatterns), RegexOptions.IgnoreCase);
        foreach (var r in Read("Microsoft-Windows-PowerShell/Operational", "EventID=4104", TimeSpan.FromDays(7), 500))
            using (r)
            {
                var text = Prop(r, 2) ?? "";
                if (!psPattern.IsMatch(text) || ps.Count >= 20) continue;
                var row = new { Time = r.TimeCreated?.ToString("s"), Snippet = Sys.Trunc(text, 500) };
                ps.Add(row);
                ctx.Add(Severity.High, "Events", $"Suspicious PowerShell script ran at {row.Time}",
                        "The script used techniques typical of malware (download-and-run, disabling protection, in-memory loading).",
                        "Review the script and what launched it.", row, "T1059.001", "events.powershell-suspicious");
            }

        return new { NewServices = services, LogsCleared = cleared, FailedLogons7d = failed, DefenderRtpDisabled = rtp,
                     DefenderExclusionChanges = exclusionChanges, SuspiciousPowerShell = ps };
    }
}
