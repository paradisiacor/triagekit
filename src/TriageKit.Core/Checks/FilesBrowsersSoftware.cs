using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

[SupportedOSPlatform("windows")]
public sealed class RecentFilesCheck : ICheck
{
    public string Name => "Recently created files";
    public bool IsSlow => true;

    private static readonly Regex Ext = new(@"\.(exe|dll|scr|com|pif|ps1|vbs|vbe|js|jse|hta|bat|cmd|jar|lnk|msi)$", RegexOptions.IgnoreCase);
    private static readonly Regex Binary = new(@"\.(exe|dll|scr|com|msi)$", RegexOptions.IgnoreCase);
    private static readonly Regex Script = new(@"\.(vbs|vbe|js|jse|hta|ps1)$", RegexOptions.IgnoreCase);
    private static readonly Regex Skip = new(@"\\(node_modules|\.git|Packages|WindowsApps|Microsoft\\Edge|Google\\Chrome|BraveSoftware|Mozilla|Code Cache|GPUCache|Cache_Data|CrashDumps|INetCache|steamapps|Battle\.net\\Cache|Microsoft\\Windows Defender|Malwarebytes)\\", RegexOptions.IgnoreCase);

    public object? Run(CheckContext ctx)
    {
        var since = DateTime.Now.AddDays(-ctx.Options.RecentFileDays);
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.Combine(Sys.SystemRoot, "Temp"),
            Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public",
        };
        foreach (var u in Sys.UserProfiles())
            roots.AddRange(new[] { @"AppData\Local\Temp", @"AppData\Roaming", @"AppData\Local", "Downloads", "Desktop" }.Select(s => Path.Combine(u.Path, s)));

        var opts = new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 4, IgnoreInaccessible = true, AttributesToSkip = 0 };
        var found = new List<FileInfo>();
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase).Where(Directory.Exists))
        {
            try
            {
                foreach (var f in new DirectoryInfo(root).EnumerateFiles("*", opts))
                {
                    if (ctx.Cancellation.IsCancellationRequested || found.Count >= ctx.Options.RecentFileMaxItems) break;
                    if (!Ext.IsMatch(f.Name) || Skip.IsMatch(f.FullName)) continue;
                    try { if (f.CreationTime > since) found.Add(f); } catch { }
                }
            }
            catch { }
        }

        var rows = new List<object>();
        var riskyFiles = new List<string>(); var scriptFiles = new List<string>();
        foreach (var f in found.OrderByDescending(f => f.CreationTime))
        {
            if (SelfIdentity.IsSelf(f.FullName, Binary.IsMatch(f.Name) ? ctx.Files.Get(f.FullName)?.SHA256 : null)) continue;
            var intel = Binary.IsMatch(f.Name) ? ctx.Files.Get(f.FullName) : null;
            var risk = intel is not null ? PathHeuristics.ExecutableRisk(intel)
                     : Script.IsMatch(f.Name) && Regex.IsMatch(f.FullName, @"\\(AppData|ProgramData|Temp|Users\\Public)\\", RegexOptions.IgnoreCase) ? Risk.Medium : Risk.Info;
            if (risk is Risk.High or Risk.Critical) riskyFiles.Add(f.FullName);
            if (intel is null && risk == Risk.Medium) scriptFiles.Add(f.FullName);
            rows.Add(new { Risk = risk, Created = f.CreationTime.ToString("s"), Path = f.FullName, Size = f.Length,
                           Signer = intel?.Signer, Signature = intel?.SignatureStatus.ToString() ?? "n/a (script)", SHA256 = intel?.SHA256 });
        }
        // The findings name the files, so they can be acted on without opening the full report.
        static string List(List<string> files) => string.Join("\n", files.Take(8)) + (files.Count > 8 ? $"\n…and {files.Count - 8} more (full list in the report)" : "");
        if (riskyFiles.Count > 0)
            ctx.Add(Severity.Medium, "Files", $"{riskyFiles.Count} unsigned program(s) recently created in risky folders",
                    List(riskyFiles) + "\nUnsigned programs in Temp, AppData or Public folders are how most malware arrives.",
                    "If you don't recognise a file, don't run it; check where it came from and look up its SHA-256 on VirusTotal.", riskyFiles, ruleId: "files.unsigned-risky", mitre: "T1105");
        if (scriptFiles.Count > 0)
            ctx.Add(Severity.Low, "Files", $"{scriptFiles.Count} script file(s) recently created in AppData/ProgramData/Temp",
                    List(scriptFiles) + "\nScripts in these folders are a common way malware gets started.",
                    "Make sure you recognise these scripts.", scriptFiles, ruleId: "files.scripts", mitre: "T1059");
        if (found.Count >= ctx.Options.RecentFileMaxItems)
            ctx.Add(Severity.Info, "Files", $"Recent-file sweep stopped at {ctx.Options.RecentFileMaxItems} items", "", "Increase RecentFileMaxItems in config.json for a deeper sweep.");
        return rows;
    }
}

[SupportedOSPlatform("windows")]
public sealed class BrowserExtensionCheck : ICheck
{
    public string Name => "Browser extensions";

    private static readonly (string Browser, string Rel)[] Chromium =
    {
        ("Chrome", @"AppData\Local\Google\Chrome\User Data"), ("Edge", @"AppData\Local\Microsoft\Edge\User Data"),
        ("Brave", @"AppData\Local\BraveSoftware\Brave-Browser\User Data"), ("Vivaldi", @"AppData\Local\Vivaldi\User Data"),
        ("Opera", @"AppData\Roaming\Opera Software\Opera Stable"), ("Opera GX", @"AppData\Roaming\Opera Software\Opera GX Stable"),
    };
    private static readonly Dictionary<string, string> Wallets = new(StringComparer.OrdinalIgnoreCase)
    {
        ["nkbihfbeogaeaoehlefnkodbefgpgknn"] = "MetaMask", ["ejbalbakoplchlghecdalmeeeajnimhm"] = "MetaMask", ["bfnaelmomeimhlpmgjnjophhpkkoljpa"] = "Phantom",
        ["hnfanknocfeofbddgcijnmhnfnkdnaad"] = "Coinbase Wallet", ["egjidjbpglichdcondbcbdnbeeppgdph"] = "Trust Wallet", ["acmacodkjbdgmoleebolmdjonilkdbch"] = "Rabby",
        ["aholpfdialjgjfhomihkjbmgjidlcdno"] = "Exodus Web3", ["mcohilncbfahbmgdjkbpemcciiolgcge"] = "OKX Wallet", ["fhbohimaelbohpjbbldcngcnapndodjp"] = "Binance Wallet",
        ["dmkamcknogkgcdfhhbddcghachkejeap"] = "Keplr", ["ibnejdfjmmkpcnlpebklmnkoeoihofec"] = "TronLink",
    };
    private static readonly Regex AccountSite = new(@"(steamcommunity\.com|steampowered\.com|discord\.com|roblox\.com|epicgames\.com|battle\.net|riotgames\.com|csgoroll|skinport|buff\.163\.com|csfloat|cs\.money|dmarket|tradeit\.gg)", RegexOptions.IgnoreCase);
    private static readonly Regex SessionPower = new(@"^(cookies|webRequest|webRequestBlocking|declarativeNetRequest|declarativeNetRequestWithHostAccess|scripting|debugger)$", RegexOptions.IgnoreCase);
    private static readonly Regex Broad = new(@"(<all_urls>|^\*://\*/\*$|^https?://\*/\*$|^webRequest|^nativeMessaging$|^debugger$|^proxy$|^cookies$|^scripting$)", RegexOptions.IgnoreCase);

    public object? Run(CheckContext ctx)
    {
        var store = new Regex(string.Join("|", ctx.Indicators.BrowserStoreUpdateUrls), RegexOptions.IgnoreCase);
        var rows = new List<object>();
        var walletsSeen = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in Sys.UserProfiles())
        {
            foreach (var (browser, rel) in Chromium)
            {
                var baseDir = Path.Combine(u.Path, rel);
                if (!Directory.Exists(baseDir)) continue;
                var profiles = SafeDirs(baseDir).Where(d => Path.GetFileName(d) is "Default" || Path.GetFileName(d).StartsWith("Profile ")).ToList();
                if (Directory.Exists(Path.Combine(baseDir, "Extensions"))) profiles.Add(baseDir);
                foreach (var prof in profiles)
                    foreach (var extDir in SafeDirs(Path.Combine(prof, "Extensions")))
                    {
                        var ver = SafeDirs(extDir).OrderByDescending(Directory.GetLastWriteTime).FirstOrDefault();
                        if (ver is null) continue;
                        try
                        {
                            using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(ver, "manifest.json")), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                            var m = doc.RootElement;
                            var name = Str(m, "name") ?? Path.GetFileName(extDir);
                            if (name.StartsWith("__MSG_")) name = Localize(ver, Str(m, "default_locale") ?? "en", name[6..^2]) ?? name;
                            var perms = Arr(m, "permissions").Concat(Arr(m, "host_permissions")).ToList();
                            var broad = perms.Where(p => Broad.IsMatch(p)).Distinct().ToList();
                            bool fromStore = store.IsMatch(Str(m, "update_url") ?? "");
                            var risk = !fromStore && broad.Count > 0 ? Risk.High : !fromStore ? Risk.Medium : broad.Count >= 2 ? Risk.Low : Risk.Info;
                            var row = new { Risk = risk, Browser = browser, Name = name, FromStore = fromStore, BroadPermissions = string.Join(", ", broad),
                                            Version = Str(m, "version"), User = u.Name, Profile = Path.GetFileName(prof), Installed = Directory.GetCreationTime(ver).ToString("s"), Id = Path.GetFileName(extDir) };
                            rows.Add(row);
                            if (risk == Risk.High)
                                ctx.Add(Severity.High, "Browser", $"Extension not from the official store, with access to your browsing: {name} ({browser})",
                                        $"Permissions: {row.BroadPermissions}. Sideloaded extensions like this can steal passwords, cookies and crypto wallets.",
                                        $"Remove it in {browser} > Extensions unless you installed it deliberately from a source you trust.", row, "T1176", "browser.sideloaded-broad");
                            else if (risk == Risk.Medium)
                                ctx.Add(Severity.Medium, "Browser", $"Extension not from the official store: {name} ({browser})", "", "Make sure you installed this extension yourself.", row, "T1176", "browser.sideloaded");
                            if (Wallets.TryGetValue(Path.GetFileName(extDir), out var wallet)) walletsSeen.Add($"{wallet} ({browser})");
                            // Extensions aimed at account sites (Steam trading, Discord, Roblox...): a favourite of account
                            // thieves, because they act inside your signed-in session. With cookie or request access they
                            // can take the session itself.
                            var targets = perms.Concat(m.TryGetProperty("content_scripts", out var cs) && cs.ValueKind == JsonValueKind.Array
                                    ? cs.EnumerateArray().SelectMany(c => Arr(c, "matches")) : Enumerable.Empty<string>())
                                .Select(t => AccountSite.Match(t)).Where(x => x.Success).Select(x => x.Groups[1].Value.ToLowerInvariant()).Distinct().ToList();
                            var powerful = perms.Where(p => SessionPower.IsMatch(p)).Distinct().ToList();
                            if (fromStore && targets.Count > 0)
                                ctx.Add(powerful.Count > 0 ? Severity.Medium : Severity.Low, "Sessions", $"Extension can act on your {string.Join(", ", targets)} pages: {name} ({browser})",
                                        $"It can read and change what you see on {string.Join(", ", targets)} while you're signed in{(powerful.Count > 0 ? $", and has {string.Join(", ", powerful)} access, which can take your session itself" : "")}. Popular trading and helper extensions do this, and fake ones use it to steal items and accounts.",
                                        "Keep it only if you installed it on purpose and know the publisher. Check its reviews and publisher in the store.", new { row.Name, row.Browser, row.Id, Sites = targets, Permissions = powerful }, "T1176", "session.extension-account-site");
                        }
                        catch { }
                    }
            }
            // Firefox
            foreach (var prof in SafeDirs(Path.Combine(u.Path, @"AppData\Roaming\Mozilla\Firefox\Profiles")))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(prof, "extensions.json")));
                    foreach (var a in doc.RootElement.GetProperty("addons").EnumerateArray())
                    {
                        var loc = Str(a, "location");
                        if (loc is not null && loc.StartsWith("app-", StringComparison.OrdinalIgnoreCase) && loc != "app-profile") continue;   // shipped with Firefox
                        if ((a.TryGetProperty("isSystem", out var sys) && sys.ValueKind == JsonValueKind.True) ||
                            (a.TryGetProperty("isBuiltin", out var bi) && bi.ValueKind == JsonValueKind.True)) continue;
                        bool signed = a.TryGetProperty("signedState", out var ss) && ss.ValueKind == JsonValueKind.Number && ss.GetInt32() >= 2;
                        string? name = a.TryGetProperty("defaultLocale", out var dl) && dl.ValueKind == JsonValueKind.Object ? Str(dl, "name") : null;
                        var row = new { Risk = signed ? Risk.Info : Risk.Medium, Browser = "Firefox", Name = name ?? Str(a, "id"), FromStore = signed, BroadPermissions = "",
                                        Version = Str(a, "version"), User = u.Name, Profile = Path.GetFileName(prof), Installed = (string?)null, Id = Str(a, "id") };
                        rows.Add(row);
                        if (!signed) ctx.Add(Severity.Medium, "Browser", $"Unsigned Firefox add-on: {row.Name}", "", "Make sure you installed this add-on yourself.", row, "T1176", "browser.firefox-unsigned");
                    }
                }
                catch { }
            }
        }
        if (walletsSeen.Count > 0)
            ctx.Add(Severity.Info, "Sessions", $"Crypto wallet extensions: {string.Join(", ", walletsSeen)}",
                    "Info stealers look for wallet extensions first, because a stolen wallet can be emptied instantly and for good.",
                    "Keep the recovery phrase offline (never as a plain file, screenshot or clipboard text), use a hardware wallet for larger amounts, and keep this PC clean.",
                    new { Wallets = walletsSeen }, "T1555.003", "session.wallet-extension");
        return rows;
    }

    private static IEnumerable<string> SafeDirs(string dir) { try { return Directory.Exists(dir) ? Directory.GetDirectories(dir) : Array.Empty<string>(); } catch { return Array.Empty<string>(); } }
    private static string? Str(JsonElement e, string p) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static IEnumerable<string> Arr(JsonElement e, string p) =>
        e.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!) : Enumerable.Empty<string>();
    private static string? Localize(string verDir, string locale, string key)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(verDir, "_locales", locale, "messages.json")));
            foreach (var p in doc.RootElement.EnumerateObject())
                if (string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase)) return Str(p.Value, "message");
        }
        catch { }
        return null;
    }
}

[SupportedOSPlatform("windows")]
public sealed class SoftwareCheck : ICheck
{
    public string Name => "Installed software";

    public object? Run(CheckContext ctx)
    {
        var apps = new Dictionary<string, (string Name, string? Version, string? Publisher, string? Installed)>(StringComparer.OrdinalIgnoreCase);
        void Collect(RegistryKey root, string key)
        {
            foreach (var sub in Reg.SubKeys(root, key))
            {
                var path = $@"{key}\{sub}";
                if (Reg.Value(root, path, "DisplayName") is not string name || string.IsNullOrWhiteSpace(name)) continue;
                if (Reg.Value(root, path, "SystemComponent") is int sc && sc == 1) continue;
                apps.TryAdd(name.Trim(), (name.Trim(), Reg.Value(root, path, "DisplayVersion") as string, Reg.Value(root, path, "Publisher") as string, Reg.Value(root, path, "InstallDate") as string));
            }
        }
        Collect(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        Collect(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
        foreach (var sid in Reg.LoadedUserSids()) Collect(Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall");

        var running = System.Diagnostics.Process.GetProcesses().Select(p => { try { return p.ProcessName; } catch { return ""; } }).ToList();
        var remote = new List<object>();
        foreach (var tool in ctx.Indicators.RemoteAccessTools)
        {
            var hit = apps.Values.FirstOrDefault(a => Regex.IsMatch(a.Name, tool.Pattern, RegexOptions.IgnoreCase));
            bool isRunning = !string.IsNullOrEmpty(tool.Process) && running.Any(p => Regex.IsMatch(p, $"^({tool.Process})$", RegexOptions.IgnoreCase));
            if (hit.Name is null && !isRunning) continue;
            var row = new { Tool = tool.Name, Installed = hit.Name ?? "(running, not installed - portable copy?)", hit.Version, hit.Publisher, Running = isRunning };
            remote.Add(row);
            ctx.Add(hit.Name is null ? Severity.Medium : Severity.Low, "Software", $"Remote-access tool {(hit.Name is null ? "running" : "installed")}: {tool.Name}",
                    "These tools are legitimate, but scammers and attackers use them to take full control of a PC." + (hit.Name is null ? " A portable copy running without installation is more suspicious." : ""),
                    "Uninstall it if you don't use it regularly, and never let someone you don't know connect.", row, "T1219", "software.remote-access");
        }
        var dual = new Regex(string.Join("|", ctx.Indicators.DualUseToolPatterns), RegexOptions.IgnoreCase);
        foreach (var a in apps.Values.Where(a => dual.IsMatch(a.Name)))
            ctx.Add(Severity.Info, "Software", $"Security/hacking tool installed: {a.Name}", "Legitimate for power users, but worth knowing about on a shared or work PC.", "", new { a.Name, a.Version }, ruleId: "software.dual-use");

        return new
        {
            InstalledCount = apps.Count, RemoteAccessTools = remote,
            Installed = apps.Values.OrderBy(a => a.Name).Select(a => new { a.Name, a.Version, a.Publisher, a.Installed }).ToList()
        };
    }
}
