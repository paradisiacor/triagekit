using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

/// <summary>
/// What to do when an account or session may have been stolen. Shown once per report as its own card (not
/// repeated under every finding), because changing a password alone doesn't end a stolen session: copied cookies
/// keep working until the session is signed out.
/// </summary>
internal static class SignOutEverywhere
{
    public const string Pointer = "Then follow \"Sign out everywhere\" in this report.";
    public const string Steps =
        "From a clean device (your phone is fine): 1) Change the passwords of your email, Microsoft and Google accounts first, then the rest. " +
        "2) End all other sessions: Google myaccount.google.com/device-activity; Microsoft account.microsoft.com/security (\"Sign out everywhere\"); " +
        "Discord Settings > Devices > \"Log out all known devices\" and Settings > Authorized Apps; Steam store.steampowered.com/twofactor/manage (\"Deauthorize all other devices\") and steamcommunity.com/dev/apikey (revoke any key you didn't create); " +
        "Roblox Settings > Security > \"Log out of all other sessions\"; Epic, Battle.net, Riot, banking and crypto apps have the same option under security or devices. " +
        "3) Remove passkeys, recovery emails and phone numbers you don't recognise. 4) Move crypto to a new wallet with a new recovery phrase. 5) Only then trust this PC again, after the cause is removed.";

    /// <summary>Adds the card once if any account-theft finding at Medium or worse is in the report.</summary>
    public static void AddIfNeeded(CheckContext ctx)
    {
        bool needed;
        lock (ctx.Findings) needed = ctx.Findings.Any(f => f.RuleId is { } id && (id.StartsWith("session.") || id.StartsWith("gaming.")) && f.Severity <= Severity.Medium);
        if (needed)
            ctx.Add(Severity.Info, "Sessions", "Sign out everywhere (what to do if accounts may be stolen)", Steps,
                "Do this after reading the findings above. A new password alone doesn't log out someone who copied your session.", null, "T1539", "session.sign-out-steps");
    }
}

/// <summary>Per-user folders, honouring redirection (OneDrive Desktop, Downloads moved to another drive).</summary>
[SupportedOSPlatform("windows")]
internal static class UserFolders
{
    private const string DownloadsGuid = "{374DE290-123F-4565-9164-39C4925E467B}";

    public static string Desktop(Sys.UserProfile u) => Resolve(u, "Desktop") ?? Path.Combine(u.Path, "Desktop");
    public static string Downloads(Sys.UserProfile u) => Resolve(u, DownloadsGuid) ?? Path.Combine(u.Path, "Downloads");

    private static string? Resolve(Sys.UserProfile u, string name)
    {
        try
        {
            var raw = Reg.Value(Registry.Users, $@"{u.Sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", name) as string;
            if (string.IsNullOrWhiteSpace(raw)) return null;
            // %USERPROFILE% must be this user's profile, not the account TriageKit runs as.
            var path = Regex.Replace(raw, "%USERPROFILE%", u.Path.Replace("$", "$$"), RegexOptions.IgnoreCase);
            path = Environment.ExpandEnvironmentVariables(path);
            return Directory.Exists(path) ? path : null;
        }
        catch { return null; }
    }
}

/// <summary>
/// Signs that browser sessions, cookies or app logins are being (or were) stolen. Read-only and private: names,
/// sizes, times, settings and command lines are looked at; cookie values, passwords and tokens never.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SessionTheftCheck : ICheck
{
    public string Name => "Accounts, sessions & downloads";

    private const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    internal static readonly Regex BrowserExe = new(@"(^|\\)(chrome|msedge|brave|opera|vivaldi|chromium|thorium|yandex|browser|arc|firefox)\.exe$|\\Opera[^\\]*\\launcher\.exe$", O);
    internal static readonly Regex DebugFlags = new(@"--remote-debugging-(port|pipe|address)|(^|\s)-start-debugger-server|(^|\s)--?marionette\b", O);
    internal static readonly Regex ExtensionFlags = new(@"--load-extension\s*=|--disable-extensions-except", O);
    internal static readonly Regex DumpFlags = new(DebugFlags + "|" + ExtensionFlags, O);
    // Chromium's own child processes repeat the parent's switches; only a real --type switch marks one.
    internal static readonly Regex ChildProcess = new(@"(^|\s)--type=(renderer|gpu-process|utility|crashpad-handler|zygote|ppapi|broker|nacl-loader)\b", O);
    private static readonly Regex AutomationParent = new(@"^(chromedriver|msedgedriver|geckodriver|node|python|pythonw|py|Code|dotnet|java|javaw|deno|bun|cypress|playwright)\.exe$", O);
    private static readonly Regex UserWritable = new(@"\\(AppData|Temp|ProgramData|Users\\Public|Downloads)\\", O);

    public object? Run(CheckContext ctx)
    {
        var rows = new List<object>();
        var processes = Wmi.Query("SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process", optional: true);
        Shortcuts(ctx, rows);
        RunningProcesses(ctx, rows, processes);
        BrowserLaunchSettings(ctx, rows);
        BrowserProfiles(ctx, rows);
        BrowserFolders(ctx, rows);
        StealerLeftovers(ctx, rows);
        OldBrowsers(ctx, rows);
        GamingAccounts.Hosts(ctx, rows);
        GamingAccounts.Downloads(ctx, rows);
        GamingAccounts.AppTampering(ctx, rows);
        GamingAccounts.Exposure(ctx, rows);
        SignOutEverywhere.AddIfNeeded(ctx);
        return rows;
    }

    // ---------------------------------------------------------------- shortcuts
    private static void Shortcuts(CheckContext ctx, List<object> rows)
    {
        var roots = new List<(string Dir, int Depth)>
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), 0),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs"), 2),
        };
        foreach (var u in Sys.UserProfiles())
        {
            roots.Add((UserFolders.Desktop(u), 0));
            roots.Add((Path.Combine(u.Path, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"), 2));
            foreach (var pin in new[] { "TaskBar", "StartMenu", "ImplicitAppShortcuts" })
                roots.Add((Path.Combine(u.Path, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned", pin), 1));
        }
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (dir, depth) in roots.Where(r => Directory.Exists(r.Dir)))
        {
            List<string> links;
            try { links = Directory.EnumerateFiles(dir, "*.lnk", new EnumerationOptions { RecurseSubdirectories = depth > 0, MaxRecursionDepth = Math.Max(1, depth), IgnoreInaccessible = true }).Take(800).ToList(); }
            catch { continue; }
            foreach (var lnk in links)
            {
                if (!seen.Add(lnk)) continue;
                Yara.Shortcut.Info? info;
                try { if (new FileInfo(lnk).Length > 65536) continue; info = Yara.Shortcut.Parse(File.ReadAllBytes(lnk)); } catch { continue; }
                if (info?.Target is null || info.Arguments is null) continue;
                var args = info.Arguments;
                var name = Path.GetFileNameWithoutExtension(lnk);
                // Steam's browser can be opened for debugging too; stealers use that to read the Steam web session.
                if (Regex.IsMatch(info.Target, @"\\steam\.exe$", O) && Regex.IsMatch(args, @"-cef-enable-debugging|-devtools\b", O))
                {
                    var srow = new { Kind = "SteamShortcut", Shortcut = lnk, info.Target, info.Arguments };
                    rows.Add(srow);
                    ctx.Add(Severity.Medium, "Sessions", $"Steam shortcut opens Steam with debugging on: {name}",
                        $"{lnk}\nArguments: {Sys.Trunc(args, 300)}\nThis lets other programs read Steam's built-in browser, including your signed-in Steam session. Skin and plugin tools sometimes need it; stealers use it too.",
                        "If you didn't set this up for a Steam skin or plugin tool, remove the arguments from the shortcut. " + SignOutEverywhere.Pointer, srow, "T1539", "session.steam-debug");
                    continue;
                }
                if (!BrowserExe.IsMatch(info.Target)) continue;
                bool debug = DebugFlags.IsMatch(args), extension = ExtensionFlags.IsMatch(args);
                if (!debug && !extension) continue;
                var dataDir = UserDataDir(args);
                var row = new { Kind = "Shortcut", Shortcut = lnk, info.Target, info.Arguments, UserDataDir = dataDir };
                rows.Add(row);
                if (debug)
                {
                    // A separate profile folder is what developers use for a debug shortcut; on the normal profile it's
                    // the stealer pattern (every browser start opens your real sessions to another program).
                    bool separate = dataDir is not null;
                    ctx.Add(separate ? Severity.Medium : Severity.High, "Sessions", $"Browser shortcut opens it with remote debugging: {name}",
                        $"{lnk}\nTarget: {info.Target}\nArguments: {Sys.Trunc(args, 300)}\nRemote debugging lets another program read everything in the browser, including signed-in sessions. {(separate ? $"It uses a separate profile ({dataDir}), as developer setups do, so your normal sessions may not be exposed." : "It uses your normal profile, which is how info stealers change shortcuts so every browser start leaks your cookies.")}",
                        $"If you didn't create this shortcut for development, delete it and pin the browser again from its install folder. {(separate ? "" : SignOutEverywhere.Pointer)}", row, "T1539", "session.browser-shortcut-debug");
                }
                else
                {
                    var ext = Regex.Match(args, @"--load-extension\s*=\s*(""[^""]+""|\S+)", O).Groups[1].Value.Trim('"');
                    bool exists = ext.Length > 0 && ext.Split(',').Any(p => Directory.Exists(p.Trim()));
                    ctx.Add(UserWritable.IsMatch(ext + "\\") ? Severity.High : Severity.Medium, "Sessions", $"Browser shortcut loads an extra extension: {name}",
                        $"{lnk}\nExtension folder: {(ext.Length > 0 ? ext : "(not given)")} {(exists ? "(exists)" : "(not found)")}\nAn extension loaded this way bypasses the store and can read everything you do in the browser. Malware adds it to shortcuts to keep a stealer extension running.",
                        "If you don't develop browser extensions, delete the shortcut, pin the browser again, and check the extension folder with a full check. " + SignOutEverywhere.Pointer, row, "T1176", "session.browser-shortcut-extension");
                }
            }
        }
    }

    internal static string? UserDataDir(string args)
    {
        var m = Regex.Match(args, @"--user-data-dir\s*=\s*(""[^""]+""|\S+)", O);
        return m.Success ? m.Groups[1].Value.Trim('"') : null;
    }

    // ---------------------------------------------------------------- browsers / Steam running with those switches now
    private static void RunningProcesses(CheckContext ctx, List<object> rows, List<Dictionary<string, object?>> processes)
    {
        var byPid = processes.Where(p => p.L("ProcessId") is not null).GroupBy(p => p.L("ProcessId")!.Value).ToDictionary(g => g.Key, g => g.First());
        foreach (var p in processes)
        {
            var name = p.S("Name") ?? ""; var cmd = p.S("CommandLine") ?? ""; var exe = p.S("ExecutablePath") ?? name;
            if (cmd.Length == 0) continue;
            if (name.Equals("steam.exe", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(cmd, @"-cef-enable-debugging|-devtools\b", O))
            {
                var srow = new { Kind = "SteamProcess", Pid = p.L("ProcessId"), CommandLine = Sys.Trunc(cmd, 400) };
                rows.Add(srow);
                ctx.Add(Severity.Medium, "Sessions", "Steam is running with debugging on", $"PID {srow.Pid}: {srow.CommandLine}\nOther programs can read Steam's built-in browser, including your signed-in session, while it runs.",
                    "If no Steam skin or plugin tool needs this, restart Steam normally. " + SignOutEverywhere.Pointer, srow, "T1539", "session.steam-debug");
                continue;
            }
            if (!BrowserExe.IsMatch(exe) && !name.Equals("msedgewebview2.exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (!DebugFlags.IsMatch(cmd) || ChildProcess.IsMatch(cmd)) continue;
            var parentPid = p.L("ParentProcessId") ?? 0;
            byPid.TryGetValue(parentPid, out var parent);
            var parentName = parent?.S("Name"); var parentPath = parent?.S("ExecutablePath");
            // The same browser as parent means this is a child of a browser that's already been judged.
            if (parentName is not null && parentName.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            bool knownAutomation = parentName is not null && AutomationParent.IsMatch(parentName) && parentPath is not null && ctx.Files.Get(parentPath, hash: false).IsSigned;
            bool parentSuspicious = parent is null || (parentPath is not null && UserWritable.IsMatch(parentPath) && !ctx.Files.Get(parentPath, hash: false).IsSigned);
            bool stealth = Regex.IsMatch(cmd, @"--headless|--window-position=-\d|--start-minimized|--silent-launch|--no-startup-window", O);
            var dataDir = UserDataDir(cmd);
            bool tempProfile = dataDir is not null && Regex.IsMatch(dataDir, @"\\Temp\\|\\Users\\Public\\|\\ProgramData\\", O);
            var row = new { Kind = "Process", Pid = p.L("ProcessId"), Name = name, CommandLine = Sys.Trunc(cmd, 400), Parent = parentName ?? "(exited)", ParentPath = parentPath, UserDataDir = dataDir };
            rows.Add(row);
            Severity sev; string title, detail, advice;
            if (knownAutomation && !parentSuspicious)
            {
                sev = Severity.Low; title = $"Browser automation is running ({name}, started by {parentName})";
                detail = "A signed developer or test tool controls this browser, as Playwright, Puppeteer, Selenium or editors do.";
                advice = "Fine if you use developer or test tools. If not, close it and run a full check.";
            }
            else if (parentSuspicious || (stealth && tempProfile))
            {
                sev = Severity.High; title = $"Browser is running under remote control ({name})";
                detail = $"It was started {(parent is null ? "by a program that has already exited" : $"by {parentName} ({parentPath})")}{(stealth ? ", hidden from view" : "")}{(tempProfile ? $", with a copied profile in {dataDir}" : "")}. This is how current info stealers read cookies despite browser encryption: they start a hidden browser with a copy of your profile and pull the sessions out over the debugging port.";
                advice = "Close all windows of this browser now (check Task Manager), disconnect from the internet and run a full check. " + SignOutEverywhere.Pointer;
            }
            else
            {
                sev = Severity.Medium; title = $"Browser was started with remote debugging ({name})";
                detail = $"Started by {parentName ?? "an unknown program"}. Remote debugging lets another program read this browser's sessions. Developers use it; stealers too.";
                advice = "If you didn't start it this way yourself, close the browser and run a full check.";
            }
            ctx.Add(sev, "Sessions", title, $"PID {row.Pid}: {row.CommandLine}\n{detail}", advice, row, "T1539", sev == Severity.Low ? "session.browser-automation" : "session.browser-remote");
        }
    }

    // ---------------------------------------------------------------- how the browser is started and what policy allows
    private static readonly (string Browser, string Policy, string ProgId, string Data)[] Browsers =
    {
        ("Chrome", @"SOFTWARE\Policies\Google\Chrome", "ChromeHTML", @"Google\Chrome\User Data"),
        ("Edge", @"SOFTWARE\Policies\Microsoft\Edge", "MSEdgeHTM", @"Microsoft\Edge\User Data"),
        ("Brave", @"SOFTWARE\Policies\BraveSoftware\Brave", "BraveHTML", @"BraveSoftware\Brave-Browser\User Data"),
    };

    private static void BrowserLaunchSettings(CheckContext ctx, List<object> rows)
    {
        bool managed = Wmi.Query("SELECT PartOfDomain FROM Win32_ComputerSystem", optional: true).FirstOrDefault()?.B("PartOfDomain") == true
                       || Reg.SubKeys(Registry.LocalMachine, @"SOFTWARE\Microsoft\Enrollments").Any(k => Reg.Value(Registry.LocalMachine, $@"SOFTWARE\Microsoft\Enrollments\{k}", "ProviderID") is string { Length: > 0 });
        foreach (var (browser, policy, progId, _) in Browsers)
        {
            foreach (var (hive, label) in new[] { (Registry.LocalMachine, "HKLM"), (Registry.CurrentUser, "HKCU") })
            {
                var debugging = Reg.Value(hive, policy, "RemoteDebuggingAllowed") as int?;
                var abe = Reg.Value(hive, policy, "ApplicationBoundEncryptionEnabled") as int?;
                if (abe == 0)
                    ctx.Add(managed ? Severity.Low : Severity.High, "Sessions", $"{browser}'s cookie encryption is switched off by policy",
                        $@"{label}\{policy}\ApplicationBoundEncryptionEnabled = 0. {browser} then stores cookies so any program running as you can decrypt them. {(managed ? "This PC is managed by an organisation, which may have set it." : "On a home PC nothing legitimate needs this; stealers set it.")}",
                        managed ? "Ask your IT department if this is intended." : $@"Delete the value (regedit, {label}\{policy}) and run a full check. " + SignOutEverywhere.Pointer, new { browser, label, policy }, "T1562.001", "session.policy-abe-off");
                if (debugging == 1)
                    ctx.Add(managed ? Severity.Info : Severity.Medium, "Sessions", $"{browser} allows remote debugging by policy",
                        $@"{label}\{policy}\RemoteDebuggingAllowed = 1.", managed ? "Usually set by your IT department." : "Delete the value unless you set it for development.", new { browser, label, policy }, "T1562.001", "session.policy-debugging");
            }
            var key = $@"{progId}\shell\open\command";
            string? cmd = null;
            try { cmd = Registry.ClassesRoot.OpenSubKey(key)?.GetValue(null) as string; } catch { }
            if (cmd is not null && DumpFlags.IsMatch(cmd))
            {
                rows.Add(new { Kind = "LaunchCommand", browser, key, cmd });
                ctx.Add(Severity.High, "Sessions", $"Links open {browser} with remote control switches",
                    $"HKCR\\{key} = {Sys.Trunc(cmd, 300)}\nEvery link you click starts {browser} in a way that lets another program read your sessions.",
                    $"Reset the default browser (Settings > Apps > Default apps) or reinstall {browser}, then run a full check. " + SignOutEverywhere.Pointer, new { browser, key, cmd }, "T1546.001", "session.launch-hijack");
            }
        }
        foreach (var client in Reg.SubKeys(Registry.LocalMachine, @"SOFTWARE\Clients\StartMenuInternet"))
        {
            string? cmd = null;
            try { cmd = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Clients\StartMenuInternet\{client}\shell\open\command")?.GetValue(null) as string; } catch { }
            if (cmd is not null && DumpFlags.IsMatch(cmd))
                ctx.Add(Severity.High, "Sessions", $"Start menu opens {client} with remote control switches", $@"HKLM\SOFTWARE\Clients\StartMenuInternet\{client}\shell\open\command = {Sys.Trunc(cmd, 300)}",
                    $"Reinstall {client}, then run a full check. " + SignOutEverywhere.Pointer, new { client, cmd }, "T1546.001", "session.launch-hijack");
        }
        // WebView2 (used by many apps, TriageKit included) honours extra switches from this environment variable.
        var envSources = new List<(string Where, string? Value)> { ("machine", Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") as string) };
        foreach (var sid in Reg.LoadedUserSids()) envSources.Add(($"user {Sys.AccountName(sid) ?? sid}", Reg.Value(Registry.Users, $@"{sid}\Environment", "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS") as string));
        foreach (var (where, value) in envSources.Where(e => e.Value is not null && DebugFlags.IsMatch(e.Value)))
            ctx.Add(Severity.High, "Sessions", "Apps' built-in browsers are opened for remote debugging",
                $"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS ({where}) = {Sys.Trunc(value, 300)}\nEvery app that shows web content with WebView2 (Teams, Outlook, many launchers) can then be read by another program.",
                "Delete this environment variable (System Properties > Environment Variables) unless you set it for development, then run a full check. " + SignOutEverywhere.Pointer, new { where, value }, "T1539", "session.webview2-debug");
    }

    // ---------------------------------------------------------------- per profile: debugging trace, unpacked extensions
    private static void BrowserProfiles(CheckContext ctx, List<object> rows)
    {
        var since = DateTime.Now.AddDays(-30);
        foreach (var u in Sys.UserProfiles())
            foreach (var (browser, _, _, data) in Browsers)
            {
                var userData = Path.Combine(u.Path, "AppData", "Local", data);
                if (!Directory.Exists(userData)) continue;
                // Chromium writes DevToolsActivePort into the profile folder when it runs with a debugging port.
                var port = Path.Combine(userData, "DevToolsActivePort");
                if (File.Exists(port) && File.GetLastWriteTime(port) > since)
                    ctx.Add(Severity.Medium, "Sessions", $"{browser} was recently opened with remote debugging on your normal profile",
                        $"{port} (written {File.GetLastWriteTime(port):yyyy-MM-dd HH:mm})\nThe browser left this file because it ran with a debugging port on your real profile. Developers rarely do this on their main profile; stealers do it to read your sessions.",
                        "If that wasn't you, run a full check. " + SignOutEverywhere.Pointer, new { browser, port }, "T1539", "session.devtools-port");
                IEnumerable<string> profiles;
                try { profiles = Directory.GetDirectories(userData).Where(d => Path.GetFileName(d) is "Default" || Path.GetFileName(d).StartsWith("Profile ", StringComparison.Ordinal)).ToList(); } catch { continue; }
                foreach (var prof in profiles)
                    foreach (var (id, name, path) in UnpackedExtensions(prof))
                    {
                        bool risky = UserWritable.IsMatch(path + "\\") && !path.StartsWith(prof, StringComparison.OrdinalIgnoreCase);
                        rows.Add(new { Kind = "UnpackedExtension", browser, Profile = Path.GetFileName(prof), id, name, path, Exists = Directory.Exists(path) });
                        ctx.Add(risky ? Severity.High : Severity.Medium, "Sessions", $"Unpacked extension loaded in {browser}: {name}",
                            $"Extension {id} is loaded from {path} {(Directory.Exists(path) ? "" : "(folder no longer exists)")}, not from the store. Unpacked extensions skip the store's checks; stealer extensions are installed this way.",
                            $"If you don't develop extensions, remove it ({browser} > Extensions, with Developer mode on to see it) and run a full check. " + SignOutEverywhere.Pointer, new { browser, id, name, path }, "T1176", "session.unpacked-extension");
                    }
            }
    }

    /// <summary>Extensions in (Secure) Preferences with location 4 (unpacked) or a path outside the profile's Extensions folder.</summary>
    private static readonly Regex BrowserResources = new(@"^[A-Za-z]:\\.*\\Application\\\d+(\.\d+){3}\\resources\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    internal static IEnumerable<(string Id, string Name, string Path)> UnpackedExtensions(string profileDir)
    {
        var found = new Dictionary<string, (string, string, string)>();
        foreach (var file in new[] { "Secure Preferences", "Preferences" })
        {
            var p = Path.Combine(profileDir, file);
            try
            {
                if (!File.Exists(p) || new FileInfo(p).Length > 20_000_000) continue;
                using var doc = JsonDocument.Parse(File.ReadAllText(p), new JsonDocumentOptions { MaxDepth = 256 });
                if (!doc.RootElement.TryGetProperty("extensions", out var ext) || !ext.TryGetProperty("settings", out var settings) || settings.ValueKind != JsonValueKind.Object) continue;
                foreach (var e in settings.EnumerateObject())
                {
                    var v = e.Value;
                    if (v.ValueKind != JsonValueKind.Object) continue;
                    int loc = v.TryGetProperty("location", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetInt32() : 0;
                    var path = v.TryGetProperty("path", out var pe) && pe.ValueKind == JsonValueKind.String ? pe.GetString() ?? "" : "";
                    bool absolute = path.Length > 2 && (path[1] == ':' || path.StartsWith(@"\\"));
                    // Chromium locations: 4 = unpacked ("Load unpacked"), 8 = --load-extension. 5 and 10 are the browser's own
                    // component extensions (PDF viewer, Web Store, Brave/Edge helpers): they live in the browser's versioned
                    // resources folder, and old versions stay listed after an update. Those are only interesting if a
                    // component points anywhere else.
                    if (loc is 5 or 10 && BrowserResources.IsMatch(path)) continue;
                    if (loc is not (4 or 8) && !absolute) continue;
                    var name = v.TryGetProperty("manifest", out var m) && m.ValueKind == JsonValueKind.Object && m.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? e.Name : e.Name;
                    found[e.Name] = (e.Name, name, path);
                }
            }
            catch { }
        }
        return found.Values;
    }

    // ---------------------------------------------------------------- foreign programs inside browser folders
    // Stealers copy themselves into the browser's Application folder so Chrome's elevation service accepts them.
    private static void BrowserFolders(CheckContext ctx, List<object> rows)
    {
        var pf = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) };
        var apps = new (string Rel, Regex Signer)[] { (@"Google\Chrome\Application", new(@"^Google", O)), (@"Microsoft\Edge\Application", new(@"^Microsoft", O)), (@"BraveSoftware\Brave-Browser\Application", new(@"^Brave Software", O)) };
        foreach (var root in pf.Distinct(StringComparer.OrdinalIgnoreCase))
            foreach (var (rel, signer) in apps)
            {
                var dir = Path.Combine(root, rel);
                if (!Directory.Exists(dir)) continue;
                List<string> files;
                try { files = Directory.GetFiles(dir, "*.exe").Concat(Directory.GetFiles(dir, "*.dll")).Concat(Directory.GetDirectories(dir).SelectMany(d => { try { return Directory.GetFiles(d, "*.exe"); } catch { return Array.Empty<string>(); } })).Take(200).ToList(); }
                catch { continue; }
                foreach (var f in files)
                {
                    var fi = ctx.Files.Get(f, hash: false);
                    if (fi.IsSigned && (signer.IsMatch(fi.Signer ?? "") || fi.IsMicrosoft)) continue;
                    rows.Add(new { Kind = "BrowserFolderFile", File = f, fi.Signer, Status = fi.SignatureStatus.ToString() });
                    ctx.Add(Severity.High, "Sessions", $"Foreign program inside the browser's folder: {Path.GetFileName(f)}",
                        $"{f}\n{(fi.IsSigned ? $"Signed by {fi.Signer}, not by the browser's maker." : "Not validly signed.")} Browsers only put their own signed files here. Info stealers copy themselves into this folder to get past the browser's cookie protection.",
                        "Run a full check and reinstall the browser. " + SignOutEverywhere.Pointer, new { f, fi.Signer }, "T1574", "session.browser-folder");
                }
            }
    }

    // ---------------------------------------------------------------- what stealers leave behind
    // Weighted markers: files weigh 2, folders 1; a finding needs 5 points and at least one file. Names are matched
    // anywhere in the name ("Chrome Passwords.txt", "All Passwords.txt", "Roblox Cookies.txt").
    internal static readonly Regex StealerFile = new(@"(^|[ _\-])(Passwords?|Cookies?|Autofills?|CreditCards?|Cards|Tokens?|History|Wallets?|Logins?)\.txt$|^(User|System)[ _]?Info(rmation)?\.txt$|^Information\.txt$|^System\.txt$|^(Installed)?Software\.txt$|^InstalledBrowsers\.txt$|^Process(es|List)\.txt$|^DomainDetects\.txt$|^ImportantAutofills\.txt$|^Screen(shot)?\.(png|jpg)$|^Discord[ _]?Tokens?\.txt$", O);
    internal static readonly Regex StealerDir = new(@"^(Browsers?|Credentials|Cookies|Wallets?|Messenger|Telegram|Discord|Steam|Games|FileGrabber|Grabber|Autofills?|Passwords?|System|Chrome|Edge|Brave|Firefox|Opera|Roblox|Crypto)$", O);
    // Copies of session stores that belong only in their app's own folder.
    internal static readonly Regex SessionCopy = new(@"^(Login ?(Data|vault)( For Account)?|Cookies|Web ?Data|key4\.db|logins\.json|cookies\.sqlite|local\.vdf|loginusers\.vdf|RobloxCookies\.dat|launcher_accounts\.json|RiotGamesPrivateSettings\.yaml|recentservers\.xml)(\.db|\.sqlite|\.bak|_copy|\d*)?$", O);
    private static readonly Regex StealerHelperDll = new(@"^(sqlite3|nss3|mozglue|freebl3|softokn3|msvcp140|vcruntime140)\.dll$", O);
    private static readonly string[] LiveProfileSigns = { "Preferences", "First Run", "Last Version", "GrShaderCache", "Crashpad", "component_crx_cache", "Local State" };

    internal static int StealerScore(IEnumerable<string> fileNames, IEnumerable<string> dirNames, out List<string> markers)
    {
        markers = new List<string>();
        int files = 0, score = 0;
        foreach (var f in fileNames.Where(f => StealerFile.IsMatch(f)).Distinct(StringComparer.OrdinalIgnoreCase)) { files++; score += 2; markers.Add(f); }
        foreach (var d in dirNames.Where(d => StealerDir.IsMatch(d)).Distinct(StringComparer.OrdinalIgnoreCase)) { score += 1; markers.Add(d + "\\"); }
        return files > 0 ? score : 0;
    }

    internal static void StealerLeftovers(CheckContext ctx, List<object> rows, IEnumerable<string>? testRoots = null)
    {
        var since = DateTime.Now.AddDays(-30);
        var roots = new List<(string Dir, bool Temp)>();
        if (testRoots is not null) roots.AddRange(testRoots.Select(r => (r, true)));
        else
        {
            roots.Add((Path.Combine(Sys.SystemRoot, "Temp"), true));
            roots.Add((Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public", true));
            roots.Add((Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), false));
            foreach (var u in Sys.UserProfiles())
            {
                roots.Add((Path.Combine(u.Path, @"AppData\Local\Temp"), true));
                roots.Add((Path.Combine(u.Path, @"AppData\Roaming"), false));
                roots.Add((Path.Combine(u.Path, @"AppData\Local"), false));
            }
        }
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, temp) in roots.Where(r => Directory.Exists(r.Dir)).DistinctBy(r => r.Dir, StringComparer.OrdinalIgnoreCase))
        {
            int budget = 6000;
            foreach (var dir in new[] { root }.Concat(Dirs(root, temp ? 4 : 2, temp)))
            {
                if (ctx.Cancellation.IsCancellationRequested) return;
                if (--budget < 0) { CheckContext.Minor($"Stealer leftover search in {root} stopped after 6,000 folders"); break; }
                bool isRoot = dir.Equals(root, StringComparison.OrdinalIgnoreCase);
                DateTime changed; try { changed = Directory.GetLastWriteTime(dir); } catch { continue; }
                FileInfo[] files; string[] subdirs;
                try { files = new DirectoryInfo(dir).GetFiles(); subdirs = Directory.GetDirectories(dir).Select(d => Path.GetFileName(d)).ToArray(); } catch { continue; }
                var recentFiles = files.Where(f => { try { return f.LastWriteTime > since; } catch { return false; } }).ToList();
                if (!isRoot && changed < since && recentFiles.Count == 0) continue;

                // (a) Stealer log folder (its files, plus the files one level down, as in nested log layouts).
                if (!isRoot)
                {
                    var nested = new List<string>();
                    foreach (var sd in subdirs.Take(40)) try { nested.AddRange(Directory.GetFiles(Path.Combine(dir, sd)).Take(50).Select(f => Path.GetFileName(f))); } catch { }
                    var score = StealerScore(files.Select(f => f.Name).Concat(nested), subdirs, out var markers);
                    if (score >= 5 && reported.Add(dir))
                    {
                        var row = new { Kind = "StealerFolder", Folder = dir, Markers = markers, Changed = changed.ToString("s") };
                        rows.Add(row);
                        ctx.Add(Severity.High, "Sessions", "Folder that looks like stolen browser data waiting to be sent",
                            $"{dir}\nContains: {string.Join(", ", markers.Take(10))}\nChanged: {changed:yyyy-MM-dd HH:mm}\nInfo stealers collect passwords, cookies and wallets into a folder like this before uploading it. TriageKit didn't open the files.",
                            "Disconnect from the internet, run a full check and a second-opinion scanner. " + SignOutEverywhere.Pointer, row, "T1555.003", "session.stealer-folder");
                        continue;
                    }
                }
                // (b) Stealer helper libraries: the SQLite/NSS set stealers download to read browser databases.
                var helpers = files.Where(f => StealerHelperDll.IsMatch(f.Name)).Select(f => f.Name).ToList();
                if (helpers.Count >= 3 && !Regex.IsMatch(dir, @"Mozilla|Firefox|Thunderbird|SeaMonkey|LibreWolf|Waterfox|Zen Browser|Floorp", O) && reported.Add(dir + "|dll"))
                {
                    var row = new { Kind = "StealerHelpers", Folder = dir, Files = helpers };
                    rows.Add(row);
                    ctx.Add(Severity.High, "Sessions", "Libraries stealers use to read browser databases",
                        $"{dir}\nFound: {string.Join(", ", helpers)}\nThis set of libraries outside a Firefox-family install is what Vidar, StealC and similar stealers download to read saved passwords and cookies.",
                        "Run a full check. " + SignOutEverywhere.Pointer, row, "T1555.003", "session.stealer-helpers");
                }
                if (!temp) continue;
                // (c) Copied session stores in temporary/shared places.
                bool liveProfile = LiveProfileSigns.Count(n => files.Any(f => f.Name.Equals(n, StringComparison.OrdinalIgnoreCase)) || subdirs.Any(d => d.Equals(n, StringComparison.OrdinalIgnoreCase))) >= 2
                                   || Regex.IsMatch(dir, @"[\\/]EBWebView([\\/]|$)|\.WebView2([\\/]|$)|puppeteer|playwright|scoped_dir|chrome_profile", O);
                var copies = recentFiles.Where(f => SessionCopy.IsMatch(f.Name) && LooksLikeCopy(f, liveProfile)).Select(f => f.Name).ToList();
                if (subdirs.Any(d => d.Equals("tdata", StringComparison.OrdinalIgnoreCase)) && !files.Any(f => f.Name.Equals("Telegram.exe", StringComparison.OrdinalIgnoreCase)) && !dir.Contains("Telegram Desktop", StringComparison.OrdinalIgnoreCase))
                    copies.Add("tdata (Telegram session)");
                if (copies.Count > 0 && reported.Add(dir))
                {
                    var row = new { Kind = "SessionCopy", Folder = dir, Files = copies, LiveProfile = liveProfile };
                    rows.Add(row);
                    ctx.Add(Severity.High, "Sessions", liveProfile ? "Copy of a signed-in browser profile in a temporary folder" : "Copies of browser or app sessions in a temporary folder",
                        $"{dir}\nFound: {string.Join(", ", copies.Take(8))}\n{(liveProfile ? "A browser profile here holds real saved logins or cookies, not an empty test profile. Stealers copy your profile here and read it with a hidden browser." : "Browsers, Steam, Roblox, Riot and Telegram keep these files only in their own folders. A copy in a temporary folder is how stealers take over accounts without needing the password.")}",
                        "Run a full check. " + SignOutEverywhere.Pointer, row, "T1539", "session.copied");
                }
                // (d) Archives of stolen data (names inside the ZIP only; nothing is extracted).
                foreach (var z in recentFiles.Where(f => f.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) && f.Length < 60_000_000).Take(30))
                {
                    try
                    {
                        using var zip = ZipFile.OpenRead(z.FullName);
                        var names = zip.Entries.Take(2000).Select(e => e.FullName.Replace('\\', '/')).ToList();
                        var fileNames = names.Where(n => !n.EndsWith('/')).Select(n => n.Split('/').Last());
                        var dirNames = names.SelectMany(n => n.Split('/').SkipLast(1)).Distinct(StringComparer.OrdinalIgnoreCase);
                        var score = StealerScore(fileNames, dirNames, out var markers);
                        if (score >= 5 && reported.Add(z.FullName))
                        {
                            var row = new { Kind = "StealerArchive", File = z.FullName, Markers = markers };
                            rows.Add(row);
                            ctx.Add(Severity.High, "Sessions", "Archive that looks like stolen browser data",
                                $"{z.FullName}\nContains: {string.Join(", ", markers.Take(10))}\nInfo stealers pack passwords, cookies and wallets into an archive like this before uploading. TriageKit read only the list of names.",
                                "Disconnect from the internet and run a full check. " + SignOutEverywhere.Pointer, row, "T1560", "session.stealer-archive");
                        }
                    }
                    catch { }
                }
            }
        }
    }

    /// <summary>
    /// A session store counts as a copy when it really holds data: browser databases must be SQLite files, and inside a
    /// live (automation or WebView2) profile only populated ones count, since a blank test profile holds nothing.
    /// </summary>
    private static bool LooksLikeCopy(FileInfo f, bool liveProfile)
    {
        try
        {
            bool db = Regex.IsMatch(f.Name, @"^(Login ?(Data|vault)|Cookies|Web ?Data|key4\.db|cookies\.sqlite)", O);
            if (!db) return !liveProfile;
            var head = new byte[16];
            using (var s = new FileStream(f.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) if (s.Read(head, 0, 16) < 16) return false;
            if (System.Text.Encoding.ASCII.GetString(head, 0, 15) != "SQLite format 3") return false;
            return !liveProfile || f.Length > (f.Name.StartsWith("Cookies", StringComparison.OrdinalIgnoreCase) ? 256 * 1024 : 64 * 1024);
        }
        catch { return false; }
    }

    private static readonly Regex OwnLocations = new(@"[\\/](Google[\\/]Chrome[\\/]User Data|Microsoft[\\/]Edge[\\/]User Data|BraveSoftware[\\/]Brave-Browser[\\/]User Data|Mozilla[\\/]Firefox[\\/]Profiles|Packages|Microsoft[\\/]Windows|node_modules|\.git)([\\/]|$)", O);

    private static IEnumerable<string> Dirs(string root, int depth, bool temp)
    {
        var stack = new Stack<(string, int)>(); stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (d, level) = stack.Pop();
            if (level > 0) yield return d;
            if (level >= depth) continue;
            string[] subs;
            try { subs = Directory.GetDirectories(d); } catch { continue; }
            foreach (var s in subs)
            {
                try { if (new DirectoryInfo(s).Attributes.HasFlag(FileAttributes.ReparsePoint)) continue; } catch { continue; }
                // AppData\Local\Temp is its own root; the browsers' real data folders are where these names belong.
                if (!temp && (Regex.IsMatch(s, @"[\\/]Temp$", O) || OwnLocations.IsMatch(s))) continue;
                if (temp && Regex.IsMatch(s, @"[\\/](node_modules|\.git)$", O)) continue;
                stack.Push((s, level + 1));
            }
        }
    }

    // ---------------------------------------------------------------- browsers that stopped updating
    private static void OldBrowsers(CheckContext ctx, List<object> rows)
    {
        var pf = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) };
        var candidates = new List<(string Browser, string Exe)>();
        foreach (var root in pf)
        {
            candidates.Add(("Chrome", Path.Combine(root, @"Google\Chrome\Application\chrome.exe")));
            candidates.Add(("Edge", Path.Combine(root, @"Microsoft\Edge\Application\msedge.exe")));
            candidates.Add(("Brave", Path.Combine(root, @"BraveSoftware\Brave-Browser\Application\brave.exe")));
        }
        foreach (var u in Sys.UserProfiles()) candidates.Add(("Chrome", Path.Combine(u.Path, @"AppData\Local\Google\Chrome\Application\chrome.exe")));
        foreach (var (browser, exe) in candidates.Where(c => File.Exists(c.Exe)).DistinctBy(c => c.Exe, StringComparer.OrdinalIgnoreCase))
        {
            int major; DateTime built;
            try { major = FileVersionInfo.GetVersionInfo(exe).FileMajorPart; built = File.GetLastWriteTime(exe); } catch { continue; }
            var age = (DateTime.Now - built).TotalDays;
            bool waiting = File.Exists(Path.Combine(Path.GetDirectoryName(exe)!, "new_" + Path.GetFileName(exe)));
            rows.Add(new { Kind = "Browser", browser, Path = exe, Major = major, AgeDays = (int)age, UpdateWaiting = waiting });
            if (waiting)
                ctx.Add(Severity.Low, "Sessions", $"{browser} update is waiting for a restart", $"{exe}\nThe new version is downloaded but only becomes active when {browser} is closed completely.",
                    $"Close all {browser} windows (and its tray icon), then open it again.", new { browser, exe }, null, "session.browser-update-waiting");
            else if (age > 120 || (browser == "Chrome" && major is > 0 and < 127))
                ctx.Add(Severity.Medium, "Sessions", $"{browser} hasn't updated for {(int)(age / 30)} months (version {major})",
                    $"{exe}\nBrowsers update every few weeks; this one is out of date. Newer versions make cookie theft much harder (app-bound encryption, Chrome 127 and later) and fix many security holes.",
                    $"Update {browser} (Menu > Help > About) or uninstall it if you don't use it.", new { browser, exe, major }, "T1539", "session.old-browser");
        }
    }
}

/// <summary>Online account protection beyond the browser: hosts redirects, fake installers, cheat loaders, app tampering.</summary>
[SupportedOSPlatform("windows")]
internal static class GamingAccounts
{
    private const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    internal static readonly Regex Platforms = new(@"(^|\.)(steamcommunity\.com|steampowered\.com|steamstatic\.com|steamcontent\.com|steamusercontent\.com|steam-chat\.com|valvesoftware\.com|discord\.com|discordapp\.com|discord\.gg|discordapp\.net|discord\.media|epicgames\.com|epicgames\.dev|unrealengine\.com|battle\.net|blizzard\.com|riotgames\.com|leagueoflegends\.com|playvalorant\.com|roblox\.com|rbxcdn\.com|ea\.com|origin\.com|ubisoft\.com|ubi\.com|rockstargames\.com|gog\.com|nintendo\.com|xbox\.com|xboxlive\.com|playstation\.com|twitch\.tv|faceit\.com|minecraft\.net|mojang\.com|accounts\.google\.com|login\.live\.com|login\.microsoftonline\.com|paypal\.com)$", O);

    /// <summary>True when a hosts line names one of the account sites (the Network check leaves those to this check).</summary>
    public static bool MentionsPlatform(string hostsLine) =>
        hostsLine.Split('#')[0].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Skip(1).Any(n => Platforms.IsMatch(n.TrimEnd('.')));

    public static void Hosts(CheckContext ctx, List<object> rows, string[]? testLines = null)
    {
        // Windows can be told to read the hosts file from another folder.
        var defaultDir = Path.Combine(Environment.SystemDirectory, @"drivers\etc");
        var dbPath = testLines is null ? Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DataBasePath") as string : null;
        var dir = string.IsNullOrWhiteSpace(dbPath) ? defaultDir : Environment.ExpandEnvironmentVariables(dbPath);
        if (testLines is null && !string.Equals(Path.GetFullPath(dir).TrimEnd('\\'), Path.GetFullPath(defaultDir).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            ctx.Add(Severity.High, "Sessions", "Windows reads its hosts file from an unusual folder",
                $"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\DataBasePath = {dbPath}\nThe hosts file decides where website names lead. Moving it elsewhere hides redirects from people and tools that check the normal one.",
                @"Set DataBasePath back to %SystemRoot%\System32\drivers\etc, check the hosts file in the other folder, and run a full check.", new { dbPath }, "T1565.001", "gaming.hosts-moved");
        var hosts = Path.Combine(dir, "hosts");
        string[] lines; try { lines = testLines ?? File.ReadAllLines(hosts); } catch { return; }
        var groups = new Dictionary<(string Verdict, string Ip), List<string>>();
        foreach (var raw in lines)
        {
            var line = raw.Split('#')[0].Trim();
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var ip = parts[0];
            var names = parts.Skip(1).Select(n => n.TrimEnd('.')).Where(n => Platforms.IsMatch(n)).ToList();
            if (names.Count == 0 || !IPAddress.TryParse(ip, out var addr)) continue;
            var verdict = addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(addr) ? "local" : IsPrivate(addr) ? "network" : "internet";
            if (!groups.TryGetValue((verdict, ip), out var list)) groups[(verdict, ip)] = list = new();
            list.AddRange(names);
        }
        foreach (var ((verdict, ip), names) in groups)
        {
            var distinct = names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var shown = string.Join(", ", distinct.Take(8)) + (distinct.Count > 8 ? $" and {distinct.Count - 8} more" : "");
            var row = new { Kind = "Hosts", Ip = ip, Names = distinct, Verdict = verdict };
            rows.Add(row);
            switch (verdict)
            {
                case "internet":
                    ctx.Add(Severity.High, "Sessions", $"Account sites are redirected to another server ({ip})",
                        $"{hosts}: {shown} → {ip}\nVisits to these sites from this PC go to {ip} instead of the real servers. That's a classic way to steal game, chat and email logins with a perfect-looking fake page.",
                        "Remove these lines from the hosts file (as administrator) and run a full check. " + SignOutEverywhere.Pointer, row, "T1565.001", "gaming.hosts-redirect");
                    break;
                case "network":
                    ctx.Add(Severity.Medium, "Sessions", $"Account sites are sent to a device on your network ({ip})",
                        $"{hosts}: {shown} → {ip}\nGame download caches (such as LanCache) do this on purpose. If you don't run one, something on this PC or your network is intercepting these sites.",
                        "Remove the lines unless you set up a download cache.", row, "T1565.001", "gaming.hosts-lan");
                    break;
                default:
                    ctx.Add(Severity.Low, "Sessions", $"Account sites are sent to this PC itself ({ip})",
                        $"{hosts}: {shown} → {ip}\nEither they're blocked, or a program on this PC handles them as a local proxy (tools like Watt Toolkit/Steam++ do this, and so does malware that wants to stop updates or read logins).",
                        "If you don't use such a tool and didn't block these sites yourself, remove the lines (edit the hosts file as administrator).", row, "T1565.001", "gaming.hosts-local");
                    break;
            }
        }
    }

    private static bool IsPrivate(IPAddress a)
    {
        if (a.AddressFamily == AddressFamily.InterNetworkV6) return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6UniqueLocal;
        var b = a.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
    }

    // Installers people download, and who really signs them. Exact signer names (the publisher's legal name on the
    // certificate), so look-alike company names don't pass.
    internal static readonly (Regex Name, Regex Signer, string App)[] Installers =
    {
        (new(@"^SteamSetup.*\.exe$", O), new(@"^Valve( Corp\.?| Corporation)?$", O), "Steam"),
        (new(@"^DiscordSetup.*\.exe$", O), new(@"^Discord,? Inc\.?$", O), "Discord"),
        (new(@"^OBS[-_ ]?Studio[-_ ].*(Installer|Setup|x64|Windows).*\.exe$", O), new(@"^(OBS Project|Hugh Bailey|Wizards of OBS,? LLC)$", O), "OBS Studio"),
        (new(@"^(ChromeSetup|ChromeStandaloneSetup(64)?|GoogleChromeStandaloneEnterprise(64)?)\.(exe|msi)$", O), new(@"^Google LLC$", O), "Google Chrome"),
        (new(@"^(EpicInstaller|EpicGamesLauncherInstaller).*\.(exe|msi)$", O), new(@"^Epic Games,? Inc\.?$", O), "Epic Games Launcher"),
        (new(@"^Battle\.net-Setup.*\.exe$", O), new(@"^Blizzard Entertainment,? Inc\.?$", O), "Battle.net"),
        (new(@"^Install (League of Legends|VALORANT|Riot Client).*\.exe$", O), new(@"^Riot Games,? Inc\.?$", O), "Riot Client"),
        (new(@"^(EAappInstaller|OriginThinSetup).*\.exe$", O), new(@"^Electronic Arts,? Inc\.?$", O), "EA app"),
        (new(@"^RobloxPlayer(Launcher|Installer)?.*\.exe$|^RobloxStudio(Launcher|Installer).*\.exe$", O), new(@"^Roblox Corporation$", O), "Roblox"),
        (new(@"^MinecraftInstaller.*\.(exe|msi)$", O), new(@"^(Microsoft Corporation|Mojang AB)$", O), "Minecraft"),
        (new(@"^TeamViewer(_| )?(Setup|QS|Host_Setup).*\.exe$|^TeamViewerQS.*\.exe$", O), new(@"^TeamViewer (Germany )?GmbH$", O), "TeamViewer"),
        (new(@"^AnyDesk.*\.(exe|msi)$", O), new(@"^(AnyDesk Software GmbH|philandro Software GmbH)$", O), "AnyDesk"),
        (new(@"^rustdesk.*\.(exe|msi)$", O), new(@"^(Purslane Ltd\.?|RustDesk.*)$", O), "RustDesk"),
        (new(@"^ScreenConnect\.ClientSetup.*\.(exe|msi)$", O), new(@"^ConnectWise,? (LLC|Inc\.?)$", O), "ScreenConnect"),
        (new(@"^(SpotifySetup|SpotifyFullSetup).*\.exe$", O), new(@"^Spotify AB$", O), "Spotify"),
        (new(@"^(ZoomInstaller|ZoomInstallerFull).*\.(exe|msi)$", O), new(@"^Zoom (Video Communications|Communications),? Inc\.?$", O), "Zoom"),
        (new(@"^(tsetup|Telegram ?Setup)[-_ x.0-9]*\.exe$", O), new(@"^Telegram FZ-LLC$", O), "Telegram"),
        (new(@"^vlc-[0-9.]+-win(32|64)\.exe$", O), new(@"^VideoLAN$", O), "VLC"),
        (new(@"^MSIAfterburnerSetup.*\.exe$", O), new(@"^Micro-Star International.*$", O), "MSI Afterburner"),
        (new(@"^(NVIDIA_app|GeForce_Experience).*\.exe$|^[0-9.]+-desktop-win1[01]-win64-.*\.exe$", O), new(@"^NVIDIA Corporation$", O), "NVIDIA driver/app"),
        (new(@"^(amd-software-adrenalin|whql-amd-software).*\.exe$", O), new(@"^Advanced Micro Devices,? Inc\.?$", O), "AMD Software"),
    };

    // Cheats, cracks and "free Robux" tools: whole words only, and generic words like "loader" or "trainer" only next to
    // a game name, so "bootloader-flash.exe" or "TypingTrainer.exe" don't count.
    internal static readonly Regex CheatName = new(
        @"(^|[^a-z])(cheats?|hacks?|aimbot|wallhack|triggerbot|esp[-_ ]?(hack|cheat)|injector|executor|spoofer|keygen|robux|v-?bucks|free[-_ ]?skins|mod[-_ ]?menu|krnl|synapse[-_ ]?x|fluxus|solara|xeno[-_ ]?executor|celery[-_ ]?executor|jjsploit)([^a-z]|$)" +
        @"|(roblox|fortnite|valorant|cs2|csgo|gta|minecraft|apex|warzone|rust|pubg)[-_ ]?(loader|trainer|crack|inject(or)?|hack|cheat|unlocker)" +
        @"|(loader|trainer|crack|unlocker)[-_ ]?(roblox|fortnite|valorant|cs2|csgo|gta|minecraft|apex|warzone|rust|pubg)", O);

    public static void Downloads(CheckContext ctx, List<object> rows)
    {
        var since = DateTime.Now.AddDays(-180);
        var cheatSince = DateTime.Now.AddDays(-60);
        foreach (var u in Sys.UserProfiles())
        {
            var dir = UserFolders.Downloads(u);
            if (!Directory.Exists(dir)) continue;
            List<FileInfo> files;
            try { files = new DirectoryInfo(dir).EnumerateFiles("*", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2, IgnoreInaccessible = true }).Where(f => Regex.IsMatch(f.Extension, @"^\.(exe|msi|scr|com)$", O)).Take(3000).ToList(); }
            catch { continue; }
            foreach (var f in files)
            {
                if (ctx.Cancellation.IsCancellationRequested) return;
                var known = Installers.FirstOrDefault(i => i.Name.IsMatch(f.Name));
                DateTime when; try { when = f.LastWriteTime > f.CreationTime ? f.LastWriteTime : f.CreationTime; } catch { continue; }
                bool cheat = known.Name is null && CheatName.IsMatch(Path.GetFileNameWithoutExtension(f.Name)) && when > cheatSince;
                if ((known.Name is null || when < since) && !cheat) continue;
                var intel = ctx.Files.Get(f.FullName, hash: false);
                var origin = DownloadOrigin(f.FullName);
                var from = origin is null ? "" : $" It was downloaded from {origin}.";
                if (known.Name is not null)
                {
                    var signer = intel.Signer ?? "";
                    bool genuine = intel.IsSigned && known.Signer.IsMatch(signer) && (!signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) || intel.IsMicrosoft);
                    var row = new { Kind = "Installer", File = f.FullName, known.App, intel.Signer, Status = intel.SignatureStatus.ToString(), Genuine = genuine, Origin = origin };
                    rows.Add(row);
                    if (genuine) continue;
                    if (intel.IsSigned)
                        ctx.Add(Severity.High, "Sessions", $"Fake {known.App} installer in Downloads: {f.Name}",
                            $"{f.FullName}\nIt's signed by \"{intel.Signer}\", not by the company that makes {known.App}.{from} Fake installers of popular apps are one of the most common ways info stealers spread.",
                            $"Don't run it. Delete it and download {known.App} only from its official website. If you already ran it, run a full check. " + SignOutEverywhere.Pointer, row, "T1036.005", "gaming.fake-installer");
                    else
                        ctx.Add(Severity.Medium, "Sessions", $"{f.Name} is named like the {known.App} installer but isn't validly signed",
                            $"{f.FullName}\nSignature: {Describe(intel.SignatureStatus)}.{from} Current {known.App} installers are signed by their maker. An old download can have an expired signature; a fake one usually has none.",
                            $"Delete it and download {known.App} again from its official website. If you already ran it and something seemed off, run a full check.", row, "T1036.005", "gaming.unsigned-installer");
                    continue;
                }
                if (intel.IsSigned) continue;   // signed tools (trainers from known vendors) aren't the problem
                var crow = new { Kind = "Cheat", File = f.FullName, Date = when.ToString("s"), Origin = origin };
                rows.Add(crow);
                ctx.Add(Severity.Medium, "Sessions", $"Unsigned file named like a cheat, executor or crack: {f.Name}",
                    $"{f.FullName}\nSaved {when:yyyy-MM-dd}.{from} Free cheats, executors, cracks and \"free Robux/V-Bucks\" tools are the most common way gamers lose their accounts: many are info stealers in disguise. Cheats can also get a game account banned.",
                    "If you ran it, run a full check with archives on. Otherwise just delete it. " + SignOutEverywhere.Pointer, crow, "T1204.002", "gaming.cheat-tool");
            }
        }
    }

    private static string Describe(Intel.SignatureStatus s) => s switch
    {
        Intel.SignatureStatus.NotSigned => "not signed",
        Intel.SignatureStatus.Expired => "signed, but the certificate has expired",
        Intel.SignatureStatus.Revoked => "signed with a certificate that was revoked",
        Intel.SignatureStatus.HashMismatch => "signed, but the file was changed after signing",
        Intel.SignatureStatus.Untrusted => "signed with a certificate Windows doesn't trust",
        _ => s.ToString(),
    };

    /// <summary>Host the file was downloaded from (Windows' "Mark of the Web" Zone.Identifier stream), or null.</summary>
    internal static string? DownloadOrigin(string path)
    {
        try
        {
            var text = File.ReadAllText(path + ":Zone.Identifier");
            var url = Regex.Match(text, @"^(HostUrl|ReferrerUrl)=(\S+)", RegexOptions.Multiline).Groups[2].Value;
            return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Host.Length > 0 ? u.Host : null;
        }
        catch { return null; }
    }

    // ---------------------------------------------------------------- apps changed after install (Steam, Battle.net, wallets)
    public static void AppTampering(CheckContext ctx, List<object> rows)
    {
        // Steam: debugging marker and DLLs planted next to steam.exe (side-loading).
        var steam = (Reg.Value(Registry.CurrentUser, @"Software\Valve\Steam", "SteamPath") as string)?.Replace('/', '\\')
                    ?? Reg.Value(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath") as string;
        if (steam is not null && Directory.Exists(steam))
        {
            var marker = Path.Combine(steam, ".cef-enable-remote-debugging");
            if (File.Exists(marker))
                ctx.Add(Severity.Medium, "Sessions", "Steam's built-in browser is set to allow remote debugging",
                    $"{marker}\nWith this file, other programs can read Steam's browser, including your signed-in session. Some skin and plugin tools create it; so do Steam session stealers.",
                    "Delete the file unless a Steam skin or plugin tool you use needs it. " + SignOutEverywhere.Pointer, new { marker }, "T1539", "session.steam-debug");
            foreach (var dll in new[] { "hid.dll", "version.dll", "winmm.dll", "dwmapi.dll", "user32.dll", "dinput8.dll", "winhttp.dll", "wininet.dll", "iphlpapi.dll" })
            {
                var p = Path.Combine(steam, dll);
                if (!File.Exists(p)) continue;
                var fi = ctx.Files.Get(p, hash: false);
                if (fi.IsSigned && Regex.IsMatch(fi.Signer ?? "", @"^Valve", O)) continue;
                rows.Add(new { Kind = "SteamSideload", File = p, fi.Signer });
                ctx.Add(Severity.High, "Sessions", $"Planted library next to Steam: {dll}",
                    $"{p}\n{(fi.IsSigned ? $"Signed by {fi.Signer}." : "Not validly signed.")} Windows loads a DLL with this name from Steam's folder before its own, so it runs inside Steam with access to your account. Steam doesn't ship this file here.",
                    "Run a full check, then delete the file and verify Steam's files (or reinstall Steam). " + SignOutEverywhere.Pointer, new { p, fi.Signer }, "T1574.001", "session.steam-sideload");
            }
        }
        // Battle.net agent folder: only Blizzard-signed programs belong there.
        var agent = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Battle.net\Agent");
        if (Directory.Exists(agent))
        {
            List<string> exes; try { exes = Directory.EnumerateFiles(agent, "*.exe", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 2, IgnoreInaccessible = true }).Take(50).ToList(); } catch { exes = new(); }
            foreach (var e in exes)
            {
                var fi = ctx.Files.Get(e, hash: false);
                if (fi.IsSigned && Regex.IsMatch(fi.Signer ?? "", @"^Blizzard", O)) continue;
                ctx.Add(Severity.High, "Sessions", $"Foreign program in Battle.net's agent folder: {Path.GetFileName(e)}", $"{e}\n{(fi.IsSigned ? $"Signed by {fi.Signer}." : "Not validly signed.")} Only Blizzard's own programs belong here.",
                    "Run a full check and reinstall Battle.net. " + SignOutEverywhere.Pointer, new { e, fi.Signer }, "T1574", "session.battlenet-foreign");
            }
        }
        // Wallet and chat apps whose code (app.asar) changed long after the app itself: the way wallet-draining
        // malware patches Exodus, Atomic and similar apps.
        foreach (var u in Sys.UserProfiles())
            foreach (var (app, rel) in new[] { ("Exodus", @"AppData\Local\exodus"), ("Atomic Wallet", @"AppData\Local\Programs\atomic"), ("Ledger Live", @"AppData\Local\Programs\ledger-live-desktop"), ("Signal", @"AppData\Local\Programs\signal-desktop") })
            {
                var root = Path.Combine(u.Path, rel);
                if (!Directory.Exists(root)) continue;
                List<string> asars;
                try { asars = Directory.EnumerateFiles(root, "app.asar", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3, IgnoreInaccessible = true }).Take(5).ToList(); } catch { continue; }
                foreach (var asar in asars)
                {
                    var appDir = Path.GetDirectoryName(Path.GetDirectoryName(asar)!)!;
                    FileInfo? exe; try { exe = Directory.GetFiles(appDir, "*.exe").Select(p => new FileInfo(p)).OrderByDescending(f => f.Length).FirstOrDefault(); } catch { continue; }
                    if (exe is null) continue;
                    var gap = File.GetLastWriteTime(asar) - exe.LastWriteTime;
                    if (gap < TimeSpan.FromHours(1)) continue;
                    rows.Add(new { Kind = "AppAsar", app, asar, Exe = exe.FullName, GapHours = (int)gap.TotalHours });
                    bool wallet = app is "Exodus" or "Atomic Wallet" or "Ledger Live";
                    ctx.Add(Severity.High, "Sessions", $"{app}'s program code was changed after it was installed",
                        $"{asar} changed {gap.TotalHours:0} hours after {exe.Name}. Updates replace both together; malware that steals crypto or messages patches only this file.",
                        $"Uninstall {app}, run a full check, reinstall from the official site{(wallet ? ", and move your funds to a new wallet with a new recovery phrase" : "")}. " + SignOutEverywhere.Pointer, new { app, asar }, "T1554", "session.app-patched");
                }
            }
    }

    // ---------------------------------------------------------------- what an infection would expose (one Info card)
    public static void Exposure(CheckContext ctx, List<object> rows)
    {
        var present = new List<string>();
        foreach (var u in Sys.UserProfiles())
        {
            void Has(string label, params string[] rels) { if (rels.Any(r => Directory.Exists(Path.Combine(u.Path, r)) || File.Exists(Path.Combine(u.Path, r)))) present.Add(label); }
            Has("Exodus wallet", @"AppData\Roaming\Exodus\exodus.wallet");
            Has("Atomic wallet", @"AppData\Roaming\atomic");
            Has("Electrum wallet", @"AppData\Roaming\Electrum\wallets");
            Has("Bitcoin Core wallet", @"AppData\Roaming\Bitcoin\wallet.dat", @"AppData\Roaming\Bitcoin\wallets");
            Has("Ledger Live", @"AppData\Roaming\Ledger Live");
            Has("Guarda wallet", @"AppData\Roaming\Guarda");
            Has("Wasabi wallet", @"AppData\Roaming\WalletWasabi");
        }
        var wallets = present.Distinct().ToList();
        rows.Add(new { Kind = "Wallets", Present = wallets });
        if (wallets.Count > 0)
            ctx.Add(Severity.Info, "Sessions", $"Crypto wallets on this PC: {string.Join(", ", wallets)}",
                "Info stealers look for wallets first, because a stolen wallet can be emptied instantly and for good.",
                "Keep the recovery phrase offline (never as a plain file, screenshot or clipboard text), use a hardware wallet for larger amounts, and keep this PC clean.", new { wallets }, "T1555.003", "session.wallet");
    }
}
