using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

/// <summary>
/// "Paste this to verify you're human" scams (ClickFix / fake CAPTCHA) get people to press Win+R and paste a command.
/// Windows remembers what was typed in the Run box (RunMRU) and the Explorer address bar (TypedPaths), so the trace
/// survives even after the malware deletes its own files.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RunHistoryCheck : ICheck
{
    public string Name => "Run box history";

    private const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    // Programs that run commands or code. Word boundaries everywhere: "irm" must not match inside "confirm".
    private static readonly Regex Launcher = new(@"\b(powershell|pwsh)(\.exe)?\b|\bcmd(\.exe)?\s+/[ck]\b|\b(mshta|conhost|rundll32|regsvr32|msiexec|certutil|bitsadmin|wscript|cscript|forfiles|hh|pcalua|odbcconf|installutil|msbuild|wmic|finger|syncappvpublishingserver)(\.exe|\.vbs)?\b", O);
    // Launchers that are dangerous as soon as they point at the internet.
    private static readonly Regex RemoteLauncher = new(@"\b(mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|hh|pcalua|odbcconf|installutil|wscript|cscript|msbuild)(\.exe)?\b", O);
    private static readonly Regex Download = new(@"\b(iwr|irm|curl|wget)\b|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|\bbitsadmin\b.*/transfer|\bcertutil\b.*-urlcache", O);
    // The internet: web/ftp URLs, WebDAV shares (\\host@ssl\..., \\host@80\..., DavWWWRoot) and bare IP addresses.
    // A plain \\server\share is the local network (software deployment, printers) and doesn't count.
    private static readonly Regex Internet = new(@"https?://|ftp://|\\\\[^\\\s]+@(ssl|\d+)(@\d+)?\\|davwwwroot|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?/", O);
    // mshta/hh also accept an address without "http://" ("mshta evil.example/a").
    private static readonly Regex SchemelessHost = new(@"\b(mshta|hh)(\.exe)?\s+(?![a-z]:\\|\\\\)[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?/", O);
    // A program opened straight from a WebDAV share, with no launcher in front.
    private static readonly Regex WebDavProgram = new(@"^\s*\\\\[^\\\s]+@(ssl|\d+)(@\d+)?\\\S*\.(exe|hta|bat|cmd|ps1|vbs|js|jse|wsf|msi|lnk|scr|cpl)\b", O);
    private static readonly Regex FingerPipe = new(@"\bfinger(\.exe)?\s+\S+@\S+.*\|\s*(cmd|powershell|pwsh)\b", O);
    private static readonly Regex Hidden = new(@"\biex\b|invoke-expression|\s[-/]e[a-z]*\s+[A-Za-z0-9+/=]{16,}|frombase64string|\s[-/]w(indowstyle)?\s+h(idden)?\b|conhost(\.exe)?\s+--headless|\|\s*(powershell|pwsh|cmd|iex)\b", O);
    // Words the scam pages put after the command ("# I am not a robot - Verification ID 4471"). Checked with URLs and
    // file paths removed, so a link to a real CAPTCHA page or a folder named "Cloudflare" doesn't count.
    private static readonly Regex Lure = new(@"i am not a robot|i'?m not a robot|verification (id|code)|human verification|verify you are human|captcha|cloudflare|ray id|✅|✔", O);
    private static readonly Regex UrlOrPath = new(@"(https?|ftp)://\S+|[a-z]:\\[^""'\s]*|\\\\[^""'\s]+", O);

    /// <summary>Undoes common obfuscation: cmd carets (p^o^w^e^r), PowerShell backticks and quote/concatenation tricks ("pow"+"ershell").</summary>
    internal static string Normalize(string cmd) => Regex.Replace(cmd.Replace("^", "").Replace("`", ""), @"[""']\s*\+\s*[""']|[""']", "");

    public object? Run(CheckContext ctx)
    {
        var rows = new List<object>();
        foreach (var sid in Reg.LoadedUserSids())
        {
            if (ctx.Cancellation.IsCancellationRequested) break;
            var user = Sys.AccountName(sid) ?? sid;
            foreach (var (name, value) in Reg.Values(Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
            {
                if (name.Equals("MRUList", StringComparison.OrdinalIgnoreCase) || value is not string raw) continue;
                var cmd = raw.EndsWith("\\1") ? raw[..^2] : raw;
                Judge(ctx, rows, user, "Run box (Win+R)", cmd);
            }
            foreach (var (_, value) in Reg.Values(Registry.Users, $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"))
                if (value is string typed) Judge(ctx, rows, user, "Explorer address bar", typed);
        }
        return new { Entries = rows };
    }

    /// <summary>
    /// High: a command line that downloads and runs something, a code launcher pointed at the internet, or a launcher
    /// with the scam's "I am not a robot" text. Medium: a hidden or encoded shell command. Low: a plain download
    /// command. Plain URLs, file paths and ordinary commands are not judged.
    /// </summary>
    public static Severity? Assess(string cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return null;
        var n = Normalize(cmd);
        if (WebDavProgram.IsMatch(n) || FingerPipe.IsMatch(n)) return Severity.High;
        bool launcher = Launcher.IsMatch(n), download = Download.IsMatch(n), hidden = Hidden.IsMatch(n);
        bool internet = Internet.IsMatch(n) || SchemelessHost.IsMatch(n);
        bool lure = Lure.IsMatch(UrlOrPath.Replace(cmd, " "));
        if (!launcher && !download) return null;   // a website, a folder, an app name
        if (launcher && download) return Severity.High;
        if (launcher && internet && (hidden || lure || RemoteLauncher.IsMatch(n))) return Severity.High;
        if (launcher && lure) return Severity.High;
        if (launcher && hidden) return Severity.Medium;
        if (download && internet) return Severity.Low;
        return null;
    }

    private static void Judge(CheckContext ctx, List<object> rows, string user, string where, string cmd)
    {
        var sev = Assess(cmd);
        rows.Add(new { User = user, Where = where, Command = Sys.Trunc(cmd, 400), Flagged = sev?.ToString() });
        if (sev is null) return;
        var what = sev == Severity.Low ? "A download command was typed into" : "Suspicious command was pasted into";
        ctx.Add(sev.Value, "Persistence", $"{what} the {where}",
            $"User: {user}\nCommand: {Sys.Trunc(cmd, 600)}",
            sev == Severity.Low
                ? "If you typed this yourself, accept this finding. If you don't recognise it, check what was downloaded and run a full check."
                : "This matches the fake \"verify you are human\" scam that tricks people into running a download command. If you didn't type this yourself: disconnect from the internet, run a full check, change passwords from another device, and sign out of all sessions on important accounts.",
            new { User = user, Where = where, Command = Sys.Trunc(cmd, 2000) }, "T1204.004", "clickfix.run-history");
    }
}
