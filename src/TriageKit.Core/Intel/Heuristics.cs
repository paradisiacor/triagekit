using System.Text.RegularExpressions;
using TriageKit.Core.Engine;

namespace TriageKit.Core.Intel;

/// <summary>Pure, platform-independent heuristics (unit tested on any OS).</summary>
public static class PathHeuristics
{
    private const RegexOptions O = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;
    private static readonly Regex[] Suspicious =
    {
        new(@"\\AppData\\Local\\Temp\\", O), new(@"\\Windows\\Temp\\", O), new(@"\\Users\\Public\\", O),
        new(@"\\Downloads\\", O), new(@"\\\$Recycle\.Bin\\", O), new(@"\\PerfLogs\\", O), new(@"\\Windows\\Tasks\\", O),
        new(@"\\Windows\\debug\\", O), new(@"\\Windows\\Fonts\\.*\.(exe|dll)$", O),
        // Executables dropped directly in the root of ProgramData / AppData are unusual for real software.
        new(@"\\ProgramData\\[^\\]+\.(exe|dll|scr|ps1|vbs|js|bat|cmd)$", O),
        new(@"\\AppData\\(Roaming|Local|LocalLow)\\[^\\]+\.(exe|dll|scr|ps1|vbs|js|bat|cmd)$", O),
    };

    public static bool IsSuspicious(string? path) => !string.IsNullOrEmpty(path) && Suspicious.Any(r => r.IsMatch(path));

    public static bool IsUserWritable(string? path) =>
        !string.IsNullOrEmpty(path) && Regex.IsMatch(path, @"\\(Users|ProgramData|Windows\\Temp)\\", O);

    /// <summary>Risk of an executable that runs automatically or is running now.</summary>
    public static string ExecutableRisk(FileIntel? f)
    {
        if (f is null) return Risk.Info;
        if (!f.Exists) return Risk.Low;                             // broken/orphaned entry
        if (f.SignatureStatus == SignatureStatus.HashMismatch) return Risk.Critical; // tampered signed file
        if (f.IsSigned) return f.Suspicious ? Risk.Low : Risk.Info;
        if (f.Suspicious) return Risk.High;
        if (IsUserWritable(f.Path)) return Risk.Medium;
        return Risk.Low;
    }

    public static string Max(string a, string b) => Risk.ToSeverity(a) <= Risk.ToSeverity(b) ? a : b;
}

public static class CommandLine
{
    private static readonly Regex Proxy = new(@"\\(rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|cmd|javaw?|pythonw?|msiexec|conhost)\.exe$",
                                              RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Payload = new(@"([a-z]:\\[^""<>|*?\r\n]+?\.(dll|ocx|cpl|vbs|vbe|js|jse|hta|ps1|bat|cmd|jar|py|msi|exe|scr))(?=[\s,""']|$)",
                                                RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ExeToken = new(@"^(.+?\.(exe|com|bat|cmd|dll|scr|ps1|vbs|js|hta|msi|jar))(?=\s|,|$)",
                                                 RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Extracts the file that a command line actually runs. For proxy programs (rundll32, powershell, wscript...)
    /// returns the payload they launch, because that is what needs to be judged.
    /// </summary>
    public static string? ExtractTarget(string? commandLine, Func<string, string>? expand = null, Func<string, string?>? resolve = null)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        expand ??= Environment.ExpandEnvironmentVariables;
        var cmd = expand(commandLine.Trim());
        if (cmd.StartsWith(@"\??\")) cmd = cmd[4..];
        if (cmd.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) cmd = expand("%SystemRoot%") + cmd[11..];

        string first;
        if (cmd.StartsWith('"')) { int end = cmd.IndexOf('"', 1); first = end > 1 ? cmd[1..end] : cmd.Trim('"'); }
        else { var m = ExeToken.Match(cmd); first = m.Success ? m.Groups[1].Value : cmd.Split(' ', 2)[0]; }

        if (Proxy.IsMatch(first) || Proxy.IsMatch("\\" + first))
        {
            var rest = cmd.Length > first.Length ? cmd[Math.Min(cmd.Length, cmd.IndexOf(first, StringComparison.OrdinalIgnoreCase) + first.Length)..] : "";
            var p = Payload.Match(rest);
            if (p.Success) return p.Groups[1].Value;
        }
        if (!Regex.IsMatch(first, @"^([a-zA-Z]:\\|\\\\)") && resolve is not null)
            return resolve(first) ?? first;
        return first;
    }

    public static bool IsSuspiciousScriptHost(string? commandLine) =>
        !string.IsNullOrEmpty(commandLine) &&
        Regex.IsMatch(commandLine, @"(powershell|pwsh|mshta|wscript|cscript|cmd\.exe).*(http[s]?://|frombase64|\s-e(nc|ncodedcommand)?\s|\.vbs|\.vbe|\.js\b|\.hta|bitsadmin|certutil.*-urlcache|-w(indowstyle)?\s+h(idden)?|iex\s*\(|invoke-expression|downloadstring)",
                      RegexOptions.IgnoreCase);
}
