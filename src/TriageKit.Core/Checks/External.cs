using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

[SupportedOSPlatform("windows")]
public sealed class DefenderQuickScanCheck : ICheck
{
    public string Name => "Defender quick scan";
    public bool IsSlow => true;
    public int Order => 50;

    public object? Run(CheckContext ctx)
    {
        if (!ctx.Options.RunDefenderQuickScan) return new { Ran = false, Reason = "Off (Defender may remove what it finds, so TriageKit doesn't start it unless you turn it on)" };
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (!File.Exists(exe)) return new { Ran = false, Reason = "MpCmdRun.exe not found (Defender not installed or replaced by another antivirus)" };
        var started = DateTime.Now;
        var (code, output) = Proc.Run(exe, "-Scan -ScanType 1", TimeSpan.FromMinutes(30));
        // Exit code 2 = threats found (and handled by Defender's own remediation policy), but also "couldn't scan".
        // Named threats in the (English) output or new entries in Defender's detection list confirm it.
        if (code == 2 && (System.Text.RegularExpressions.Regex.IsMatch(output, @"found [1-9]\d* threats?|Threat\s*:", System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                          || Reputation.DefenderDetections.Since(started.ToUniversalTime()).Count > 0))
            ctx.Add(Severity.High, "Scanners", "Microsoft Defender found threats", "Defender's quick scan (which you turned on) found something and handled it under Defender's own settings. See Windows Security > Protection history.",
                    "Open Protection history and check that each threat was removed.", new { Started = started.ToString("s") }, ruleId: "scanner.defender-found");
        return new { Ran = true, ExitCode = code, ThreatsFound = code == 2, Output = Sys.Trunc(output, 1500) };
    }
}

[SupportedOSPlatform("windows")]
public sealed class AutorunsCheck : ICheck
{
    public string Name => "Sysinternals Autoruns";
    public bool IsSlow => true;
    public int Order => 60;

    public object? Run(CheckContext ctx)
    {
        if (!ctx.Options.RunAutoruns)
        {
            ctx.Add(Severity.Info, "Collector", "Sysinternals Autoruns is switched off", "RunAutoruns is false in config.json, so Autoruns' extra autostart locations were not checked. TriageKit's own autostart check still ran.",
                    "Turn it back on unless you switched it off on purpose.", ruleId: "collector.disabled");
            return new { Ran = false, Reason = "Disabled in config" };
        }
        var exe = new[] { "autorunsc64.exe", "autorunsc.exe" }.Select(n => Path.Combine(ctx.Options.ToolsDirectory, "Sysinternals", n)).FirstOrDefault(File.Exists);
        if (exe is null) return new { Ran = false, Reason = @"tools\Sysinternals\autorunsc64.exe not found" };
        // Copy to a private folder only administrators can write, verify THAT copy, and run it. Verifying the
        // original and then running it would leave a window in which the file on the USB stick could be swapped.
        var priv = Path.Combine(Path.GetTempPath(), "TriageKit-" + Guid.NewGuid().ToString("N"));
        string runCopy;
        try
        {
            var di = Directory.CreateDirectory(priv);
            if (OperatingSystem.IsWindows() && ctx.Options.Elevated)
            {
                // Only SYSTEM and Administrators may write here, so a non-admin process can't swap the copy.
                var sec = new System.Security.AccessControl.DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.LocalSystemSid, System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid })
                    sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid, null), System.Security.AccessControl.FileSystemRights.FullControl,
                        System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                System.IO.FileSystemAclExtensions.SetAccessControl(di, sec);
            }
            runCopy = Path.Combine(priv, Path.GetFileName(exe));
            File.Copy(exe, runCopy);
        }
        catch (Exception ex) { return new { Ran = false, Reason = "Could not prepare autorunsc: " + ex.Message }; }
        if (new FileIntelService().Get(runCopy) is not { IsMicrosoft: true })
        {
            try { Directory.Delete(priv, true); } catch { }
            return new { Ran = false, Reason = "autorunsc is not validly signed by Microsoft; refusing to run it" };
        }
        exe = runCopy;

        var csv = Path.Combine(ctx.Options.OutputDirectory, "autoruns.csv");
        // -a * all locations, -c CSV, -h hashes, -s verify signatures, -m hide Microsoft entries, -o output file
        var (code, _) = Proc.Run(exe, $"-accepteula -nobanner -a * -c -h -s -m -o \"{csv}\" *", TimeSpan.FromMinutes(15));
        try { Directory.Delete(priv, true); } catch { }
        if (!File.Exists(csv)) return new { Ran = false, Reason = $"autorunsc exited with {code} and produced no output" };

        var rows = Csv.Parse(File.ReadAllText(csv));   // ReadAllText honours the UTF-16 BOM autorunsc writes
        if (rows.Count < 2) return new { Ran = true, Entries = 0 };
        var header = rows[0]; int iPath = header.IndexOf("Image Path"), iSigner = header.IndexOf("Signer"), iEntry = header.IndexOf("Entry"), iLoc = header.IndexOf("Entry Location");
        int unverified = 0;
        foreach (var r in rows.Skip(1))
        {
            string Get(int i) => i >= 0 && i < r.Count ? r[i] : "";
            var path = Get(iPath); if (string.IsNullOrWhiteSpace(path)) continue;
            if (Get(iSigner).StartsWith("(Verified)")) continue;
            unverified++;
            var intel = ctx.Files.Get(path);
            var risk = PathHeuristics.ExecutableRisk(intel);
            if (risk is Risk.High or Risk.Critical or Risk.Medium)
                ctx.Add(risk == Risk.Medium ? Severity.Low : Risk.ToSeverity(risk), "Scanners", $"Autoruns: unverified autostart {Get(iEntry)}", $"{Get(iLoc)}\n{path}",
                        "Review this entry in autoruns.csv or the Autoruns GUI.", new { Entry = Get(iEntry), Location = Get(iLoc), Path = path, Signer = Get(iSigner) }, "T1547", "scanner.autoruns-unverified");
        }
        return new { Ran = true, Entries = rows.Count - 1, Unverified = unverified, Csv = "autoruns.csv" };
    }
}

internal static class Proc
{
    public static (int ExitCode, string Output) Run(string exe, string args, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        using var p = Process.Start(psi)!;
        var sb = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data is not null && sb.Length < 20000) sb.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null && sb.Length < 20000) sb.AppendLine(e.Data); };
        p.BeginOutputReadLine(); p.BeginErrorReadLine();
        if (!p.WaitForExit(timeout)) { try { p.Kill(true); } catch { } return (-1, sb + "\n(timed out)"); }
        p.WaitForExit();
        return (p.ExitCode, sb.ToString());
    }
}

/// <summary>Minimal RFC 4180 CSV parser (quoted fields, embedded commas/quotes/newlines).</summary>
public static class Csv
{
    public static List<List<string>> Parse(string text)
    {
        var rows = new List<List<string>>(); var row = new List<string>(); var field = new StringBuilder(); bool quoted = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (quoted)
            {
                if (c == '"') { if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; } else quoted = false; }
                else field.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { row.Add(field.ToString()); field.Clear(); }
            else if (c == '\n' || c == '\r')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                row.Add(field.ToString()); field.Clear();
                if (row.Count > 1 || row[0].Length > 0) rows.Add(row);
                row = new List<string>();
            }
            else field.Append(c);
        }
        if (field.Length > 0 || row.Count > 0) { row.Add(field.ToString()); rows.Add(row); }
        return rows;
    }
}
