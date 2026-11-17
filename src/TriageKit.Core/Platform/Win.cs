using System.Management;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;

namespace TriageKit.Core.Platform;

[SupportedOSPlatform("windows")]
public static class Wmi
{
    /// <summary>True when a WMI namespace exists (used for optional providers such as LibreHardwareMonitor). Gives up after 5 seconds.</summary>
    public static bool NamespaceExists(string ns)
    {
        try
        {
            var t = Task.Run(() => { new ManagementScope(ns, new ConnectionOptions { Timeout = TimeSpan.FromSeconds(5) }).Connect(); return true; });
            return t.Wait(TimeSpan.FromSeconds(6)) && t.Result;
        }
        catch { return false; }
    }

    /// <summary>Runs a WQL query and returns each object as a property dictionary (never throws).
    /// <paramref name="optional"/>: a failure is a minor gap (an optional detail), not a gap in the check.</summary>
    public static List<Dictionary<string, object?>> Query(string wql, string scope = @"root\cimv2", TimeSpan? timeout = null, bool optional = false)
    {
        var rows = new List<Dictionary<string, object?>>();
        try
        {
            var options = new System.Management.EnumerationOptions { Timeout = timeout ?? TimeSpan.FromSeconds(90), ReturnImmediately = true, Rewindable = false };
            using var searcher = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql), options);
            foreach (ManagementBaseObject mo in searcher.Get())
            {
                using (mo)
                {
                    var d = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in mo.Properties) d[p.Name] = p.Value;
                    d["__CLASS"] = mo.ClassPath?.ClassName;
                    rows.Add(d);
                }
            }
        }
        catch (ManagementException ex) { Gap($"WMI query failed ({Short(wql)})", ex, optional); }
        catch (UnauthorizedAccessException ex) { Gap($"WMI access denied ({Short(wql)})", ex, optional); }
        catch (System.Runtime.InteropServices.COMException ex) { Gap($"WMI unavailable ({Short(wql)})", ex, optional); }
        return rows;
    }

    private static void Gap(string what, Exception ex, bool optional)
    {
        if (optional) Engine.CheckContext.Minor(what, ex); else Engine.CheckContext.Note(what, ex);
    }

    private static string Short(string wql) => wql.Length > 60 ? wql[..60] + "..." : wql;

    public static string? S(this Dictionary<string, object?> d, string key) => d.TryGetValue(key, out var v) && v is not null ? Convert.ToString(v) : null;
    public static long? L(this Dictionary<string, object?> d, string key) { try { return d.TryGetValue(key, out var v) && v is not null ? Convert.ToInt64(v) : null; } catch { return null; } }
    public static bool? B(this Dictionary<string, object?> d, string key) => d.TryGetValue(key, out var v) && v is bool b ? b : null;
    public static string[] A(this Dictionary<string, object?> d, string key) =>
        d.TryGetValue(key, out var v) && v is Array arr ? arr.Cast<object?>().Where(x => x is not null).Select(x => x!.ToString()!).ToArray() : Array.Empty<string>();

    public static DateTime? Date(this Dictionary<string, object?> d, string key)
    {
        var s = d.S(key);
        if (string.IsNullOrEmpty(s)) return null;
        try { return ManagementDateTimeConverter.ToDateTime(s); } catch { return null; }
    }
}

[SupportedOSPlatform("windows")]
public static class Reg
{
    public static object? Value(RegistryKey root, string subKey, string name)
    {
        try { using var k = root.OpenSubKey(subKey, false); return k?.GetValue(name); } catch { return null; }
    }

    public static IEnumerable<(string Name, object? Value)> Values(RegistryKey root, string subKey)
    {
        RegistryKey? k = null;
        try { k = root.OpenSubKey(subKey, false); } catch { }
        if (k is null) yield break;
        using (k)
            foreach (var n in k.GetValueNames())
            {
                object? v; try { v = k.GetValue(n); } catch { v = null; }
                yield return (n, v);
            }
    }

    public static IEnumerable<string> SubKeys(RegistryKey root, string subKey)
    {
        try { using var k = root.OpenSubKey(subKey, false); return k?.GetSubKeyNames() ?? Array.Empty<string>(); }
        catch { return Array.Empty<string>(); }
    }

    /// <summary>Hives of real user accounts currently loaded under HKEY_USERS.</summary>
    public static IEnumerable<string> LoadedUserSids() =>
        SubKeys(Registry.Users, "").Where(s => s.StartsWith("S-1-5-21-") && !s.EndsWith("_Classes"));
}

[SupportedOSPlatform("windows")]
public static class Sys
{
    public sealed record UserProfile(string Sid, string Path, string Name);

    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static List<UserProfile> UserProfiles()
    {
        var list = new List<UserProfile>();
        const string key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        foreach (var sid in Reg.SubKeys(Registry.LocalMachine, key).Where(s => s.StartsWith("S-1-5-21-")))
        {
            var path = Reg.Value(Registry.LocalMachine, $@"{key}\{sid}", "ProfileImagePath") as string;
            if (!string.IsNullOrEmpty(path)) { path = Environment.ExpandEnvironmentVariables(path); if (Directory.Exists(path)) list.Add(new(sid, path, System.IO.Path.GetFileName(path))); }
        }
        return list;
    }

    public static string SystemRoot => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    /// <summary>Resolves a bare program name (e.g. "rundll32.exe") the way Windows would.</summary>
    public static string? ResolveProgram(string name)
    {
        var sys = Path.Combine(SystemRoot, "System32");
        foreach (var candidate in new[] { name, name + ".exe" })
        {
            var p = Path.Combine(sys, candidate); if (File.Exists(p)) return p;
            p = Path.Combine(SystemRoot, candidate); if (File.Exists(p)) return p;
        }
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            try { var p = Path.Combine(dir.Trim(), name); if (File.Exists(p)) return p; if (File.Exists(p + ".exe")) return p + ".exe"; } catch { }
        }
        return null;
    }

    [SupportedOSPlatform("windows")]
    public static string? AccountName(string sid)
    {
        try { return new System.Security.Principal.SecurityIdentifier(sid).Translate(typeof(System.Security.Principal.NTAccount)).Value; } catch { return null; }
    }

    public static string Trunc(string? s, int max = 600) => s is null ? "" : s.Length <= max ? s : s[..max] + "...";
}
