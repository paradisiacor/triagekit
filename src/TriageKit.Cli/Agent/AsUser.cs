using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace TriageKit.Cli.Agent;

/// <summary>
/// Opens files, folders and links WITHOUT administrator rights. TriageKit's window runs elevated, and anything
/// started directly from it (a browser for a report or a web link) would inherit that admin token. Handing the
/// target to explorer.exe makes the already-running, unelevated Explorer of the signed-in user open it instead.
/// </summary>
[SupportedOSPlatform("windows")]
public static class AsUser
{
    public static void Open(string target)
    {
        if (string.IsNullOrWhiteSpace(target) || target.Contains('"')) return;
        try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), $"\"{target}\"") { UseShellExecute = false }); }
        catch { }
    }

    [DllImport("user32.dll")] private static extern IntPtr GetShellWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int pid);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    /// <summary>
    /// The account of the desktop's Explorer, which is who will actually open a file we hand over. With "Run as
    /// administrator" using another account's password, this differs from the account TriageKit runs as.
    /// </summary>
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);

    private static string? SessionString(int session, int infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, session, infoClass, out var buf, out _)) return null;
        try { return Marshal.PtrToStringUni(buf); } finally { WTSFreeMemory(buf); }
    }

    public static SecurityIdentifier? ShellUser()
    {
        // The user signed in to this desktop session (works across accounts without opening their processes).
        try
        {
            int session = Process.GetCurrentProcess().SessionId;
            var user = SessionString(session, 5 /* WTSUserName */);
            var domain = SessionString(session, 7 /* WTSDomainName */);
            if (!string.IsNullOrEmpty(user))
                return (SecurityIdentifier)new NTAccount(string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}").Translate(typeof(SecurityIdentifier));
        }
        catch { }
        return ExplorerUser();
    }

    private static SecurityIdentifier? ExplorerUser()
    {
        IntPtr proc = IntPtr.Zero, token = IntPtr.Zero;
        try
        {
            var shell = GetShellWindow();
            if (shell == IntPtr.Zero || GetWindowThreadProcessId(shell, out var pid) == 0 || pid == 0) return null;
            proc = OpenProcess(0x1000, false, pid);   // PROCESS_QUERY_LIMITED_INFORMATION
            if (proc == IntPtr.Zero || !OpenProcessToken(proc, 0x0008 /* TOKEN_QUERY */, out token)) return null;
            using var id = new WindowsIdentity(token);
            return id.User;
        }
        catch { return null; }
        finally { if (token != IntPtr.Zero) CloseHandle(token); if (proc != IntPtr.Zero) CloseHandle(proc); }
    }
}
