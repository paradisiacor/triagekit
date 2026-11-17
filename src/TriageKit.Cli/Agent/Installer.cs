using System.Diagnostics;
using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using TriageKit.Core.Agent;
using TriageKit.Core.Platform;

namespace TriageKit.Cli.Agent;

/// <summary>
/// Installs/uninstalls the daily-protection agent: copies the kit to Program Files (admin-only), registers the Windows service,
/// the tray app autostart and an "Apps & features" entry. Every step is logged and reversible with "uninstall".
/// </summary>
[SupportedOSPlatform("windows")]
public static class Installer
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "TriageKit Tray";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TriageKit";

    public static int Install(string version, Action<string> say)
    {
        if (!Sys.IsElevated()) { say("Please run this from an administrator command prompt (or right-click > Run as administrator)."); return 5; }
        var src = AppContext.BaseDirectory.TrimEnd('\\');
        var dst = AgentPaths.InstallDir;
        var exe = Path.Combine(dst, "TriageKit.exe");

        say("Stopping any previous version...");
        StopService();
        KillTray();

        say($"Copying files to {dst} ...");
        Directory.CreateDirectory(dst);
        if (!string.Equals(Path.GetFullPath(src), Path.GetFullPath(dst), StringComparison.OrdinalIgnoreCase))
        {
            CopyFile(Path.Combine(src, "TriageKit.exe"), exe);
            foreach (var f in new[] { "config.json", "README.md", "SHA256SUMS.txt" })
                if (File.Exists(Path.Combine(src, f))) CopyFile(Path.Combine(src, f), Path.Combine(dst, f));
            foreach (var sub in new[] { "rules", "tools" })
                if (Directory.Exists(Path.Combine(src, sub))) CopyDir(Path.Combine(src, sub), Path.Combine(dst, sub));
        }

        say("Preparing the protected data folder...");
        SecureFolder.Ensure(AgentPaths.DataDir);
        SecureFolder.EnsurePrivate(AgentPaths.ReportsDir);
        SecureFolder.EnsurePrivate(Path.GetDirectoryName(AgentPaths.SecretsFile)!);
        using (var h = new HistoryStore(AgentPaths.HistoryDb))
            if (h.GetMeta("installed") is null) h.SetMeta("installed", DateTime.UtcNow.ToString("O"));
        if (!File.Exists(AgentPaths.AgentConfigFile))
            File.WriteAllText(AgentPaths.AgentConfigFile, System.Text.Json.JsonSerializer.Serialize(new AgentConfig(), new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

        say("Registering the background service...");
        var bin = $"\"{exe}\" service";
        if (ServiceExists()) Sc($"config {AgentPaths.ServiceName} binPath= \"{bin.Replace("\"", "\\\"")}\" start= delayed-auto");
        else Sc($"create {AgentPaths.ServiceName} binPath= \"{bin.Replace("\"", "\\\"")}\" start= delayed-auto DisplayName= \"TriageKit Security Agent\"");
        Sc($"description {AgentPaths.ServiceName} \"Runs scheduled read-only security checks and keeps a local history. Does not modify the system.\"");
        Sc($"failure {AgentPaths.ServiceName} reset= 86400 actions= restart/60000/restart/60000//");

        say("Adding the tray icon to Windows startup...");
        // A Run-key entry would be blocked silently for administrators (the exe asks for the highest available rights),
        // so the tray starts from a sign-in task instead. Older installs used the Run key: remove it.
        using (var run = Registry.LocalMachine.OpenSubKey(RunKey, true)) run?.DeleteValue(RunValue, false);
        RegisterTrayTask(exe, say);
        using (var u = Registry.LocalMachine.CreateSubKey(UninstallKey))
        {
            u.SetValue("DisplayName", "TriageKit Security Agent");
            u.SetValue("DisplayVersion", version);
            u.SetValue("Publisher", "TriageKit");
            u.SetValue("InstallLocation", dst);
            u.SetValue("DisplayIcon", exe);
            u.SetValue("UninstallString", $"\"{exe}\" uninstall");
            u.SetValue("NoModify", 1, RegistryValueKind.DWord);
            u.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            u.SetValue("EstimatedSize", (int)(new FileInfo(exe).Length / 1024), RegistryValueKind.DWord);
        }

        say("Starting the service...");
        StartService();
        // Start the tray for the signed-in user with a normal (non-elevated) token.
        try { Process.Start(new ProcessStartInfo("runas.exe", $"/trustlevel:0x20000 \"\\\"{exe}\\\" tray\"") { UseShellExecute = false, CreateNoWindow = true }); } catch { }

        say("");
        say("TriageKit is installed.");
        say("  A first scan starts in about 5 minutes; after that it scans daily (change the time in");
        say($"  {AgentPaths.AgentConfigFile}).");
        say("  Look for the TriageKit icon next to the clock.");
        return 0;
    }

    private const string TrayTask = "TriageKit Tray";

    /// <summary>Sign-in task for every user: highest available rights, so admins get the tray without a UAC prompt.</summary>
    private static void RegisterTrayTask(string exe, Action<string> say)
    {
        var esc = System.Security.SecurityElement.Escape(exe);
        var xml = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.3"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo><Description>Shows the TriageKit status icon next to the clock.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT20S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id=""Users""><GroupId>S-1-5-32-545</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><AllowHardTerminate>true</AllowHardTerminate></Settings>
  <Actions Context=""Users""><Exec><Command>{esc}</Command><Arguments>tray</Arguments></Exec></Actions>
</Task>";
        // Written to the admin-only data folder, not %TEMP%: a program running as the user must not be able to swap
        // the file between writing and registering (it would get its own "highest available" sign-in task).
        var privateDir = Path.Combine(AgentPaths.DataDir, "Private");
        SecureFolder.EnsurePrivate(privateDir);
        var tmp = Path.Combine(privateDir, "tray-task-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            File.WriteAllText(tmp, xml, System.Text.Encoding.Unicode);
            var code = RunQuiet("schtasks.exe", $"/Create /TN \"{TrayTask}\" /XML \"{tmp}\" /F");
            if (code != 0) say("  Couldn't create the sign-in task for the tray icon (code " + code + "). Start it from the Start menu instead.");
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    private static int RunQuiet(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, file), args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true })!;
            p.WaitForExit(30_000);
            return p.HasExited ? p.ExitCode : -1;
        }
        catch { return -1; }
    }

    public static int Uninstall(bool purgeData, Action<string> say)
    {
        if (!Sys.IsElevated()) { say("Please run this from an administrator command prompt."); return 5; }
        say("Stopping and removing the service...");
        StopService();
        if (ServiceExists()) Sc($"delete {AgentPaths.ServiceName}");
        KillTray();
        using (var run = Registry.LocalMachine.OpenSubKey(RunKey, true)) run?.DeleteValue(RunValue, false);
        RunQuiet("schtasks.exe", $"/Delete /TN \"{TrayTask}\" /F");
        Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false);

        if (purgeData) { say("Deleting history and reports..."); try { Directory.Delete(AgentPaths.DataDir, true); } catch (Exception ex) { say("  Could not delete data: " + ex.Message); } }
        else say($"Your scan history is kept in {AgentPaths.DataDir} (use 'uninstall --purge' to delete it).");

        // The running exe cannot delete itself: hand the folder removal to a short-lived cmd after we exit.
        var dir = AgentPaths.InstallDir;
        if (Directory.Exists(dir))
            Process.Start(new ProcessStartInfo("cmd.exe", $"/c ping 127.0.0.1 -n 3 >nul & rmdir /s /q \"{dir}\"") { UseShellExecute = false, CreateNoWindow = true });
        say("TriageKit has been removed.");
        return 0;
    }

    private static bool ServiceExists() => ServiceController.GetServices().Any(s => s.ServiceName.Equals(AgentPaths.ServiceName, StringComparison.OrdinalIgnoreCase));

    private static void StopService()
    {
        try
        {
            using var sc = new ServiceController(AgentPaths.ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped) { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
        }
        catch { }
    }

    private static void StartService()
    {
        try { using var sc = new ServiceController(AgentPaths.ServiceName); sc.Start(); sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); }
        catch (Exception ex) { Console.WriteLine("  Could not start the service: " + ex.Message); }
    }

    private static void KillTray()
    {
        var self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName("TriageKit"))
        {
            try { if (p.Id != self && (p.MainModule?.FileName?.StartsWith(AgentPaths.InstallDir, StringComparison.OrdinalIgnoreCase) ?? false)) { p.Kill(); p.WaitForExit(5000); } }
            catch { }
            finally { p.Dispose(); }
        }
    }

    private static void Sc(string args)
    {
        var p = Process.Start(new ProcessStartInfo("sc.exe", args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
        p.WaitForExit(30000);
    }

    private static void CopyFile(string from, string to)
    {
        for (int i = 0; ; i++)
        {
            try { File.Copy(from, to, overwrite: true); return; }
            catch (IOException) when (i < 10) { Thread.Sleep(500); }
        }
    }

    private static void CopyDir(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var f in Directory.GetFiles(from)) CopyFile(f, Path.Combine(to, Path.GetFileName(f)));
        foreach (var d in Directory.GetDirectories(from)) CopyDir(d, Path.Combine(to, Path.GetFileName(d)));
    }
}
