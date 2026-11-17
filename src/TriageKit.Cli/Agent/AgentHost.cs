using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using TriageKit.Core.Agent;

namespace TriageKit.Cli.Agent;

/// <summary>Fixed locations for the installed edition.</summary>
[SupportedOSPlatform("windows")]
public static class AgentPaths
{
    public const string ServiceName = "TriageKit";
    public const string PipeName = "TriageKit.Agent.v1";
    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TriageKit");
    public static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TriageKit");
    public static string ReportsDir => Path.Combine(DataDir, "Reports");
    public static string HistoryDb => Path.Combine(DataDir, "history.db");
    public static string StatusFile => Path.Combine(DataDir, "status.json");
    public static string HistoryHtml => Path.Combine(ReportsDir, "history.html");
    public static string AgentConfigFile => Path.Combine(DataDir, "agent.json");
    public static string ServiceLog => Path.Combine(DataDir, "service.log");
    public static string SecretsFile => Path.Combine(DataDir, "Private", "secrets.json");
}

/// <summary>What the tray app shows. Written by the service, readable by all users, writable only by admins/SYSTEM.</summary>
public sealed class AgentStatus
{
    public string Version { get; set; } = "";
    public string State { get; set; } = "Idle";              // Idle | Scanning
    public long LastScanId { get; set; }
    public string? LastScanTime { get; set; }
    public int? Score { get; set; }
    public string? Verdict { get; set; }
    public Dictionary<string, int> Counts { get; set; } = new();
    public int NewAlertable { get; set; }
    public List<string> NewTitles { get; set; } = new();
    public string? ReportPath { get; set; }
    public string? NextScan { get; set; }
    public string? LastError { get; set; }

    public static AgentStatus? Read(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<AgentStatus>(File.ReadAllText(path)) : null; } catch { return null; }
    }
}

[SupportedOSPlatform("windows")]
internal static class SecureFolder
{
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    /// <summary>
    /// Creates the data folder with an explicit ACL: SYSTEM and Administrators have full control, other users can only read.
    /// Prevents a standard user (or malware running as one) from tampering with history, settings or reports.
    /// </summary>
    public static void Ensure(string path) => Apply(path, usersRead: true);

    /// <summary>Reports, history and secrets: SYSTEM and Administrators only (they describe every user on the PC).</summary>
    public static void EnsurePrivate(string path) => Apply(path, usersRead: false);

    /// <summary>
    /// Standard users can create folders in ProgramData, so a malicious process could make ours first and stay its owner
    /// (and so keep the right to rewrite the ACL), or make it a junction pointing somewhere else. We refuse links, take
    /// ownership for Administrators and reset the ACL on everything already inside.
    /// </summary>
    private static void Apply(string path, bool usersRead)
    {
        RefuseLinks(path);
        var dir = Directory.CreateDirectory(path);
        RefuseLinks(path);
        var sec = new DirectorySecurity();
        sec.SetOwner(Admins);
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (usersRead)
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(sec);
        // Children created earlier (possibly by someone else) get the same owner and inherit the new ACL. Walked by
        // hand so we never step into a junction (its target would get our ownership and ACL changes).
        Secure(dir);
    }

    private static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    /// <summary>
    /// Owners we trust: Administrators, SYSTEM, TrustedInstaller. An individual admin account only counts inside the
    /// app window's WebView2 profile, which Windows creates as that account when it's set to "object creator" owner.
    /// Elsewhere a file owned by an admin account may have been made by malware running unelevated under it.
    /// </summary>
    private static bool Trusted(IdentityReference? owner, string path) =>
        owner is SecurityIdentifier sid && (sid == Admins || sid == SystemSid || sid == TrustedInstaller ||
            (path.Contains(@"\WebView2", StringComparison.OrdinalIgnoreCase) && IsLocalAdmin(sid)));

    [System.Runtime.InteropServices.DllImport("netapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int NetUserGetLocalGroups(string? server, string user, int level, int flags, out IntPtr buf, int max, out int read, out int total);
    [System.Runtime.InteropServices.DllImport("netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buf);

    /// <summary>
    /// When Windows is set to make the creating admin (not the Administrators group) the owner of new files, files the
    /// app itself created are owned by that admin account. Those stay trusted; files owned by standard users do not.
    /// </summary>
    private static bool IsLocalAdmin(SecurityIdentifier sid)
    {
        try
        {
            var account = sid.Translate(typeof(NTAccount)).Value;
            var adminsName = Admins.Translate(typeof(NTAccount)).Value.Split('\\').Last();   // localized, e.g. "Administratori"
            if (NetUserGetLocalGroups(null, account, 0, 1 /* LG_INCLUDE_INDIRECT */, out var buf, -1, out var read, out _) != 0) return false;
            try
            {
                for (int i = 0; i < read; i++)
                    if (string.Equals(System.Runtime.InteropServices.Marshal.PtrToStringUni(System.Runtime.InteropServices.Marshal.ReadIntPtr(buf, i * IntPtr.Size)), adminsName, StringComparison.OrdinalIgnoreCase)) return true;
                return false;
            }
            finally { NetApiBufferFree(buf); }
        }
        catch { return false; }
    }

    private static void Secure(DirectoryInfo dir)
    {
        foreach (var child in dir.EnumerateFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = true, AttributesToSkip = 0 }))
        {
            if (child.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                // A link inside our folder can only be someone redirecting us. Removing the link never touches its target.
                try { if (child is DirectoryInfo d) d.Delete(); else child.Delete(); } catch { }
                continue;
            }
            IdentityReference? owner = null;
            try { owner = child is DirectoryInfo od ? od.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) : ((FileInfo)child).GetAccessControl().GetOwner(typeof(SecurityIdentifier)); } catch { }
            if (child.Name.Contains(".untrusted-", StringComparison.Ordinal)) continue;   // already set aside, never used
            // Only act on an owner we could actually read; an unreadable owner is left to the folder ACL above.
            if (owner is not null && !Trusted(owner, child.FullName) && child is DirectoryInfo ud)
            {
                // A folder made by someone else: move it aside the same way (it may hide files held open for writing).
                var asideDir = ud.FullName + ".untrusted-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                try { ud.MoveTo(asideDir); }
                catch (Exception ex) { throw new UnauthorizedAccessException($"{ud.FullName} was created by another user and is in use. Close the program holding it, or delete it, then try again.", ex); }
                continue;
            }
            if (owner is not null && child is FileInfo uf && !Trusted(owner, child.FullName))
            {
                // Created by a non-admin: it may still be held open for writing, and an open handle keeps working after
                // an ACL change. Move it aside (never trusted again) so the service starts from a fresh file.
                var aside = uf.FullName + ".untrusted-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss");
                try { uf.MoveTo(aside); }
                catch (Exception ex) { throw new UnauthorizedAccessException($"{uf.FullName} was created by another user and is in use. Close the program holding it, or delete it, then try again.", ex); }
                try { var fs = new FileSecurity(); fs.SetOwner(Admins); fs.SetAccessRuleProtection(false, false); new FileInfo(aside).SetAccessControl(fs); } catch { }
                continue;
            }
            try
            {
                if (child is DirectoryInfo cd)
                {
                    // A subfolder we protected on purpose (admin-only "Private", the per-viewer "View" copies) keeps its
                    // own permissions: making it inherit from here would open it to every user.
                    var current = cd.GetAccessControl();
                    if (current.AreAccessRulesProtected && Trusted(owner, cd.FullName)) continue;
                    var cs = new DirectorySecurity(); cs.SetOwner(Admins); cs.SetAccessRuleProtection(false, false); cd.SetAccessControl(cs);
                    Secure(cd);
                }
                else if (child is FileInfo cf)
                {
                    var fs = new FileSecurity(); fs.SetOwner(Admins); fs.SetAccessRuleProtection(false, false); cf.SetAccessControl(fs);
                }
            }
            catch { /* best effort; the folder ACL above already blocks non-admin writes */ }
        }
    }

    private static void RefuseLinks(string path)
    {
        // Walk up: any junction or symlink on the way (other than system ones above ProgramData) means someone is redirecting us.
        var root = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)).TrimEnd('\\');
        for (var p = Path.GetFullPath(path).TrimEnd('\\'); p.Length > root.Length && p.StartsWith(root, StringComparison.OrdinalIgnoreCase); p = Path.GetDirectoryName(p)!)
        {
            var di = new DirectoryInfo(p);
            if (di.Exists && di.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new UnauthorizedAccessException($"{p} is a link to another location. TriageKit won't use it; delete it and try again.");
        }
    }
}

/// <summary>
/// The background service: scheduled scans, history, status for the tray, and a tiny local command pipe.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class AgentService : ServiceBase
{
    private readonly string _version;
    private readonly ManualResetEventSlim _scanNow = new(false);
    private readonly CancellationTokenSource _stop = new();
    private Thread? _worker, _pipe;
    private volatile bool _scanning;
    private DateTime _lastManualTrigger = DateTime.MinValue;
    private DateTime _nextRun;

    public AgentService(string version) { _version = version; ServiceName = AgentPaths.ServiceName; CanStop = true; CanShutdown = true; }

    protected override void OnStart(string[] args)
    {
        SecureFolder.Ensure(AgentPaths.DataDir);
        SecureFolder.EnsurePrivate(AgentPaths.ReportsDir);
        WriteStatus(st => { if (st.State == "Scanning") { st.State = "Idle"; st.LastError = "The previous scan was interrupted (service restart)."; } });
        _worker = new Thread(WorkerLoop) { IsBackground = true, Name = "TriageKit scheduler" }; _worker.Start();
        _pipe = new Thread(PipeLoop) { IsBackground = true, Name = "TriageKit pipe" }; _pipe.Start();
        Log($"Service {_version} started");
    }

    protected override void OnStop() { _stop.Cancel(); _scanNow.Set(); Log("Service stopping"); }
    protected override void OnShutdown() => OnStop();

    /// <summary>Console debugging: run the loop in the foreground.</summary>
    public void RunInteractive() { OnStart(Array.Empty<string>()); Console.WriteLine("Agent running. Press Enter to stop."); Console.ReadLine(); OnStop(); }

    private void WorkerLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                var cfg = AgentConfig.Load(AgentPaths.AgentConfigFile);
                DateTime? lastScan;
                using (var h = new HistoryStore(AgentPaths.HistoryDb))
                {
                    if (h.GetMeta("installed") is null) h.SetMeta("installed", DateTime.UtcNow.ToString("O"));
                    lastScan = h.Scans(1).FirstOrDefault()?.Started;
                }
                _nextRun = Schedule.NextRun(DateTime.Now, lastScan, cfg.DailyScanTime, TimeSpan.FromMinutes(5));
                WriteStatus(s => s.NextScan = _nextRun.ToString("s"));

                var wait = _nextRun - DateTime.Now;
                if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
                if (wait > TimeSpan.FromMinutes(30)) wait = TimeSpan.FromMinutes(30);   // re-read the settings regularly
                bool manual = _scanNow.Wait(wait, _stop.Token);
                _scanNow.Reset();
                if (_stop.IsCancellationRequested) break;
                if (manual || DateTime.Now >= _nextRun)
                    RunScan(quick: !manual && cfg.QuickScheduledScans, cfg);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Log("Worker error: " + ex); WriteStatus(s => s.LastError = ex.Message); Thread.Sleep(TimeSpan.FromMinutes(1)); }
        }
    }

    private void RunScan(bool quick, AgentConfig cfg)
    {
        _scanning = true;
        WriteStatus(s => { s.State = "Scanning"; s.LastError = null; });
        try
        {
            var appCfg = AppConfig.Load(Path.Combine(AppContext.BaseDirectory, "config.json"));
            var outcome = ScanRunner.Run(new ScanRequest
            {
                BaseDirectory = AppContext.BaseDirectory, OutputRoot = AgentPaths.ReportsDir, Config = appCfg, Edition = "Installed", Installed = true, Quick = quick,
            }, _version);
            using var h = new HistoryStore(AgentPaths.HistoryDb);
            var (id, diff) = h.Record(outcome.Result, outcome.ReportHtml);
            foreach (var dir in h.Prune(Math.Max(5, cfg.KeepScans)))
                try { if (dir.StartsWith(AgentPaths.ReportsDir, StringComparison.OrdinalIgnoreCase)) Directory.Delete(dir, true); } catch { }
            File.WriteAllText(AgentPaths.HistoryHtml, HistoryReport.Render(Environment.MachineName, h.Scans(), diff), new UTF8Encoding(false));
            WriteStatus(s =>
            {
                s.State = "Idle"; s.LastScanId = id; s.LastScanTime = DateTime.Now.ToString("s"); s.Score = outcome.Result.Score; s.Verdict = outcome.Result.Verdict;
                s.Counts = outcome.Result.Counts; s.ReportPath = outcome.ReportHtml;
                s.NewAlertable = cfg.NotifyOnNewFindings ? diff.Alertable.Count() : 0;
                s.NewTitles = diff.Alertable.Take(3).Select(f => f.Title).ToList();
            });
            Log($"Scan {id} done: score {outcome.Result.Score}, {diff.New.Count} new, {diff.Resolved.Count} resolved");
        }
        catch (Exception ex) { Log("Scan failed: " + ex); WriteStatus(s => { s.State = "Idle"; s.LastError = "Scan failed: " + ex.Message; }); }
        finally { _scanning = false; }
    }

    private readonly object _statusLock = new();
    private void WriteStatus(Action<AgentStatus> change)
    {
        lock (_statusLock)
        {
            var s = AgentStatus.Read(AgentPaths.StatusFile) ?? new AgentStatus();
            s.Version = _version;
            change(s);
            var tmp = AgentPaths.StatusFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(s, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, AgentPaths.StatusFile, overwrite: true);
        }
    }

    // ------------------------------------------------------------ local command pipe
    // Only two commands exist: STATUS and SCAN. No arguments, no paths, nothing a caller can use to make the
    // SYSTEM service do anything else. Remote (network) access to the pipe is explicitly denied.
    private void PipeLoop()
    {
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                using var server = NamedPipeServerStreamAcl.Create(AgentPaths.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                                                                   PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 256, 4096, CreatePipeSecurity());
                server.WaitForConnectionAsync(_stop.Token).GetAwaiter().GetResult();
                server.ReadMode = PipeTransmissionMode.Byte;
                var buf = new byte[32];
                var readTask = server.ReadAsync(buf, 0, buf.Length, _stop.Token);
                if (!readTask.Wait(TimeSpan.FromSeconds(5))) continue;
                var cmd = Encoding.ASCII.GetString(buf, 0, readTask.Result).Trim().ToUpperInvariant();
                var reply = Handle(cmd);
                var bytes = Encoding.UTF8.GetBytes(reply + "\n");
                // Timeouts everywhere: a client that connects and never reads must not freeze the service's pipe.
                if (!server.WriteAsync(bytes, 0, bytes.Length, _stop.Token).Wait(TimeSpan.FromSeconds(5))) continue;
                server.Flush();
                Task.Run(server.WaitForPipeDrain).Wait(TimeSpan.FromSeconds(3));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Log("Pipe error: " + ex.Message); Thread.Sleep(1000); }
        }
    }

    internal string Handle(string cmd)
    {
        switch (cmd)
        {
            case "STATUS":
                return JsonSerializer.Serialize(new { ok = true, scanning = _scanning, next = _nextRun.ToString("s") });
            case "SCAN":
                if (_scanning) return JsonSerializer.Serialize(new { ok = false, message = "A scan is already running." });
                if (DateTime.Now - _lastManualTrigger < TimeSpan.FromMinutes(10))
                    return JsonSerializer.Serialize(new { ok = false, message = "A scan was started less than 10 minutes ago." });
                _lastManualTrigger = DateTime.Now;
                _scanNow.Set();
                return JsonSerializer.Serialize(new { ok = true, message = "Scan started." });
            default:
                return JsonSerializer.Serialize(new { ok = false, message = "Unknown command." });
        }
    }

    private static PipeSecurity CreatePipeSecurity()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return ps;
    }

    private static readonly object LogLock = new();
    internal static void Log(string m)
    {
        try
        {
            lock (LogLock)
            {
                var p = AgentPaths.ServiceLog;
                if (File.Exists(p) && new FileInfo(p).Length > 2_000_000) File.Move(p, p + ".old", true);
                File.AppendAllText(p, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {m}{Environment.NewLine}");
            }
        }
        catch { }
    }
}

/// <summary>Client side of the pipe (tray app and CLI verbs).</summary>
[SupportedOSPlatform("windows")]
public static class AgentClient
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint processId);

    /// <summary>Another program could create a pipe with the same name first; only talk to the installed TriageKit service.</summary>
    private static bool ServerIsOurs(NamedPipeClientStream client)
    {
        try
        {
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out var pid)) return false;
            using var p = System.Diagnostics.Process.GetProcessById((int)pid);
            var path = p.MainModule?.FileName;
            if (path is null) return IsServicePid(client);
            return string.Equals(Path.GetFullPath(path), Path.GetFullPath(Path.Combine(AgentPaths.InstallDir, "TriageKit.exe")), StringComparison.OrdinalIgnoreCase);
        }
        catch (System.ComponentModel.Win32Exception) { return IsServicePid(client); }   // SYSTEM process: ask the service manager instead
        catch { return false; }
    }

    /// <summary>The Service Control Manager knows our service's process id, and normal users may read it.</summary>
    private static bool IsServicePid(NamedPipeClientStream client)
    {
        try
        {
            if (!GetNamedPipeServerProcessId(client.SafePipeHandle, out var pid)) return false;
            var rows = TriageKit.Core.Platform.Wmi.Query($"SELECT ProcessId, PathName FROM Win32_Service WHERE Name = '{AgentPaths.ServiceName}'");
            if (rows.Count != 1 || rows[0].GetValueOrDefault("ProcessId") is not object o || Convert.ToUInt32(o) != pid) return false;
            var image = (rows[0].GetValueOrDefault("PathName") as string ?? "").Trim();
            return image.Contains(Path.Combine(AgentPaths.InstallDir, "TriageKit.exe"), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static string? Send(string command, int timeoutMs = 3000)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", AgentPaths.PipeName, PipeDirection.InOut);
            client.Connect(timeoutMs);
            if (!ServerIsOurs(client)) return null;
            var b = Encoding.ASCII.GetBytes(command);
            client.Write(b, 0, b.Length); client.Flush();
            using var r = new StreamReader(client, Encoding.UTF8);
            return r.ReadLine();
        }
        catch { return null; }
    }
}
