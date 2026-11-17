using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using TriageKit.Cli.Agent;
using TriageKit.Core.Agent;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;
using TriageKit.Core.Reporting;
using TriageKit.Core.Rules;

namespace TriageKit.Cli.Ui;

/// <summary>
/// The only way the UI can reach the app. A fixed list of commands; arguments are validated; paths never come
/// from the page (reports are referenced by scan id and resolved inside our own reports folder).
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class Bridge
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() }, MaxDepth = 64 };
    private readonly AppWindow _win;
    private readonly string _version;
    private readonly UiStore _store = UiStore.Detect();
    private CancellationTokenSource? _scanCts;
    private volatile bool _scanning;
    private string? _exeSha;
    private readonly SafeStartHost _safe;

    public Bridge(AppWindow win, string version)
    {
        _win = win; _version = version;
        _safe = new SafeStartHost(win, _store, version, () => _scanning);
        Task.Run(async () =>
        {
            try { _store.ImportExisting(); } catch { }
            _win.Post(new { @event = "app.changed" });
            if (Environment.ProcessPath is string exe) Updates.CleanupOld(exe);
            await CheckUpdate();
            var lastUpdateCheck = DateTime.UtcNow;
            while (true)
            {
                await Task.Delay(TimeSpan.FromHours(4));
                if (DateTime.UtcNow - lastUpdateCheck > TimeSpan.FromHours(20)) { await CheckUpdate(); lastUpdateCheck = DateTime.UtcNow; }
            }
        });
    }

    /// <summary>Files dropped on the page (WebView2 passes them to the host directly, never through page code).</summary>
    public void ReceiveFiles(IReadOnlyList<string> paths) => _safe.Dropped(paths);

    public void Receive(string json)
    {
        long id = 0;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            id = root.GetProperty("id").GetInt64();
            var cmd = root.GetProperty("cmd").GetString() ?? "";
            var args = root.TryGetProperty("args", out var a) ? a.Clone() : default;
            Task.Run(async () =>
            {
                try { var result = await Handle(cmd, args); _win.Post(new { id, ok = true, result }); }
                catch (Exception ex) { _win.Post(new { id, ok = false, error = ex.Message }); }
            });
        }
        catch (Exception ex) { _win.Post(new { id, ok = false, error = "Bad request: " + ex.Message }); }
    }

    private async Task<object?> Handle(string cmd, JsonElement a)
    {
        switch (cmd)
        {
            case "app.state": return AppState();
            case "app.theme": return true;
            case "scans.list": using (var h = _store.Open()) return h.Scans(200).Select(Summary).ToList();
            case "scan.get": return ScanDetail(Long(a, "id"));
            case "scan.start": return StartScan(Str(a, "mode") ?? "full", Bool(a, "offline"));
            case "doctor.latest": return DoctorLatest();
            case "scan.cancel": _scanCts?.Cancel(); return new { ok = true };
            case "report.open": { var dir = ReportDir(Long(a, "id")); var html = Path.Combine(dir, "report.html"); Shell(html, _store.Installed); return true; }
            case "report.folder": { var dir = ReportDir(Long(a, "id")); AsUser.Open(dir); return true; }
            case "report.share": return ShareReport(Long(a, "id"));
            case "findings.accept": { var r = Accept(a); _win.Post(new { @event = "app.changed" }); return r; }
            case "suppressions.list": return Suppressions().Items.OrderByDescending(i => i.Created).Select(i => new { i.Id, kind = i.Kind, i.Title, i.Reason, i.RuleId, i.Path, i.Sha256, created = i.Created.ToString("s"), until = i.Until?.ToString("s") }).ToList();
            case "suppressions.remove":
            {
                var set = Suppressions(); var id = Str(a, "id") ?? "";
                if (set.Items.RemoveAll(i => i.Id == id) > 0) { set.Save(SuppressionsPath); Rescore(); _win.Post(new { @event = "app.changed" }); }
                return true;
            }
            case "shell.open": OpenExternal(Str(a, "url") ?? ""); return true;
            case "update.check": await CheckUpdate(force: true); return new { available = _update is not null, version = _update?.Version };
            case "update.install": return await InstallUpdate();
            case "app.restart":
                if (Environment.ProcessPath is string me) { try { Process.Start(new ProcessStartInfo(me) { UseShellExecute = true }); } catch { } }
                _win.Post(new { @event = "app.closing" }); _ = Task.Run(async () => { await Task.Delay(500); Environment.Exit(0); }); return true;
            case "safestart.pick": return await _safe.Pick(Bool(a, "folder"));
            case "safestart.check": return _safe.Check(Str(a, "token") ?? "");
            case "safestart.cancel": _safe.Cancel(); return true;
            case "safestart.history": return _safe.History();
            case "safestart.get": return _safe.Get(Str(a, "id") ?? "");
            case "watch.state": return _safe.WatchState();
            case "watch.before": return _safe.WatchBefore();
            case "watch.after": return _safe.WatchAfter();
            case "watch.discard": return _safe.WatchDiscard();
            case "settings.get": return SettingsGet();
            case "settings.save": SettingsSave(a); return new { ok = true };
            case "agent.install": return await RunElevatedTask(() => Installer.Install(_version, _ => { }), "Daily protection is on. The first automatic check runs in about 5 minutes.");
            case "agent.uninstall": return await RunElevatedTask(() => Installer.Uninstall(Bool(a, "purge"), _ => { }), "Daily protection was turned off. Your history was kept.");
            case "agent.scanNow": { var r = AgentClient.Send("SCAN"); return new { message = r is null ? "The TriageKit service is not responding." : (JsonDocument.Parse(r).RootElement.GetProperty("message").GetString() ?? "OK") }; }
            case "agent.saveConfig": AgentSave(a); return new { ok = true };
            default: throw new InvalidOperationException("Unknown command.");
        }
    }

    // ------------------------------------------------------------------ state
    private object AppState()
    {
        AppWindow.RuntimeAvailable(out var wv);
        var pack = RulePack.Verify(Path.Combine(AppContext.BaseDirectory, "rules"));
        _exeSha ??= TryHash(Environment.ProcessPath);
        return new
        {
            version = _version, edition = _store.Installed ? "Installed" : "Portable", elevated = Sys.IsElevated(), machine = Environment.MachineName,
            os = OsName(), scanning = _scanning, exePath = Environment.ProcessPath, exeSha256 = _exeSha, webview = wv,
            rules = new { version = pack.Trusted ? pack.Version : Indicators.LoadBuiltIn().Version, trusted = pack.Trusted },
            agent = Agent(),
            update = _update is null ? null : new { version = _update.Version, notes = _update.Notes, published = _update.Published.ToString("s"), size = _update.Size, status = _updateStatus },
        };
    }

    private static string OsName()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var name = k?.GetValue("ProductName") as string ?? "Windows"; var disp = k?.GetValue("DisplayVersion") as string;
            if (Environment.OSVersion.Version.Build >= 22000) name = name.Replace("Windows 10", "Windows 11");
            return disp is null ? name : $"{name} {disp}";
        }
        catch { return "Windows"; }
    }


    private string ServerUrl => AppConfig.Load(_store.ConfigPath).UpdateServerUrl ?? Updates.DefaultUrl;

    // ------------------------------------------------------------------ updates
    private UpdateInfo? _update;
    private string? _updateStatus;

    private async Task CheckUpdate(bool force = false)
    {
        var cfg = AppConfig.Load(_store.ConfigPath);
        if (!cfg.CheckForUpdates && !force) return;
        var u = await Updates.CheckAsync(ServerUrl, _version, cfg.UpdateChannel);
        if (u?.Version != _update?.Version) { _update = u; _win.Post(new { @event = "app.changed" }); }
    }

    private async Task<object> InstallUpdate()
    {
        var u = _update ?? throw new InvalidOperationException("No update is available.");
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Can't find TriageKit.exe.");
        if (_scanning) throw new InvalidOperationException("Wait for the current check to finish.");
        _updateStatus = "Downloading…"; _win.Post(new { @event = "app.changed" });
        try
        {
            var bytes = await Updates.DownloadAsync(u, new Progress<double>(p => { var t = $"Downloading… {p:P0}"; if (t != _updateStatus) { _updateStatus = t; _win.Post(new { @event = "app.changed" }); } }));
            _updateStatus = "Installing…"; _win.Post(new { @event = "app.changed" });
            bool service = _store.Installed && ServiceInstalled();
            Updates.Install(exe, bytes);
            // The installed service runs the same exe: restart it so it uses the new version.
            if (service && Path.GetFullPath(exe).Equals(Path.GetFullPath(Path.Combine(AgentPaths.InstallDir, "TriageKit.exe")), StringComparison.OrdinalIgnoreCase))
                try { using var sc = new ServiceController(AgentPaths.ServiceName); if (sc.Status == ServiceControllerStatus.Running) { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } sc.Start(); } catch { }
            _updateStatus = $"Version {u.Version} is installed. Restart TriageKit to use it.";
            _win.Post(new { @event = "app.changed" });
            return new { ok = true, restart = true };
        }
        catch (Exception ex) { _updateStatus = null; _win.Post(new { @event = "app.changed" }); throw new InvalidOperationException("Update failed: " + ex.Message); }
    }

    private static bool ServiceInstalled() { try { return ServiceController.GetServices().Any(s => s.ServiceName.Equals(AgentPaths.ServiceName, StringComparison.OrdinalIgnoreCase)); } catch { return false; } }

    private object Agent()
    {
        bool installed = ServiceInstalled(), running = false;
        if (installed) try { using var sc = new ServiceController(AgentPaths.ServiceName); running = sc.Status == ServiceControllerStatus.Running; } catch { }
        var status = AgentStatus.Read(AgentPaths.StatusFile);
        var cfg = AgentConfig.Load(AgentPaths.AgentConfigFile);
        return new { installed, running, nextScan = status?.NextScan, config = new { dailyScanTime = cfg.DailyScanTime, quickScheduledScans = cfg.QuickScheduledScans, notifyOnNewFindings = cfg.NotifyOnNewFindings, keepScans = cfg.KeepScans } };
    }

    private static object Summary(ScanSummary s) => new { id = s.Id, time = s.Started.ToString("s"), score = s.Score, verdict = s.Verdict, counts = s.Counts, quick = s.Quick };

    private object ScanDetail(long id)
    {
        using var h = _store.Open();
        var all = h.Scans(100000);
        var s = all.FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("That check no longer exists.");
        var dir = _store.ReportDirOf(s);
        var result = dir is null ? null : UiStore.Load(Path.Combine(dir, "results.json"));
        // Re-apply the current accept list, so accepting something updates old scans too.
        var findings = Suppressions().Apply((result?.Findings ?? new List<Finding>()).Select(f => f.Accepted ? f with { Accepted = false, AcceptedReason = null } : f));
        var highlights = Highlights.Build(findings);
        var prev = all.Where(x => x.Id < id && (s.Quick || !x.Quick)).OrderByDescending(x => x.Id).FirstOrDefault();
        var diff = FindingDiff.Compare(prev is null ? null : h.FindingsOf(prev.Id), h.FindingsOf(id));
        return new
        {
            summary = Summary(s), findings, highlights,
            diff = new { first = prev is null, @new = diff.New.OrderBy(f => f.Severity).Select(f => new { severity = f.Severity, title = f.Title }), resolved = diff.Resolved.OrderBy(f => f.Severity).Select(f => new { severity = f.Severity, title = f.Title }) },
        };
    }

    // ------------------------------------------------------------------ accepted findings & exclusions
    private string SuppressionsPath => AppPaths.SuppressionsFile(_store.Installed, AppContext.BaseDirectory);
    private SuppressionSet Suppressions() => SuppressionSet.Load(SuppressionsPath);

    private object Accept(JsonElement a)
    {
        if (_store.Installed && !Sys.IsElevated()) throw new InvalidOperationException("Restart TriageKit as administrator to change the accept list.");
        var kind = Str(a, "kind") ?? "finding";
        var title = (Str(a, "title") ?? "").Trim();
        var reason = (Str(a, "reason") ?? "").Trim();
        if (reason.Length > 200) reason = reason[..200];
        int days = a.TryGetProperty("days", out var d) && d.ValueKind == JsonValueKind.Number ? Math.Clamp(d.GetInt32(), 0, 3650) : 0;
        var sev = Enum.TryParse<Severity>(Str(a, "severity"), out var sv) ? sv : Severity.Medium;
        var item = new Suppression { Title = title.Length > 200 ? title[..200] : title, Reason = reason, Until = days > 0 ? DateTime.UtcNow.AddDays(days) : null };
        switch (kind)
        {
            case "finding":
                item.Fingerprint = FindingFingerprint.Of(new Finding { Severity = sev, Category = Str(a, "category") ?? "", Title = title, RuleId = Str(a, "ruleId") });
                break;
            case "rule":
                var rule = Str(a, "ruleId");
                if (string.IsNullOrWhiteSpace(rule) || rule.StartsWith("collector.")) throw new InvalidOperationException("This kind of finding can't be accepted as a whole.");
                item.RuleId = rule; break;
            case "path":
                var path = (Str(a, "path") ?? "").Trim().Trim('"');
                if (path.Length < 4 || !Path.IsPathFullyQualified(path)) throw new InvalidOperationException("Enter a full folder or file path, e.g. D:\\Games.");
                var full = Path.GetFullPath(path).TrimEnd('\\');
                // Never allow excluding whole drives or Windows itself: that would blind the scan.
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
                var users = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))!.TrimEnd('\\');
                if (full.Length <= 3 || full.Equals(win, StringComparison.OrdinalIgnoreCase) || win.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase)
                    || full.Equals(users, StringComparison.OrdinalIgnoreCase) || full.Equals(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("That folder is too broad to exclude. Pick a specific folder, e.g. a game or tools folder.");
                item.Path = full; if (item.Title.Length == 0) item.Title = full; break;
            default: throw new InvalidOperationException("Unknown kind.");
        }
        var set = Suppressions();
        set.Items.RemoveAll(i => (i.Fingerprint is not null && i.Fingerprint == item.Fingerprint) || (i.RuleId is not null && i.RuleId == item.RuleId) || (i.Path is not null && string.Equals(i.Path, item.Path, StringComparison.OrdinalIgnoreCase)));
        set.Items.Add(item);
        set.Save(SuppressionsPath);
        Rescore();
        return new { ok = true, id = item.Id, critical = sev == Severity.Critical && kind != "finding" };
    }

    /// <summary>Updates the stored score of recent scans after the accept list changed.</summary>
    private void Rescore(int recent = 20)
    {
        var set = Suppressions();
        using var h = _store.Open();
        foreach (var s in h.Scans(recent))
        {
            var dir = _store.ReportDirOf(s);
            var r = dir is null ? null : UiStore.Load(Path.Combine(dir, "results.json"));
            if (r is null) continue;
            var findings = set.Apply(r.Findings.Select(f => f.Accepted ? f with { Accepted = false, AcceptedReason = null } : f));
            var (score, verdict) = Scoring.Calculate(findings);
            var counts = new Dictionary<string, int>();
            foreach (Severity sv in Enum.GetValues<Severity>()) counts[sv.ToString()] = findings.Count(f => f.Severity == sv && !f.Accepted);
            counts["Accepted"] = findings.Count(f => f.Accepted);
            h.UpdateScore(s.Id, score, verdict, counts);
        }
    }

    private object ShareReport(long id)
    {
        var dir = ReportDir(id);
        var r = UiStore.Load(Path.Combine(dir, "results.json")) ?? throw new InvalidOperationException("This scan's results file is missing.");
        r.Findings = Suppressions().Apply(r.Findings.Select(f => f.Accepted ? f with { Accepted = false, AcceptedReason = null } : f));
        (r.Score, r.Verdict) = Scoring.Calculate(r.Findings);
        r.Highlights = Highlights.Build(r.Findings);
        foreach (Severity sv in Enum.GetValues<Severity>()) r.Counts[sv.ToString()] = r.Findings.Count(f => f.Severity == sv && !f.Accepted);
        var path = ReportWriter.WriteShareable(r, dir);
        AsUser.Open(dir);
        return new { path };
    }

    private string ReportDir(long id)
    {
        using var h = _store.Open();
        var s = h.Scans(100000).FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("That check no longer exists.");
        return _store.ReportDirOf(s) ?? throw new InvalidOperationException("The report folder was moved or deleted.");
    }

    // ------------------------------------------------------------------ scanning
    private object DoctorLatest()
    {
        if (!Directory.Exists(_store.ReportsDir)) return new { found = false };
        var dir = Directory.GetDirectories(_store.ReportsDir, "*_doctor").OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase).FirstOrDefault();
        var r = dir is null ? null : UiStore.Load(Path.Combine(dir, "results.json"));
        if (r is null) return new { found = false };
        var cats = new[] { "Stability", "Performance", "Gaming" };
        var findings = r.Findings.Where(f => cats.Contains(f.Category)).ToList();
        object? D(string k) => r.Data.TryGetValue(k, out var v) ? v : null;
        return new { found = true, time = r.Meta.Started, folder = Path.GetFileName(dir), findings, highlights = Highlights.Build(findings, 6),
                     stability = D("Stability & crashes"), health = D("Devices & system health"), performance = D("Gaming & performance"), gaming = D("Gamer account protection"),
                     live = D("Live performance (20 s)"), hardware = D("Monitors, RAM & graphics card"), sensors = D("Sensors: voltages & temperatures") };
    }

    private object StartScan(string mode, bool offline)
    {
        if (_scanning) throw new InvalidOperationException("A check is already running.");
        if (_safe.Busy) throw new InvalidOperationException("Wait for Safe Start to finish.");
        bool quick = mode == "quick", deep = mode == "deep", doctor = mode == "doctor";
        _scanning = true;
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;
        var cfg = AppConfig.Load(_store.ConfigPath);
        var modules = doctor ? new HashSet<string>(ScanRunner.AddOnModules, StringComparer.OrdinalIgnoreCase)
                             : new HashSet<string>(new[] { "security" }.Concat(quick ? Array.Empty<string>() : cfg.IncludeModules), StringComparer.OrdinalIgnoreCase);
        var checks = CheckCatalog.All().OrderBy(c => c.Order).Where(c => modules.Contains(c.Module) && !(quick && c.IsSlow) && (deep || !c.DeepOnly)).Select(c => c.Name).ToList();
        _win.Post(new { @event = "scan.started", data = new { checks, quick, deep, doctor } });
        Task.Run(() =>
        {
            try
            {
                var lastStatus = DateTime.MinValue;
                var outcome = ScanRunner.Run(new ScanRequest
                {
                    BaseDirectory = AppContext.BaseDirectory, OutputRoot = _store.ReportsDir, Config = cfg, Quick = quick, Deep = deep, Offline = offline, Modules = modules, FolderSuffix = doctor ? "_doctor" : "",
                    Edition = _store.Installed ? "Installed" : "Portable", Installed = _store.Installed, Cancellation = token,
                    Progress = (name, i, n) => _win.Post(new { @event = "scan.progress", data = new { name, index = i, total = n } }),
                    CheckFinished = o => _win.Post(new { @event = "scan.checkDone", data = new { name = o.Name, ms = o.Ms, state = o.State, note = o.Note } }),
                    CheckStarted = name => _win.Post(new { @event = "scan.checkStart", data = new { name } }),
                    Status = m => { if ((DateTime.Now - lastStatus).TotalMilliseconds > 120) { lastStatus = DateTime.Now; _win.Post(new { @event = "scan.status", data = new { text = m } }); } },
                }, _version);
                if (doctor)
                {
                    _win.Post(new { @event = "scan.finished", data = new { doctor = true, counts = outcome.Result.Counts } });
                    return;
                }
                long id; ScanDiff diff;
                using (var h = _store.Open()) (id, diff) = h.Record(outcome.Result, outcome.ReportHtml);
                _win.Post(new { @event = "scan.finished", data = new { id, score = outcome.Result.Score, verdict = outcome.Result.Verdict, counts = outcome.Result.Counts, newCount = diff.New.Count, resolvedCount = diff.Resolved.Count } });
            }
            catch (Exception ex) { _win.Post(new { @event = "scan.failed", data = new { message = "The check failed: " + ex.Message } }); }
            finally { _scanning = false; }
        });
        return new { ok = true };
    }

    // ------------------------------------------------------------------ settings (config.json, unknown keys preserved)
    private static readonly string[] SettingKeys = { "RunDefenderQuickScan", "RunYara", "RunAutoruns", "EventLogDays", "RecentFileDays", "OnlineLookups", "OnlineLookupsAsked", "ReputationCircl", "ReputationDefender", "ScanArchives", "RememberFileChecks", "CheckForUpdates" };

    private object SettingsGet()
    {
        var c = AppConfig.Load(_store.ConfigPath);
        static object Secret(string? v) => string.IsNullOrWhiteSpace(v) ? new { set = false } : new { set = true, hint = v.Length > 4 ? v[^4..] : "" };
        return new
        {
            path = _store.ConfigPath,
            modules = c.IncludeModules,
            values = new { runDefenderQuickScan = c.RunDefenderQuickScan, runYara = c.RunYara, runAutoruns = c.RunAutoruns, eventLogDays = c.EventLogDays, recentFileDays = c.RecentFileDays, onlineLookups = c.OnlineLookups, onlineLookupsAsked = c.OnlineLookupsAsked, reputationCircl = c.ReputationCircl, reputationDefender = c.ReputationDefender, scanArchives = c.ScanArchives, rememberFileChecks = c.RememberFileChecks, checkForUpdates = c.CheckForUpdates },
            secrets = new { virusTotal = Secret(c.VirusTotalApiKey), malwareBazaar = Secret(c.MalwareBazaarAuthKey) },
        };
    }

    private void SettingsSave(JsonElement a)
    {
        JsonObject root;
        try { root = File.Exists(_store.ConfigPath) ? (JsonNode.Parse(File.ReadAllText(_store.ConfigPath), documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true }) as JsonObject ?? new()) : new(); }
        catch { root = new(); }
        if (a.TryGetProperty("values", out var v))
            foreach (var key in SettingKeys)
            {
                var camel = char.ToLowerInvariant(key[0]) + key[1..];
                if (!v.TryGetProperty(camel, out var val)) continue;
                root[key] = val.ValueKind switch
                {
                    JsonValueKind.True => true, JsonValueKind.False => false,
                    JsonValueKind.Number => Math.Clamp(val.GetInt32(), 1, 365),
                    _ => root[key]?.DeepClone(),
                };
            }
        if (a.TryGetProperty("modules", out var mods) && mods.ValueKind == JsonValueKind.Array)
        {
            var arr = new JsonArray();
            foreach (var m in mods.EnumerateArray()) if (m.GetString() is string ms && ScanRunner.AddOnModules.Contains(ms)) arr.Add(ms);
            root["IncludeModules"] = arr;
        }
        // Installed copy: config.json sits in Program Files, which every user can read, so API keys go to an
        // admins-only secrets file instead. The portable copy keeps them in config.json next to the exe.
        var secretsRoot = _store.Installed ? AppConfig.ReadSecrets() : root;
        if (a.TryGetProperty("secrets", out var s))
        {
            void Set(string prop, string key)
            {
                if (!s.TryGetProperty(prop, out var x) || x.ValueKind != JsonValueKind.String) return;
                var val = x.GetString()!.Trim();
                if (val.Length > 200 || val.Any(ch => char.IsControl(ch) || char.IsWhiteSpace(ch))) throw new InvalidOperationException("That key doesn't look right.");
                secretsRoot[key] = val;
            }
            Set("virusTotal", "VirusTotalApiKey"); Set("malwareBazaar", "MalwareBazaarAuthKey");
        }
        if (_store.Installed)
        {
            foreach (var k in AppConfig.SecretKeys) if (root[k] is JsonNode n && n.GetValueKind() == JsonValueKind.String && !secretsRoot.ContainsKey(k)) secretsRoot[k] = n.DeepClone();
            foreach (var k in AppConfig.SecretKeys) root.Remove(k);
            AppConfig.WriteSecrets(secretsRoot);
        }
        File.WriteAllText(_store.ConfigPath, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    // ------------------------------------------------------------------ daily protection (installed agent)
    private static Task<object> RunElevatedTask(Func<int> action, string okMessage) => Task.Run<object>(() =>
    {
        if (!Sys.IsElevated()) throw new InvalidOperationException("Restart TriageKit as administrator first.");
        var code = action();
        if (code != 0) throw new InvalidOperationException($"That didn't work (code {code}). See {AgentPaths.ServiceLog}.");
        return new { message = okMessage };
    });

    private static void AgentSave(JsonElement a)
    {
        var cfg = AgentConfig.Load(AgentPaths.AgentConfigFile);
        var t = Str(a, "dailyScanTime");
        if (t is not null && TimeSpan.TryParse(t, out var ts) && ts >= TimeSpan.Zero && ts < TimeSpan.FromDays(1)) cfg.DailyScanTime = ts.ToString(@"hh\:mm");
        if (a.TryGetProperty("quickScheduledScans", out var q)) cfg.QuickScheduledScans = q.ValueKind == JsonValueKind.True;
        if (a.TryGetProperty("notifyOnNewFindings", out var n)) cfg.NotifyOnNewFindings = n.ValueKind == JsonValueKind.True;
        if (a.TryGetProperty("keepScans", out var k) && k.ValueKind == JsonValueKind.Number) cfg.KeepScans = Math.Clamp(k.GetInt32(), 5, 365);
        if (!Sys.IsElevated()) throw new InvalidOperationException("Restart TriageKit as administrator to change these settings.");
        File.WriteAllText(AgentPaths.AgentConfigFile, JsonSerializer.Serialize(cfg, new JsonSerializerOptions { WriteIndented = true }));
    }

    // ------------------------------------------------------------------ helpers
    public static void OpenExternal(string url)
    {
        // Only plain https links to well-known reference sites.
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return;
        var allowed = new[] { "attack.mitre.org", "www.virustotal.com", "bazaar.abuse.ch", "hashlookup.circl.lu", "learn.microsoft.com", "support.microsoft.com" };
        if (!allowed.Contains(u.Host, StringComparer.OrdinalIgnoreCase)) return;
        AsUser.Open(u.AbsoluteUri);
    }

    private static void Shell(string file, bool installed = false)
    {
        if (!File.Exists(file)) return;
        // Only open a report whose bytes still match the evidence manifest written with it.
        if (!Core.Reporting.ReportIntegrity.Matches(file)) throw new InvalidOperationException("This report was changed after the scan, so it won't be opened.");
        // Installed-mode reports sit in an admin-only folder, and the browser runs without admin rights. Open a copy in
        // this user's own temp folder (readable only by this user) instead.
        var target = file;
        var users = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
        bool readable;
        try { readable = new FileInfo(file).GetAccessControl().GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier)).OfType<System.Security.AccessControl.FileSystemAccessRule>().Any(r => r.IdentityReference == users && r.AccessControlType == System.Security.AccessControl.AccessControlType.Allow && r.FileSystemRights.HasFlag(System.Security.AccessControl.FileSystemRights.ReadData)); }
        catch { readable = false; }
        // Only the installed edition keeps reports in an admin-only folder. The portable edition's reports sit with
        // TriageKit (often on a stick, where FAT/exFAT has no permissions at all) and are opened directly, so no copy
        // is ever left on the PC.
        if (installed && !readable) target = ViewCopy(file);
        AsUser.Open(target);
    }
    /// <summary>
    /// A copy of an admin-only report that only the desktop user (who opens it through Explorer) can read: a new
    /// folder with an unguessable name under TriageKit's admin-only data folder, created with its permissions already
    /// set, and a file that must not exist yet. Nothing user-writable is involved, so nobody can redirect the copy.
    /// Copies older than a day are removed.
    /// </summary>
    private static string ViewCopy(string file)
    {
        var root = Path.Combine(TriageKit.Cli.Agent.AgentPaths.DataDir, "View");
        // Secure the folder once (or again if someone else made it). Re-securing every time would reset the
        // permissions of a copy that is still open in the browser.
        var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
        bool ours;
        try { var di = new DirectoryInfo(root); ours = di.Exists && !di.Attributes.HasFlag(FileAttributes.ReparsePoint) && di.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier)) is System.Security.Principal.SecurityIdentifier o && o == admins; }
        catch { ours = false; }
        if (!ours) TriageKit.Cli.Agent.SecureFolder.EnsurePrivate(root);
        foreach (var old in new DirectoryInfo(root).EnumerateDirectories())
            try { if (!old.Attributes.HasFlag(FileAttributes.ReparsePoint) && old.CreationTimeUtc < DateTime.UtcNow.AddDays(-1)) old.Delete(true); } catch { }
        var viewer = TriageKit.Cli.Agent.AsUser.ShellUser() ?? System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var sec = new System.Security.AccessControl.DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        const System.Security.AccessControl.InheritanceFlags inherit = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
        foreach (var (who, rights) in new[] {
            (new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null), System.Security.AccessControl.FileSystemRights.FullControl),
            (new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null), System.Security.AccessControl.FileSystemRights.FullControl),
            (viewer, System.Security.AccessControl.FileSystemRights.ReadAndExecute) })
            sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(who, rights, inherit, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        var dir = new DirectoryInfo(Path.Combine(root, Guid.NewGuid().ToString("N")));
        System.IO.FileSystemAclExtensions.Create(dir, sec);
        var target = Path.Combine(dir.FullName, Path.GetFileName(Path.GetDirectoryName(file)) + "-" + Path.GetFileName(file));
        using (var src = File.OpenRead(file))
        using (var dst = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            src.CopyTo(dst);
        return target;
    }

    private static string? TryHash(string? path) { try { using var f = File.OpenRead(path!); return Convert.ToHexString(SHA256.HashData(f)); } catch { return null; } }
    private static long Long(JsonElement a, string k) => a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.TryGetInt64(out var l) ? l : throw new ArgumentException($"Missing {k}");
    private static string? Str(JsonElement a, string k) => a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static bool Bool(JsonElement a, string k) => a.ValueKind == JsonValueKind.Object && a.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.True;
}
