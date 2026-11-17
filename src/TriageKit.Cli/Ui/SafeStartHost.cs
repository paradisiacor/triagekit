using System.Collections.Concurrent;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Windows.Forms;
using TriageKit.Core.SafeStart;

namespace TriageKit.Cli.Ui;

/// <summary>
/// App side of Safe Start. The page never sends a path: files and folders arrive through the native picker or a
/// drag-and-drop that WebView2 hands to the host directly, and the page only gets an opaque token for them.
/// Results are kept as JSON in the reports folder (SafeStart\), the Install Watch "before" snapshot too, so the app can be
/// closed (or the PC restarted) between "before" and "after".
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class SafeStartHost
{
    private readonly AppWindow _win;
    private readonly UiStore _store;
    private readonly string _version;
    private readonly Func<bool> _scanRunning;
    private readonly ConcurrentDictionary<string, string> _tokens = new();
    private CancellationTokenSource? _cts;
    private volatile bool _busy;
    public bool Busy => _busy;

    public SafeStartHost(AppWindow win, UiStore store, string version, Func<bool> scanRunning)
    { _win = win; _store = store; _version = version; _scanRunning = scanRunning; }

    private string Dir { get { var d = Path.Combine(_store.ReportsDir, "SafeStart"); Directory.CreateDirectory(d); return d; } }
    private string BeforeFile => Path.Combine(Dir, "watch-before.json");

    private static readonly JsonSerializerOptions Save = new(InstallWatch.Json) { WriteIndented = true };

    // ------------------------------------------------------------------ choosing what to check
    private object Token(string path)
    {
        var t = Guid.NewGuid().ToString("N");
        _tokens[t] = path;
        bool folder = Directory.Exists(path);
        long size = 0; try { if (!folder) size = new FileInfo(path).Length; } catch { }
        return new { token = t, name = Path.GetFileName(path.TrimEnd('\\', '/')) is { Length: > 0 } n ? n : path, path, folder, size };
    }

    /// <summary>Paths that WebView2 delivered with a drop (CoreWebView2File objects); only the first is used.</summary>
    public void Dropped(IReadOnlyList<string> paths)
    {
        var p = paths.FirstOrDefault(x => File.Exists(x) || Directory.Exists(x));
        _win.Post(new { @event = "safestart.dropped", data = p is null ? null : Token(p) });
    }

    public Task<object?> Pick(bool folder)
    {
        var tcs = new TaskCompletionSource<object?>();
        _win.BeginInvoke(() =>
        {
            try
            {
                string? path = null;
                var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                if (folder)
                {
                    using var d = new FolderBrowserDialog { Description = "Choose the downloaded folder to check", UseDescriptionForTitle = true, InitialDirectory = downloads };
                    if (d.ShowDialog(_win) == DialogResult.OK) path = d.SelectedPath;
                }
                else
                {
                    using var d = new OpenFileDialog { Title = "Choose the download to check", InitialDirectory = downloads, Filter = "All files (*.*)|*.*", DereferenceLinks = false, CheckFileExists = true };
                    if (d.ShowDialog(_win) == DialogResult.OK) path = d.FileName;
                }
                tcs.SetResult(path is null ? null : Token(path));
            }
            catch (Exception ex) { tcs.SetException(ex); }
        });
        return tcs.Task;
    }

    // ------------------------------------------------------------------ check a download
    public object Check(string token)
    {
        if (!_tokens.TryRemove(token, out var path)) throw new InvalidOperationException("Choose the file again.");
        Begin();
        var cts = _cts = new CancellationTokenSource();
        _win.Post(new { @event = "safestart.started", data = new { name = Path.GetFileName(path.TrimEnd('\\', '/')) } });
        Task.Run(() =>
        {
            try
            {
                var last = DateTime.MinValue; int seen = 0;
                var result = ScanRunner.CheckDownload(Request(cts.Token), _version, path, shown =>
                {
                    seen++;
                    if ((DateTime.Now - last).TotalMilliseconds > 150) { last = DateTime.Now; _win.Post(new { @event = "safestart.progress", data = new { text = shown, files = seen } }); }
                });
                var id = $"check_{DateTime.Now:yyyyMMdd-HHmmss}";
                File.WriteAllText(Path.Combine(Dir, id + ".json"), JsonSerializer.Serialize(result, Save));
                Prune("check_*.json", 100);
                _win.Post(new { @event = "safestart.done", data = new { id, result = Shape(result) } });
            }
            catch (OperationCanceledException) { _win.Post(new { @event = "safestart.failed", data = new { message = "The check was stopped." } }); }
            catch (Exception ex) { _win.Post(new { @event = "safestart.failed", data = new { message = "The check couldn't finish: " + ex.Message } }); }
            finally { _busy = false; }
        });
        return new { ok = true };
    }

    public void Cancel() => _cts?.Cancel();

    public object History() =>
        Directory.EnumerateFiles(Dir, "check_*.json").OrderByDescending(f => f).Take(30).Select(f =>
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(f));
                var r = doc.RootElement;
                return (object)new { id = Path.GetFileNameWithoutExtension(f), name = r.GetProperty("name").GetString(), verdict = r.GetProperty("verdict").GetString(),
                                     started = r.GetProperty("started").GetDateTime().ToString("s"), files = r.GetProperty("files").GetInt32() };
            }
            catch { return null!; }
        }).Where(x => x is not null).ToList();

    public object Get(string id)
    {
        if (!System.Text.RegularExpressions.Regex.IsMatch(id, @"^(check|watch)_\d{8}-\d{6}$")) throw new InvalidOperationException("Unknown result.");
        var f = Path.Combine(Dir, id + ".json");
        if (!File.Exists(f)) throw new InvalidOperationException("This result was deleted.");
        return JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(f));
    }

    private static object Shape(DownloadCheck.Result r) => JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(r, InstallWatch.Json));

    // ------------------------------------------------------------------ install watch
    public object WatchState()
    {
        InstallWatch.Snapshot? s = null;
        try { if (File.Exists(BeforeFile)) s = JsonSerializer.Deserialize<InstallWatch.Snapshot>(File.ReadAllText(BeforeFile), InstallWatch.Json); } catch { }
        var last = Directory.EnumerateFiles(Dir, "watch_*.json").OrderByDescending(f => f).Select(Path.GetFileNameWithoutExtension).FirstOrDefault();
        return new { before = s is null ? null : new { taken = s.Taken.ToString("s"), machine = s.Machine, items = s.Inventory.Values.Sum(v => v.Count), findings = s.Findings.Count }, last };
    }

    public object WatchBefore() => RunSnapshot(after: false);
    public object WatchAfter()
    {
        if (!File.Exists(BeforeFile)) throw new InvalidOperationException("Take the \"before\" snapshot first.");
        return RunSnapshot(after: true);
    }

    public object WatchDiscard() { try { File.Delete(BeforeFile); } catch { } return new { ok = true }; }

    private object RunSnapshot(bool after)
    {
        Begin();
        var cts = _cts = new CancellationTokenSource();
        var total = InstallWatch.SnapshotChecks.Length;
        _win.Post(new { @event = "watch.started", data = new { after, total } });
        Task.Run(() =>
        {
            try
            {
                var snap = ScanRunner.Snapshot(Request(cts.Token) with
                {
                    Progress = (name, i, n) => _win.Post(new { @event = "watch.progress", data = new { name, index = i, total = n } }),
                }, _version);
                if (!after)
                {
                    File.WriteAllText(BeforeFile, JsonSerializer.Serialize(snap, Save));
                    _win.Post(new { @event = "watch.done", data = new { after = false } });
                    return;
                }
                var before = JsonSerializer.Deserialize<InstallWatch.Snapshot>(File.ReadAllText(BeforeFile), InstallWatch.Json)!;
                var cmp = InstallWatch.Compare(before, snap);
                var id = $"watch_{DateTime.Now:yyyyMMdd-HHmmss}";
                File.WriteAllText(Path.Combine(Dir, id + ".json"), JsonSerializer.Serialize(cmp, Save));
                Prune("watch_*.json", 50);
                _win.Post(new { @event = "watch.done", data = new { after = true, id, result = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(cmp, InstallWatch.Json)) } });
            }
            catch (OperationCanceledException) { _win.Post(new { @event = "watch.failed", data = new { message = "Stopped." } }); }
            catch (Exception ex) { _win.Post(new { @event = "watch.failed", data = new { message = "The snapshot couldn't finish: " + ex.Message } }); }
            finally { _busy = false; }
        });
        return new { ok = true };
    }

    // ------------------------------------------------------------------ helpers
    private void Begin()
    {
        if (_scanRunning()) throw new InvalidOperationException("Wait for the current check to finish.");
        if (_busy) throw new InvalidOperationException("Safe Start is already working.");
        _busy = true;
    }

    private ScanRequest Request(CancellationToken ct) => new()
    {
        BaseDirectory = AppContext.BaseDirectory, OutputRoot = _store.ReportsDir, Config = AppConfig.Load(_store.ConfigPath),
        Edition = _store.Installed ? "Installed" : "Portable", Installed = _store.Installed, Cancellation = ct,
    };

    private void Prune(string pattern, int keep)
    {
        foreach (var f in Directory.EnumerateFiles(Dir, pattern).OrderByDescending(f => f).Skip(keep)) try { File.Delete(f); } catch { }
    }
}
