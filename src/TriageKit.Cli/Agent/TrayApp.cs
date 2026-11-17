using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Windows.Forms;

namespace TriageKit.Cli.Agent;

/// <summary>
/// Tray icon for the signed-in user. Reads the service's status file (read-only for users) and talks to the
/// service only through the two-command pipe. Runs without administrator rights.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _statusItem, _detailItem, _scanItem;
    private readonly System.Windows.Forms.Timer _timer;
    private long _lastSeenScan = -1;
    private string _lastState = "";
    private readonly Dictionary<string, Icon> _icons = new();

    public TrayApp()
    {
        _statusItem = new ToolStripMenuItem("TriageKit") { Enabled = false, Font = new Font(SystemFonts.MenuFont ?? SystemFonts.DefaultFont, FontStyle.Bold) };
        _detailItem = new ToolStripMenuItem("Waiting for the first scan...") { Enabled = false };
        _scanItem = new ToolStripMenuItem("Scan now", null, (_, _) => ScanNow());
        var menu = new ContextMenuStrip();
        menu.Items.AddRange(new ToolStripItem[]
        {
            _statusItem, _detailItem, new ToolStripSeparator(),
            new ToolStripMenuItem("Open TriageKit", null, (_, _) => OpenApp("overview")),
            new ToolStripMenuItem("Show findings", null, (_, _) => OpenApp("findings")),
            _scanItem, new ToolStripSeparator(),
            new ToolStripMenuItem("Hide icon until next sign-in", null, (_, _) => ExitThread()),
        });
        _icon = new NotifyIcon { ContextMenuStrip = menu, Visible = true, Text = "TriageKit", Icon = IconFor("grey") };
        _icon.DoubleClick += (_, _) => OpenApp("overview");
        _icon.BalloonTipClicked += (_, _) => OpenApp("findings");
        _timer = new System.Windows.Forms.Timer { Interval = 15000 };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Refresh();
    }

    private void Refresh()
    {
        var s = AgentStatus.Read(AgentPaths.StatusFile);
        if (s is null)
        {
            _icon.Icon = IconFor("grey"); _icon.Text = "TriageKit: service not running";
            _statusItem.Text = "Service not running"; _detailItem.Text = "Reinstall or start the 'TriageKit' service.";
            return;
        }
        var color = s.State == "Scanning" ? "blue" : s.Counts.GetValueOrDefault("Critical") > 0 ? "red" : s.Verdict switch
        {
            "Looks clean" => "green", "Incomplete check" => "amber", "Needs attention" => "amber", null => "grey", _ => "red"
        };
        _icon.Icon = IconFor(color);
        var head = s.State == "Scanning" ? "Scanning..." : s.Verdict is null ? "No scan yet" : $"{s.Verdict} ({s.Score}/100)";
        _statusItem.Text = head;
        _icon.Text = Trim($"TriageKit: {head}", 63);
        _detailItem.Text = s.LastScanTime is null ? "First scan starts shortly" :
            $"Last scan {DateTime.Parse(s.LastScanTime):ddd HH:mm}" + (s.NextScan is null ? "" : $" · next {DateTime.Parse(s.NextScan):ddd HH:mm}");
        _scanItem.Enabled = s.State != "Scanning";

        // Alert once per new scan that brought new issues.
        if (_lastSeenScan >= 0 && s.LastScanId > _lastSeenScan && s.NewAlertable > 0)
        {
            var body = string.Join("\n", s.NewTitles.Select(t => "• " + Trim(t, 90)));
            _icon.ShowBalloonTip(15000, $"TriageKit found {s.NewAlertable} new issue{(s.NewAlertable == 1 ? "" : "s")}", body + "\nClick to open the report.",
                                 s.Counts.GetValueOrDefault("Critical") > 0 || s.Counts.GetValueOrDefault("High") > 0 ? ToolTipIcon.Warning : ToolTipIcon.Info);
        }
        else if (_lastState == "Scanning" && s.State == "Idle" && !string.IsNullOrEmpty(s.LastError))
            _icon.ShowBalloonTip(10000, "TriageKit scan problem", Trim(s.LastError, 200), ToolTipIcon.Error);
        _lastSeenScan = s.LastScanId;
        _lastState = s.State;
    }

    private void ScanNow()
    {
        var reply = AgentClient.Send("SCAN");
        string msg = "The TriageKit service is not responding.";
        if (reply is not null)
        {
            try { using var d = JsonDocument.Parse(reply); msg = d.RootElement.GetProperty("message").GetString() ?? msg; } catch { }
        }
        _icon.ShowBalloonTip(5000, "TriageKit", msg, ToolTipIcon.Info);
        Refresh();
    }

    /// <summary>Reports are readable by administrators only, so the tray opens the app (which asks for admin) instead.</summary>
    private static void OpenApp(string page)
    {
        var exe = Path.Combine(AgentPaths.InstallDir, "TriageKit.exe");
        if (!File.Exists(exe)) return;
        try { Process.Start(new ProcessStartInfo(exe, $"open {page}") { UseShellExecute = true }); } catch { }
    }

    private void OpenReport()
    {
        var s = AgentStatus.Read(AgentPaths.StatusFile);
        if (s?.ReportPath is not null && File.Exists(s.ReportPath)) Open(s.ReportPath);
        else _icon.ShowBalloonTip(5000, "TriageKit", "No report yet. The first scan runs a few minutes after installation.", ToolTipIcon.Info);
    }

    private static void Open(string path)
    {
        // Only ever open our own report files from the protected data folder.
        var full = Path.GetFullPath(path);
        if (!full.StartsWith(AgentPaths.DataDir, StringComparison.OrdinalIgnoreCase) || !full.EndsWith(".html", StringComparison.OrdinalIgnoreCase) || !File.Exists(full)) return;
        try { Process.Start(new ProcessStartInfo(full) { UseShellExecute = true }); } catch { }
    }

    private static string Trim(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";

    private Icon IconFor(string color)
    {
        if (_icons.TryGetValue(color, out var cached)) return cached;
        var fill = color switch
        {
            "green" => Color.FromArgb(35, 120, 75), "amber" => Color.FromArgb(201, 134, 18), "red" => Color.FromArgb(209, 70, 47),
            "blue" => Color.FromArgb(47, 111, 174), _ => Color.FromArgb(120, 130, 136)
        };
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            // Evidence-tag shape: document with a folded corner and an eyelet.
            using var path = new GraphicsPath();
            path.AddPolygon(new[] { new Point(5, 2), new Point(20, 2), new Point(27, 9), new Point(27, 30), new Point(5, 30) });
            using var brush = new SolidBrush(fill);
            g.FillPath(brush, path);
            using var white = new SolidBrush(Color.White);
            g.FillEllipse(white, 17, 6, 6, 6);
            using var pen = new Pen(Color.White, 2.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawLine(pen, 10, 18, 22, 18);
            g.DrawLine(pen, 10, 24, 18, 24);
        }
        var h = bmp.GetHicon();
        var icon = (Icon)Icon.FromHandle(h).Clone();
        DestroyIcon(h);
        _icons[color] = icon;
        return icon;
    }

    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr handle);

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _timer.Dispose(); _icon.Visible = false; _icon.Dispose(); foreach (var i in _icons.Values) i.Dispose(); }
        base.Dispose(disposing);
    }

    public static int Run()
    {
        using var mutex = new Mutex(true, @"Local\TriageKit.Tray", out bool first);
        if (!first) return 0;   // already running for this user
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrayApp());
        return 0;
    }
}
