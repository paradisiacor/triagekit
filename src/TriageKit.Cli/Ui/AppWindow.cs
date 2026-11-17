using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace TriageKit.Cli.Ui;

/// <summary>
/// The desktop window: a WebView2 control showing the bundled UI (embedded in the exe, served from a private
/// virtual origin). Security: no remote content, navigation locked to our origin, no dev tools in release,
/// and the page can only talk to the app through the small command set in <see cref="Bridge"/>.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class AppWindow : Form
{
    public const string Origin = "https://app.triagekit.local";
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill, DefaultBackgroundColor = System.Drawing.Color.FromArgb(5, 7, 10) };
    private readonly Bridge _bridge;
    private readonly Dictionary<string, string> _assets;

    private readonly string? _startPage;

    public AppWindow(string version, string? startPage = null)
    {
        _startPage = startPage is not null && System.Text.RegularExpressions.Regex.IsMatch(startPage, "^[a-z]{3,12}$") ? startPage : null;
        Text = "TriageKit";
        // Fits a 1366 x 768 laptop panel at 125% scaling (about 1093 x 576 usable): open at 90% of the screen at most.
        var work = Screen.PrimaryScreen?.WorkingArea ?? new System.Drawing.Rectangle(0, 0, 1600, 1000);
        Width = Math.Min(1440, (int)(work.Width * 0.9)); Height = Math.Min(920, (int)(work.Height * 0.9));
        MinimumSize = new System.Drawing.Size(Math.Min(960, work.Width), Math.Min(540, work.Height));
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = System.Drawing.Color.FromArgb(5, 7, 10);
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }
        Controls.Add(_web);
        _bridge = new Bridge(this, version);
        _assets = Assembly.GetExecutingAssembly().GetManifestResourceNames()
            .Where(n => n.StartsWith("ui/", StringComparison.Ordinal) || n.StartsWith("ui\\", StringComparison.Ordinal))
            .ToDictionary(n => n.Replace('\\', '/')[3..], n => n, StringComparer.OrdinalIgnoreCase);
        Load += async (_, _) => await InitAsync();
        HandleCreated += (_, _) => SetDarkTitleBar(true);
    }

    private async Task InitAsync()
    {
        try { await StartBrowserAsync(); }
        catch (Exception ex)
        {
            // Never leave an empty black window: say what went wrong and how to get going again.
            if (IsDisposed) return;
            MessageBox.Show(this, "TriageKit couldn't start its window.\n\n" + ex.Message +
                "\n\nMake sure the Microsoft Edge WebView2 Runtime is installed and up to date (go.microsoft.com/fwlink/p/?LinkId=2124703), then start TriageKit again. " +
                "Scans also work from the command line: TriageKit.exe scan", "TriageKit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            Close();
        }
    }

    private async Task StartBrowserAsync()
    {
        bool elevated = TriageKit.Core.Platform.Sys.IsElevated();
        string dataDir;
        if (elevated)
        {
            // Running as admin: a user-level program must not be able to steer this window. Ignore WebView2 environment
            // overrides and keep the browser profile in ProgramData, writable only by SYSTEM, Administrators and the
            // person at the desktop. WebView2 never runs elevated: its browser processes always run as the desktop user
            // without admin rights, so that account has to be able to write the profile (without it the window stays black).
            foreach (System.Collections.DictionaryEntry kv in Environment.GetEnvironmentVariables())
                if (kv.Key is string k && k.StartsWith("WEBVIEW2_", StringComparison.OrdinalIgnoreCase)) Environment.SetEnvironmentVariable(k, null);
            dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TriageKit", "WebView2-" + Environment.UserName);
            try { Agent.SecureFolder.EnsureBrowserProfile(dataDir, DesktopUser()); }
            catch (Exception ex)
            {
                // Fail closed: the user-writable profile is exactly what an elevated window must not use.
                MessageBox.Show(this, "TriageKit couldn't secure its window data folder, so it won't open with administrator rights.\n\n" + ex.Message +
                    "\n\nRestart the PC and try again, or start TriageKit without administrator rights.", "TriageKit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                Close();
                return;
            }
        }
        else dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TriageKit", "WebView2");
        var env = await CoreWebView2Environment.CreateAsync(null, dataDir, new CoreWebView2EnvironmentOptions { AdditionalBrowserArguments = "" });
        await _web.EnsureCoreWebView2Async(env);
        var core = _web.CoreWebView2;
        var s = core.Settings;
#if DEBUG
        bool dev = Environment.GetEnvironmentVariable("TRIAGEKIT_DEVTOOLS") == "1";
#else
        const bool dev = false;   // release builds never open dev tools (they would give full control of the admin window)
#endif
        s.AreDevToolsEnabled = dev; s.AreDefaultContextMenusEnabled = dev; s.IsStatusBarEnabled = false; s.IsZoomControlEnabled = false;
        s.AreBrowserAcceleratorKeysEnabled = dev; s.IsPasswordAutosaveEnabled = false; s.IsGeneralAutofillEnabled = false; s.IsBuiltInErrorPageEnabled = false;
        s.AreHostObjectsAllowed = false; s.IsWebMessageEnabled = true;

        core.AddWebResourceRequestedFilter(Origin + "/*", CoreWebView2WebResourceContext.All);
        core.WebResourceRequested += (_, e) => Serve(core, e);
        core.NavigationStarting += (_, e) => { if (!e.Uri.StartsWith(Origin + "/", StringComparison.OrdinalIgnoreCase)) e.Cancel = true; };
        core.NewWindowRequested += (_, e) => { e.Handled = true; Bridge.OpenExternal(e.Uri); };
        core.WebMessageReceived += (_, e) =>
        {
            if (!e.Source.StartsWith(Origin + "/", StringComparison.OrdinalIgnoreCase)) return;
            // Drag and drop: the page sends the dropped File objects with postMessageWithAdditionalObjects, and WebView2
            // gives us their real paths here. The page itself never learns or chooses a path.
            var files = e.AdditionalObjects?.OfType<CoreWebView2File>().Select(f => f.Path).ToList();
            if (files is { Count: > 0 }) { _bridge.ReceiveFiles(files); return; }
            _bridge.Receive(e.WebMessageAsJson);
        };
        core.PermissionRequested += (_, e) => e.State = e.PermissionKind == CoreWebView2PermissionKind.ClipboardRead ? CoreWebView2PermissionState.Deny : CoreWebView2PermissionState.Deny;
        core.ProcessFailed += (_, e) =>
        {
            // The page crashed or the browser process went away: reload once, and if the browser itself is gone say so
            // instead of showing a frozen or black window.
            if (e.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessExited || e.ProcessFailedKind == CoreWebView2ProcessFailedKind.RenderProcessUnresponsive)
            {
                if (_reloads++ < 2) try { core.Reload(); } catch { }
                return;
            }
            if (e.ProcessFailedKind == CoreWebView2ProcessFailedKind.BrowserProcessExited && !IsDisposed)
            {
                BeginInvoke(() =>
                {
                    MessageBox.Show(this, "TriageKit's window stopped working (the Microsoft Edge WebView2 Runtime closed unexpectedly). Start TriageKit again.",
                        "TriageKit", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    Close();
                });
            }
        };
        core.Navigate(Origin + "/index.html" + (_startPage is null ? "" : "#" + _startPage));
    }

    private int _reloads;

    /// <summary>
    /// The account signed in to this desktop session. Usually the same account TriageKit runs as; different when a
    /// standard user started it with another account's admin password. WebView2 starts its browser as this account.
    /// </summary>
    private static System.Security.Principal.SecurityIdentifier DesktopUser()
    {
        var self = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        try
        {
            string? Query(int info)
            {
                if (!WTSQuerySessionInformation(IntPtr.Zero, -1, info, out var buf, out _)) return null;
                try { return Marshal.PtrToStringUni(buf); } finally { WTSFreeMemory(buf); }
            }
            var user = Query(5 /* WTSUserName */);
            var domain = Query(7 /* WTSDomainName */);
            if (string.IsNullOrEmpty(user)) return self;
            var account = new System.Security.Principal.NTAccount(string.IsNullOrEmpty(domain) ? user : domain + "\\" + user);
            return (System.Security.Principal.SecurityIdentifier)account.Translate(typeof(System.Security.Principal.SecurityIdentifier));
        }
        catch { return self; }
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);

    private void Serve(CoreWebView2 core, CoreWebView2WebResourceRequestedEventArgs e)
    {
        var path = Uri.TryCreate(e.Request.Uri, UriKind.Absolute, out var u) ? Uri.UnescapeDataString(u.AbsolutePath.TrimStart('/')) : "";
        if (path.Length == 0) path = "index.html";
        if (!_assets.TryGetValue(path, out var res))
        {
            e.Response = core.Environment.CreateWebResourceResponse(null, 404, "Not Found", "");
            return;
        }
        var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(res)!;
        var type = Path.GetExtension(path).ToLowerInvariant() switch
        {
            ".html" => "text/html; charset=utf-8", ".js" => "text/javascript; charset=utf-8", ".css" => "text/css; charset=utf-8",
            ".woff2" => "font/woff2", ".svg" => "image/svg+xml", ".png" => "image/png", ".json" => "application/json", _ => "application/octet-stream",
        };
        e.Response = core.Environment.CreateWebResourceResponse(stream, 200, "OK",
            $"Content-Type: {type}\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nCross-Origin-Opener-Policy: same-origin");
    }

    /// <summary>Push an event to the page (thread-safe).</summary>
    public void Post(object message)
    {
        var json = JsonSerializer.Serialize(message, Bridge.Json);
        void Send() { try { _web.CoreWebView2?.PostWebMessageAsJson(json); } catch { } }
        if (IsDisposed) return;
        if (InvokeRequired) BeginInvoke(Send); else Send();
    }

    public void SetDarkTitleBar(bool dark)
    {
        try
        {
            int on = dark ? 1 : 0;
            DwmSetWindowAttribute(Handle, 20, ref on, sizeof(int));                // immersive dark mode
            int caption = 0x000A0705;                                              // COLORREF of #05070A (BGR)
            DwmSetWindowAttribute(Handle, 35, ref caption, sizeof(int));           // caption colour (Win 11)
        }
        catch { }
    }

    [DllImport("dwmapi.dll")] private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    /// <summary>True if the Evergreen WebView2 runtime is available (it ships with Windows 11 and updated Windows 10).</summary>
    public static bool RuntimeAvailable(out string? version)
    {
        try { version = CoreWebView2Environment.GetAvailableBrowserVersionString(); return !string.IsNullOrEmpty(version); }
        catch { version = null; return false; }
    }

    public static int Run(string version, string? startPage = null)
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new AppWindow(version, startPage));
        return 0;
    }
}
