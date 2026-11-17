using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

// v0.8 "PC Doctor": stability, hardware health, performance and gamer account protection. All read-only.

[SupportedOSPlatform("windows")]
internal static class Evt
{
    public static List<EventRecord> Read(string log, string filter, TimeSpan window, int max)
    {
        var list = new List<EventRecord>();
        var ms = (long)window.TotalMilliseconds;
        try
        {
            var q = new EventLogQuery(log, PathType.LogName, $"*[System[({filter}) and TimeCreated[timediff(@SystemTime) <= {ms}]]]") { ReverseDirection = true };
            using var r = new EventLogReader(q);
            for (EventRecord? e = r.ReadEvent(); e is not null && list.Count < max; e = r.ReadEvent())
            {
                list.Add(e);
                if (Engine.CheckContext.CurrentContext.Value?.Cancellation.IsCancellationRequested == true) break;
            }
        }
        catch (EventLogNotFoundException) { }
        catch (Exception ex) { Engine.CheckContext.Note($"Event log '{log}' could not be read", ex); }
        return list;
    }

    public static string Msg(EventRecord e) { try { return e.FormatDescription() ?? ""; } catch { return ""; } }
    public static string Prop(EventRecord e, int i) { try { return e.Properties.Count > i ? e.Properties[i].Value?.ToString() ?? "" : ""; } catch { return ""; } }
}

/// <summary>Blue screens, sudden power-offs, hardware errors, GPU driver resets, app/game crashes and disk health.</summary>
[SupportedOSPlatform("windows")]
public sealed class StabilityCheck : ICheck
{
    public sealed record Bsod(string? Time, string Code, string? Name, string? Explanation);

    public string Name => "Stability & crashes";
    public string Module => "doctor";

    private static readonly Dictionary<long, (string Name, string Plain)> BugChecks = new()
    {
        [0x116] = ("VIDEO_TDR_FAILURE", "The graphics driver stopped responding. Usually a GPU driver problem, an unstable GPU overclock or overheating."),
        [0x117] = ("VIDEO_TDR_TIMEOUT_DETECTED", "The graphics card stopped responding. Usually a GPU driver problem or GPU overclock."),
        [0x133] = ("DPC_WATCHDOG_VIOLATION", "A driver took too long. Often an outdated storage (SSD) firmware/driver or chipset driver."),
        [0x1A] = ("MEMORY_MANAGEMENT", "A memory error. Often unstable RAM settings (XMP/EXPO) or faulty RAM – test with Windows Memory Diagnostic."),
        [0x50] = ("PAGE_FAULT_IN_NONPAGED_AREA", "A driver or RAM accessed invalid memory. Update drivers; test RAM if it repeats."),
        [0x124] = ("WHEA_UNCORRECTABLE_ERROR", "The hardware reported a fatal error. Usually an unstable CPU/RAM overclock, overheating or power supply."),
        [0xD1] = ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "A driver crashed – frequently a network, Wi-Fi or audio driver. Update it."),
        [0x0A] = ("IRQL_NOT_LESS_OR_EQUAL", "A driver or RAM fault. Update drivers; test RAM if it repeats."),
        [0x3B] = ("SYSTEM_SERVICE_EXCEPTION", "A driver or system component crashed. Update graphics and chipset drivers."),
        [0x7E] = ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "A driver crashed. Update or roll back recently installed drivers."),
        [0xEF] = ("CRITICAL_PROCESS_DIED", "A core Windows process stopped. Run 'sfc /scannow' and check the disk."),
        [0x9F] = ("DRIVER_POWER_STATE_FAILURE", "A driver failed during sleep/wake. Update chipset, Wi-Fi and graphics drivers."),
        [0x139] = ("KERNEL_SECURITY_CHECK_FAILURE", "A driver corrupted memory. Update drivers; test RAM if it repeats."),
        [0x1E] = ("KMODE_EXCEPTION_NOT_HANDLED", "A driver crashed. Update drivers."),
        [0xC2] = ("BAD_POOL_CALLER", "A driver misused memory. Update drivers."),
        [0x19] = ("BAD_POOL_HEADER", "Memory corruption from a driver or faulty RAM."),
        [0x7F] = ("UNEXPECTED_KERNEL_MODE_TRAP", "Often hardware (RAM/CPU overclock) or a faulty driver."),
        [0x101] = ("CLOCK_WATCHDOG_TIMEOUT", "A CPU core stopped responding. Usually an unstable CPU overclock/undervolt or BIOS issue."),
        [0x154] = ("UNEXPECTED_STORE_EXCEPTION", "A storage error. Check the SSD's health and update its firmware."),
        [0xC000021A] = ("STATUS_SYSTEM_PROCESS_TERMINATED", "A critical system process failed. Run 'sfc /scannow'."),
    };

    private static readonly (Regex Module, string Plain)[] Modules =
    {
        (new(@"^(nvwgf2um|nvd3dum|nvoglv|nvlddmkm|nvapi|nvcuda|nvgpucomp)", RegexOptions.IgnoreCase), "NVIDIA graphics driver – do a clean driver reinstall (or try the previous version)."),
        (new(@"^(atidxx|amdxx|atiu|amdvlk|atio6axx|aticfx|amdkmdag)", RegexOptions.IgnoreCase), "AMD graphics driver – do a clean driver reinstall (or try the previous version)."),
        (new(@"^(igd|ig\d|igxelpicd|igc64|intelocl)", RegexOptions.IgnoreCase), "Intel graphics driver – update it from Intel's website."),
        (new(@"^(d3d11|d3d12|dxgi|dxcore|vulkan-1)", RegexOptions.IgnoreCase), "Graphics stack (DirectX/Vulkan) – usually caused by the GPU driver or an overclock."),
        (new(@"^(EasyAntiCheat|BEClient|BEService|vgk|vgc|EAC|eac_launcher)", RegexOptions.IgnoreCase), "Anti-cheat software – repair/reinstall the anti-cheat and the game."),
        (new(@"^(xinput|dinput|hid)", RegexOptions.IgnoreCase), "Controller input – try another controller driver or unplug extra devices."),
        (new(@"^(ucrtbase|msvcp|vcruntime|msvcr)", RegexOptions.IgnoreCase), "Visual C++ runtime – reinstall the latest Microsoft Visual C++ Redistributables."),
        (new(@"^(clr|coreclr|mscorwks)", RegexOptions.IgnoreCase), ".NET runtime – repair .NET / reinstall the app."),
        (new(@"^(RTSSHooks|RTSS|MSIAfterburner|GameOverlayRenderer|DiscordHook|gameoverlay|overlay|NahimicOSD|SSOverlay)", RegexOptions.IgnoreCase), "An overlay (RivaTuner, Steam, Discord, Nahimic…) – try disabling overlays for this game."),
        (new(@"^(ntdll|KERNELBASE|kernel32)", RegexOptions.IgnoreCase), "A generic Windows module – the real cause is usually the app itself or a driver; update the app and graphics driver."),
    };

    public object? Run(CheckContext ctx)
    {
        var window = TimeSpan.FromDays(Math.Max(ctx.Options.EventLogDays, 30));
        var data = new Dictionary<string, object?>();

        // Blue screens
        var bsods = new List<Bsod>();
        foreach (var e in Evt.Read("System", "EventID=1001 and Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting']", window, 50))
            using (e)
            {
                var m = Evt.Msg(e);
                var code = Regex.Match(m, @"0x([0-9a-fA-F]{8})").Groups[1].Value;
                long.TryParse(code, System.Globalization.NumberStyles.HexNumber, null, out var bc);
                var known = BugChecks.TryGetValue(bc, out var info);
                bsods.Add(new Bsod(e.TimeCreated?.ToString("s"), $"0x{bc:X}", known ? info.Name : null, known ? info.Plain : null));
            }
        var dumps = new List<object>();
        try { foreach (var f in new DirectoryInfo(Path.Combine(Sys.SystemRoot, "Minidump")).GetFiles("*.dmp").OrderByDescending(f => f.LastWriteTime).Take(20)) dumps.Add(new { f.Name, Time = f.LastWriteTime.ToString("s"), f.Length }); } catch { }
        data["BlueScreens"] = bsods; data["Minidumps"] = dumps;
        if (bsods.Count > 0)
        {
            var groups = bsods.GroupBy(b => b.Code).OrderByDescending(g => g.Count()).ToList();
            var plain = groups[0].First().Explanation ?? "Check recently installed drivers and hardware.";
            ctx.Add(bsods.Count >= 3 ? Severity.High : Severity.Medium, "Stability", $"{(bsods.Count == 1 ? "1 blue screen" : $"{bsods.Count} blue screens")} in the last {window.Days} days",
                    string.Join("\n", groups.Take(4).Select(g => $"{g.Count()}× {g.Key} {g.First().Name ?? ""}")) + $"\nLast: {bsods[0].Time}",
                    plain, bsods, ruleId: "doctor.bsod");
        }

        // Sudden power loss / hard resets
        var kp = Evt.Read("System", "EventID=41 and Provider[@Name='Microsoft-Windows-Kernel-Power']", window, 100);
        data["UnexpectedShutdowns"] = kp.Count;
        if (kp.Count >= 2)
            ctx.Add(kp.Count >= 5 ? Severity.Medium : Severity.Low, "Stability", $"PC turned off unexpectedly {kp.Count} times in {window.Days} days",
                    "Windows didn't shut down cleanly (power loss, hard reset, freeze or crash).",
                    "If you didn't hold the power button, suspect overheating, an unstable overclock or the power supply. Check temperatures under load.", new { Count = kp.Count, Last = kp.FirstOrDefault()?.TimeCreated?.ToString("s") }, ruleId: "doctor.kernel-power");
        foreach (var e in kp) e.Dispose();

        // Hardware errors (WHEA)
        var whea = Evt.Read("System", "Provider[@Name='Microsoft-Windows-WHEA-Logger']", window, 200);
        data["HardwareErrors"] = whea.Count;
        if (whea.Count > 0)
        {
            var kinds = whea.Select(e => Regex.Match(Evt.Msg(e), @"Component:\s*(.+)").Groups[1].Value.Trim()).Where(s => s.Length > 0).GroupBy(s => s).Select(g => $"{g.Count()}× {g.Key}").ToList();
            ctx.Add(whea.Count >= 10 ? Severity.Medium : Severity.Low, "Stability", $"{whea.Count} hardware error{(whea.Count == 1 ? "" : "s")} reported by Windows",
                    kinds.Count > 0 ? string.Join("\n", kinds.Take(5)) : "WHEA-Logger events in the System log.",
                    "Corrected hardware errors are early warnings. Common causes: CPU/RAM overclock or undervolt, PCIe link issues (reseat the GPU), BIOS settings. Update the BIOS and remove overclocks to test.", new { Count = whea.Count }, ruleId: "doctor.whea");
            foreach (var e in whea) e.Dispose();
        }

        // GPU driver resets (TDR)
        var tdr = Evt.Read("System", "EventID=4101", window, 100);
        data["GpuDriverResets"] = tdr.Count;
        if (tdr.Count > 0)
            ctx.Add(tdr.Count >= 3 ? Severity.Medium : Severity.Low, "Stability", $"Graphics driver stopped responding {tdr.Count} time{(tdr.Count == 1 ? "" : "s")}",
                    "Windows reset the display driver (freezes or black screens in games).",
                    "Do a clean reinstall of the graphics driver (Display Driver Uninstaller in Safe Mode, then the latest driver). Remove GPU overclocks and check GPU temperatures.", new { Count = tdr.Count }, ruleId: "doctor.tdr");
        foreach (var e in tdr) e.Dispose();

        // App and game crashes
        var crashes = new List<(string App, string Module, DateTime? Time)>();
        foreach (var e in Evt.Read("Application", "EventID=1000 and Provider[@Name='Application Error']", TimeSpan.FromDays(30), 500))
            using (e) crashes.Add((Evt.Prop(e, 0), Evt.Prop(e, 3), e.TimeCreated));
        var byApp = crashes.Where(c => c.App.Length > 0).GroupBy(c => c.App, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count()).ToList();
        data["AppCrashes"] = byApp.Select(g => new { App = g.Key, Count = g.Count(), Modules = g.GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase).OrderByDescending(m => m.Count()).Take(3).Select(m => $"{m.Key} ({m.Count()})"), Last = g.Max(c => c.Time)?.ToString("s") }).ToList();
        foreach (var g in byApp.Where(g => g.Count() >= 3).Take(5))
        {
            var mod = g.GroupBy(c => c.Module, StringComparer.OrdinalIgnoreCase).OrderByDescending(m => m.Count()).First().Key;
            var hint = Modules.FirstOrDefault(m => m.Module.IsMatch(mod)).Plain ?? (mod.Equals(g.Key, StringComparison.OrdinalIgnoreCase) ? "The app crashes in its own code – update or reinstall it, and verify game files." : $"The crashes happen in {mod} – update or reinstall the component that provides it.");
            ctx.Add(g.Count() >= 8 ? Severity.Medium : Severity.Low, "Stability", $"{g.Key} crashed {g.Count()} times in 30 days", $"Most often in: {mod}\nLast crash: {g.Max(c => c.Time):yyyy-MM-dd HH:mm}", hint,
                    new { App = g.Key, Module = mod, Count = g.Count() }, ruleId: "doctor.app-crash");
        }

        // Disk health
        var disks = new List<object>();
        var rel = Wmi.Query("SELECT DeviceId, Wear, Temperature, TemperatureMax, ReadErrorsUncorrected, PowerOnHours FROM MSFT_StorageReliabilityCounter", @"root\Microsoft\Windows\Storage", optional: true)
                     .ToDictionary(r => r.S("DeviceId") ?? "", r => r);
        foreach (var d in Wmi.Query("SELECT DeviceId, ObjectId, FriendlyName, MediaType, HealthStatus, Size, BusType FROM MSFT_PhysicalDisk", @"root\Microsoft\Windows\Storage"))
        {
            var id = d.S("DeviceId") ?? ""; rel.TryGetValue(id, out var r);
            // The counters are often only reachable through the disk's association (what Get-StorageReliabilityCounter uses).
            if (r is null && d.S("ObjectId") is { Length: > 0 } oid)
                r = Wmi.Query($"ASSOCIATORS OF {{MSFT_PhysicalDisk.ObjectId=\"{oid.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"}} WHERE ResultClass = MSFT_StorageReliabilityCounter", @"root\Microsoft\Windows\Storage", optional: true).FirstOrDefault();
            var health = d.L("HealthStatus"); var wear = r?.L("Wear"); var temp = r?.L("Temperature"); var errs = r?.L("ReadErrorsUncorrected");
            var name = d.S("FriendlyName") ?? $"Disk {id}";
            disks.Add(new { Name = name, Health = health switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => "Unknown" }, WearPercent = wear, TemperatureC = temp, UncorrectedReadErrors = errs, PowerOnHours = r?.L("PowerOnHours"), SizeGB = d.L("Size") / 1_000_000_000 });
            if (health == 2) ctx.Add(Severity.High, "Stability", $"Disk reports it is failing: {name}", "Windows marks this drive as Unhealthy.", "Back up your files now and plan to replace the drive.", null, ruleId: "doctor.disk-unhealthy");
            else if (health == 1) ctx.Add(Severity.Medium, "Stability", $"Disk health warning: {name}", "Windows reports a health warning for this drive.", "Back up important files and check the drive with the manufacturer's tool.", null, ruleId: "doctor.disk-warning");
            if (wear >= 80) ctx.Add(Severity.Medium, "Stability", $"SSD is {wear}% worn: {name}", "The drive has used most of its rated write endurance.", "Back up regularly and plan a replacement.", null, ruleId: "doctor.ssd-wear");
            if (errs > 0) ctx.Add(Severity.Medium, "Stability", $"Disk has {errs} unreadable sector error(s): {name}", "Uncorrected read errors mean data couldn't be read.", "Back up now and run the manufacturer's diagnostics.", null, ruleId: "doctor.disk-errors");
            if (temp >= 75) ctx.Add(Severity.Low, "Stability", $"Disk is running hot ({temp} °C): {name}", "Most SSDs start slowing themselves down at around 80 °C, and heat shortens drive life.", "Improve airflow or add a heatsink to the NVMe drive.", null, ruleId: "doctor.disk-hot");
        }
        data["Disks"] = disks;
        var badBlocks = Evt.Read("System", "(EventID=7 or EventID=153) and (Provider[@Name='disk'] or Provider[@Name='stornvme'] or Provider[@Name='storahci'])", window, 100);
        if (badBlocks.Count > 0)
            ctx.Add(Severity.Medium, "Stability", $"{badBlocks.Count} disk read/retry error(s) in the event log", "Windows logged bad blocks or I/O retries.", "Back up important files and check the drive's health with the manufacturer's tool; check SATA/NVMe connections.", new { badBlocks.Count }, ruleId: "doctor.disk-events");
        foreach (var e in badBlocks) e.Dispose();

        try
        {
            var sys = new DriveInfo(Path.GetPathRoot(Sys.SystemRoot)!);
            var freePct = 100.0 * sys.AvailableFreeSpace / sys.TotalSize;
            data["SystemDriveFreePercent"] = Math.Round(freePct, 1);
            if (freePct < 10)
                ctx.Add(freePct < 5 ? Severity.Medium : Severity.Low, "Stability", $"System drive almost full ({freePct:0}% free)", $"{sys.AvailableFreeSpace / 1_000_000_000} GB free of {sys.TotalSize / 1_000_000_000} GB.",
                        "Windows and games slow down and updates fail on a full drive. Run Disk Cleanup (incl. system files) and uninstall unused games.", null, ruleId: "doctor.disk-full");
        }
        catch { }
        return data;
    }
}

/// <summary>Settings that cost performance in games, explained with honest trade-offs. Advice only.</summary>
[SupportedOSPlatform("windows")]
public sealed class PerformanceCheck : ICheck
{
    public string Name => "Gaming & performance";
    public string Module => "doctor";

    public object? Run(CheckContext ctx)
    {
        var data = new Dictionary<string, object?>();

        // RAM running below its rated speed (XMP/EXPO profile not enabled).
        var sticks = Wmi.Query("SELECT Capacity, Speed, ConfiguredClockSpeed, Manufacturer, PartNumber, SMBIOSMemoryType FROM Win32_PhysicalMemory");
        data["Memory"] = sticks.Select(s => new { GB = s.L("Capacity") / 1_073_741_824, Rated = s.L("Speed"), Running = s.L("ConfiguredClockSpeed"), Part = s.S("PartNumber")?.Trim(), Maker = s.S("Manufacturer")?.Trim() }).ToList();
        var rated = sticks.Select(s => s.L("Speed") ?? 0).DefaultIfEmpty(0).Max();
        var running = sticks.Select(s => s.L("ConfiguredClockSpeed") ?? 0).Where(v => v > 0).DefaultIfEmpty(0).Min();
        if (rated > 0 && running > 0 && running < rated * 0.9)
            ctx.Add(Severity.Low, "Performance", $"RAM runs at {running} MT/s but is rated for {rated} MT/s", "The memory's XMP/EXPO profile is probably not enabled in the BIOS, so it runs at the safe default speed.",
                    "Enable XMP (Intel) or EXPO/DOCP (AMD) in the BIOS. Typical gain: 5–15% more FPS in CPU-heavy games. If the PC becomes unstable, turn it off again.", new { Rated = rated, Running = running }, ruleId: "perf.ram-speed");
        var totalGb = sticks.Sum(s => s.L("Capacity") ?? 0) / 1_073_741_824.0;
        if (totalGb > 0 && totalGb < 15) ctx.Add(Severity.Info, "Performance", $"{totalGb:0} GB of RAM installed", "Many current games recommend 16 GB or more.", "Consider upgrading to 16–32 GB if games stutter or the PC uses the page file heavily.", null, ruleId: "perf.ram-size");
        data["TotalRamGB"] = Math.Round(totalGb, 1);

        // Power plan
        var scheme = (Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes", "ActivePowerScheme") as string)?.ToLowerInvariant();
        var plan = scheme switch { "a1841308-3541-4fab-bc81-f71556f20b4a" => "Power saver", "381b4222-f694-41f0-9685-ff5bb260df2e" => "Balanced", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" => "High performance", "e9a42b02-d5df-448d-aa00-03f14749eb61" => "Ultimate performance", null => null, _ => "Custom" };
        data["PowerPlan"] = plan;
        if (plan == "Power saver")
            ctx.Add(Severity.Low, "Performance", "Power plan is set to Power saver", "The CPU is held back to save energy, which lowers game performance.", "On a desktop or when plugged in, switch to Balanced (Settings › System › Power).", null, ruleId: "perf.power-saver");

        // Hardware-accelerated GPU scheduling and Game Mode (informational)
        data["HardwareGpuScheduling"] = Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode") is int h ? (h == 2 ? "On" : "Off") : "Default";
        var gameModeOff = Reg.LoadedUserSids().Any(sid => Reg.Value(Registry.Users, $@"{sid}\Software\Microsoft\GameBar", "AutoGameModeEnabled") is int g && g == 0);
        data["GameModeOffForSomeone"] = gameModeOff;
        if (gameModeOff) ctx.Add(Severity.Info, "Performance", "Windows Game Mode is turned off", "Game Mode gives the running game priority and pauses Windows Update installs while you play.", "Turn it on in Settings › Gaming › Game Mode.", null, ruleId: "perf.game-mode");

        // Graphics driver age
        var gpus = Wmi.Query("SELECT Name, DriverVersion, DriverDate, AdapterRAM FROM Win32_VideoController");
        data["Gpus"] = gpus.Select(g => new { Name = g.S("Name"), Driver = g.S("DriverVersion"), Date = g.Date("DriverDate")?.ToString("yyyy-MM-dd") }).ToList();
        foreach (var g in gpus)
        {
            var name = g.S("Name") ?? ""; var date = g.Date("DriverDate");
            if (date is null || Regex.IsMatch(name, "Microsoft Basic|Remote|Virtual|Parsec|Meta|DisplayLink", RegexOptions.IgnoreCase)) continue;
            var months = (int)((DateTime.Now - date.Value).TotalDays / 30);
            if (Regex.IsMatch(name, "NVIDIA|AMD|Radeon|Intel.*Arc|GeForce", RegexOptions.IgnoreCase) && months >= 6)
                ctx.Add(months >= 12 ? Severity.Low : Severity.Info, "Performance", $"Graphics driver is {months} months old: {name}", $"Driver {g.S("DriverVersion")} from {date:yyyy-MM-dd}.",
                        "New drivers fix crashes and improve performance in recent games. Update from NVIDIA/AMD/Intel's website or app.", null, ruleId: "perf.gpu-driver-age");
        }
        if (gpus.Any(g => (g.S("Name") ?? "").Contains("Microsoft Basic Display", StringComparison.OrdinalIgnoreCase)))
            ctx.Add(Severity.Medium, "Performance", "No proper graphics driver is installed", "Windows is using the 'Microsoft Basic Display Adapter'. Games will run very poorly.", "Install the driver for your graphics card from NVIDIA, AMD or Intel.", null, ruleId: "perf.basic-display");

        // Honest trade-off note for gamers with memory integrity on
        var dg = Wmi.Query("SELECT SecurityServicesRunning FROM Win32_DeviceGuard", @"root\Microsoft\Windows\DeviceGuard").FirstOrDefault();
        data["MemoryIntegrity"] = dg?.A("SecurityServicesRunning").Contains("2");
        return data;
    }
}

/// <summary>Gamer account protection: Discord client injection (the most common token stealer) and client mods.</summary>
[SupportedOSPlatform("windows")]
public sealed class GamerProtectionCheck : ICheck
{
    public string Name => "Gamer account protection";
    public string Module => "gaming";

    public object? Run(CheckContext ctx)
    {
        var rows = new List<object>();
        foreach (var u in Sys.UserProfiles())
            foreach (var flavour in new[] { "Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment" })
                foreach (var root in new[] { Path.Combine(u.Path, @"AppData\Local", flavour), Path.Combine(u.Path, @"AppData\Roaming", flavour.ToLowerInvariant()) })
                {
                    if (!Directory.Exists(root)) continue;
                    IEnumerable<string> cores;
                    try { cores = Directory.EnumerateFiles(root, "index.js", new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 6, IgnoreInaccessible = true }).Where(p => p.Contains(@"\discord_desktop_core", StringComparison.OrdinalIgnoreCase)).ToList(); }
                    catch { continue; }
                    foreach (var p in cores)
                    {
                        string text; try { text = File.ReadAllText(p); } catch { continue; }
                        var t = Regex.Replace(text, @"\s+", " ").Trim();
                        bool clean = Regex.IsMatch(t, @"^module\.exports\s*=\s*require\(\s*['""]\./core\.asar['""]\s*\);?$");
                        bool mod = Regex.IsMatch(text, @"betterdiscord|vencord|replugged|powercord|openasar", RegexOptions.IgnoreCase);
                        bool stealer = Regex.IsMatch(text, @"webhook|discord(app)?\.com/api/webhooks|token|https?://|child_process|eval\(|Buffer\.from\(|atob\(", RegexOptions.IgnoreCase) && !mod;
                        var status = clean ? "Clean" : mod ? "Client mod" : "Modified";
                        rows.Add(new { User = u.Name, Client = flavour, File = p, Status = status, Size = text.Length });
                        if (clean) continue;
                        if (mod)
                            ctx.Add(Severity.Low, "Gaming", $"Discord client mod installed ({flavour})", $"{p}\nA client mod (BetterDiscord, Vencord…) changes Discord's startup file.",
                                    "Fine if you installed it from the official site. Fake 'mods' are a common way to steal Discord accounts – only use the real project.", new { p }, "T1176", "gaming.discord-mod");
                        else
                            ctx.Add(stealer ? Severity.Critical : Severity.High, "Gaming", $"Discord has been tampered with ({flavour})",
                                    $"{p}\nDiscord's startup file contains extra code{(stealer ? " that sends data to the internet" : "")}. This is how Discord token stealers take over accounts.",
                                    "Close Discord, delete the Discord folder in %LocalAppData% and reinstall from discord.com. Then change your Discord password (this logs out all sessions), turn on two-factor authentication, and run a full scan for the malware that did this.",
                                    new { p, Preview = text.Length > 300 ? text[..300] : text }, "T1185", "gaming.discord-injection");
                    }
                }
        return new { Discord = rows };
    }
}

/// <summary>Device problems, failing drivers/services, RAM test results, throttling, file-system and update errors, reliability.</summary>
[SupportedOSPlatform("windows")]
public sealed class SystemHealthCheck : ICheck
{
    // Boot drivers Windows lists as "did not load" on almost every desktop because they only apply to other hardware
    // or configurations (Desktop Activity Moderator, UAC file virtualization with UAC off). Not a fault.
    // Logged as failing on many healthy PCs: luafv (UAC file virtualization) when virtualization is off, dam (desktop
    // activity moderator) on desktops, MapsBroker (offline maps) when no maps are downloaded.
    private static readonly HashSet<string> BenignServices = new(StringComparer.OrdinalIgnoreCase) { "dam", "luafv", "MapsBroker" };

    public string Name => "Devices & system health";
    public string Module => "doctor";

    private static readonly Dictionary<long, string> DeviceErrors = new()
    {
        [1] = "isn't configured correctly", [3] = "driver may be corrupted", [10] = "can't start", [12] = "can't find enough free resources", [14] = "needs a restart",
        [18] = "drivers need to be reinstalled", [19] = "has a corrupted registry configuration", [21] = "is being removed", [22] = "is disabled", [24] = "isn't present or not working",
        [28] = "has no driver installed", [31] = "isn't working properly (driver failed to load)", [32] = "driver service is disabled", [37] = "driver failed to initialise",
        [39] = "driver is corrupted or missing", [43] = "was stopped because it reported problems", [45] = "isn't connected", [48] = "driver was blocked (known incompatibility)", [52] = "driver isn't signed",
    };

    public object? Run(CheckContext ctx)
    {
        var data = new Dictionary<string, object?>();
        var window = TimeSpan.FromDays(Math.Max(ctx.Options.EventLogDays, 30));

        // 1. Devices with problems (yellow warning in Device Manager)
        var problems = new List<object>();
        foreach (var d in Wmi.Query("SELECT Name, PNPClass, ConfigManagerErrorCode, DeviceID, Present FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0"))
        {
            var code = d.L("ConfigManagerErrorCode") ?? 0; var name = d.S("Name") ?? d.S("DeviceID") ?? "Unknown device"; var cls = d.S("PNPClass") ?? "";
            if (code == 45 || code == 22) { problems.Add(new { Name = name, Class = cls, Code = code, Problem = DeviceErrors[code] }); continue; }   // unplugged/disabled: informational
            var what = DeviceErrors.TryGetValue(code, out var t) ? t : $"has a problem (code {code})";
            problems.Add(new { Name = name, Class = cls, Code = code, Problem = what });
            bool important = Regex.IsMatch(cls, "Display|Net|DiskDrive|SCSIAdapter|HDC|System|Processor|USB|Bluetooth|MEDIA|AudioEndpoint", RegexOptions.IgnoreCase);
            ctx.Add(important ? Severity.Medium : Severity.Low, "Stability", $"Device problem: {name} {what}", $"Device Manager code {code}. Class: {cls}\n{d.S("DeviceID")}",
                    code is 28 or 18 or 39 or 3 or 31 or 37 ? "Install or reinstall the driver from the device or PC manufacturer's website (Device Manager › right-click › Update driver)."
                    : code == 43 ? "Windows stopped this device after it reported errors. Unplug/replug it, try another port or update its driver; repeated code 43 on a GPU can mean a hardware fault."
                    : code == 52 ? "The driver isn't properly signed. Get a current driver from the manufacturer."
                    : "Open Device Manager, check the device's status and update or reinstall its driver.", new { Name = name, Code = code }, ruleId: "health.device-problem");
        }
        data["DeviceProblems"] = problems;

        // 2. Drivers/services failing to start or crashing repeatedly
        var svcFail = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        // Events name services by their display name, which is translated ("Upravitelj preuzetih karata"). Map
        // display names to service names and image paths so known-harmless and Windows-owned services are recognised
        // on every Windows language.
        var services = new Dictionary<string, (string Name, string Path)>(StringComparer.OrdinalIgnoreCase);
        foreach (var sv in Wmi.Query("SELECT Name, DisplayName, PathName FROM Win32_Service", optional: true))
        {
            var info = (sv.S("Name") ?? "", sv.S("PathName") ?? "");
            if (sv.S("DisplayName") is { Length: > 0 } dn) services.TryAdd(dn, info);
            if (info.Item1.Length > 0) services.TryAdd(info.Item1, info);
        }
        bool Benign(string n) => BenignServices.Contains(n) || (services.TryGetValue(n, out var i) && BenignServices.Contains(i.Name));
        bool WindowsOwned(string n) => services.TryGetValue(n, out var i) && Regex.IsMatch(i.Path, @"^\W?(%SystemRoot%|%windir%|[A-Z]:\\Windows)\\(System32|SysWOW64)\\", RegexOptions.IgnoreCase);
        foreach (var e in Evt.Read("System", "Provider[@Name='Service Control Manager'] and (EventID=7000 or EventID=7009 or EventID=7023 or EventID=7024 or EventID=7026 or EventID=7031 or EventID=7034)", TimeSpan.FromDays(14), 400))
            using (e)
            {
                // 7009 = "timeout (30000 ms) waiting for <service>": the service name is the second value, not the first.
                var names = e.Id == 7026 ? Regex.Split(Evt.Msg(e).Split(':').LastOrDefault() ?? "", @"\r?\n").Select(s => s.Trim()).Where(s => s.Length > 0)
                          : new[] { e.Id == 7009 ? Evt.Prop(e, 1) : Evt.Prop(e, 0) };
                foreach (var n in names.Where(n => n.Length > 0 && !Regex.IsMatch(n, @"^\d+$") && !Benign(n))) svcFail[n] = svcFail.GetValueOrDefault(n) + 1;
            }
        data["ServiceFailures"] = svcFail.OrderByDescending(k => k.Value).Take(20).ToDictionary(k => k.Key, k => k.Value);
        foreach (var (svc, n) in svcFail.Where(k => k.Value >= 3).OrderByDescending(k => k.Value).Take(5))
        {
            // Windows' own services restart themselves and rarely matter to the user; third-party ones point at a program to fix.
            bool win = WindowsOwned(svc);
            ctx.Add(win ? Severity.Low : n >= 10 ? Severity.Medium : Severity.Low, "Stability", $"Service or driver keeps failing: {svc} ({n}× in 14 days)",
                    win ? "Windows logged this built-in Windows service failing to start or stopping unexpectedly. Windows restarts it by itself, so this is usually harmless unless something stopped working."
                        : "Windows logged it failing to start or crashing.",
                    win ? "If a Windows feature misbehaves, install pending updates and run \"sfc /scannow\" in an administrator command prompt."
                        : "Update or reinstall the program/driver it belongs to. If it's left over from uninstalled software, it can usually be removed.",
                    new { Service = svc, Count = n, WindowsService = win }, ruleId: "health.service-failing");
        }

        // 3. Windows Memory Diagnostic results
        var memdiag = Evt.Read("System", "Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results']", TimeSpan.FromDays(365), 5);
        data["MemoryTests"] = memdiag.Select(e => new { Time = e.TimeCreated?.ToString("s"), Result = e.Id == 1102 ? "Errors found" : e.Id == 1101 ? "No errors" : $"Event {e.Id}" }).ToList();
        if (memdiag.FirstOrDefault(e => e.Id == 1102) is { } bad)
            ctx.Add(Severity.High, "Stability", "Windows Memory Diagnostic found RAM errors", $"Test on {bad.TimeCreated:yyyy-MM-dd} reported hardware memory errors.",
                    "Disable XMP/EXPO and test again; if errors remain, test each RAM stick alone to find the faulty one and replace it.", null, ruleId: "health.ram-errors");
        foreach (var e in memdiag) e.Dispose();

        // 4. CPU speed limited by firmware (heat / power)
        var throttle = Evt.Read("System", "Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37", TimeSpan.FromDays(14), 500);
        data["CpuThrottleEvents"] = throttle.Count;
        if (throttle.Count >= 3)
            ctx.Add(throttle.Count >= 30 ? Severity.Medium : Severity.Low, "Stability", $"CPU speed was limited by the firmware {throttle.Count} times in 14 days",
                    "The processor was slowed down, usually because of heat or power limits – a common cause of FPS drops after a few minutes of gaming.",
                    "Clean dust from fans and heatsinks, check the CPU cooler is seated properly, and on laptops use a hard surface or cooling pad. Remove aggressive overclocks.", new { throttle.Count }, ruleId: "health.cpu-throttle");
        foreach (var e in throttle) e.Dispose();

        // 5. File system corruption and storage resets
        var ntfs = Evt.Read("System", "(Provider[@Name='Ntfs'] or Provider[@Name='Microsoft-Windows-Ntfs']) and (EventID=55 or EventID=98 or EventID=137 or EventID=140)", window, 50);
        data["FileSystemErrors"] = ntfs.Count;
        if (ntfs.Count > 0)
            ctx.Add(Severity.Medium, "Stability", $"File system errors detected ({ntfs.Count})", "Windows found corruption on a drive's file system.",
                    "Back up important files, then run 'chkdsk C: /scan' (or for the affected drive) from an administrator terminal and check the drive's health.", new { ntfs.Count }, ruleId: "health.ntfs");
        foreach (var e in ntfs) e.Dispose();
        var resets = Evt.Read("System", "EventID=129 and (Provider[@Name='storahci'] or Provider[@Name='stornvme'] or Provider[@Name='iaStorAC'] or Provider[@Name='iaStorA'] or Provider[@Name='storport'])", window, 100);
        data["StorageResets"] = resets.Count;
        if (resets.Count > 0)
            ctx.Add(resets.Count >= 5 ? Severity.Medium : Severity.Low, "Stability", $"Storage controller was reset {resets.Count} time(s)", "A drive stopped responding and Windows had to reset it (this causes freezes).",
                    "Update SSD firmware and chipset/storage drivers; reseat or replace the SATA cable; check the drive's health.", new { resets.Count }, ruleId: "health.storage-reset");
        foreach (var e in resets) e.Dispose();

        // 6. Low memory and which app was using the most
        var lowMem = Evt.Read("System", "Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004", window, 50);
        if (lowMem.Count > 0)
        {
            var hog = Regex.Match(Evt.Msg(lowMem[0]), @"programs.*?:\s*([^\(\r\n]+)\(", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value.Trim();
            data["LowMemoryWarnings"] = lowMem.Count;
            ctx.Add(lowMem.Count >= 3 ? Severity.Medium : Severity.Low, "Stability", $"Windows ran low on memory {lowMem.Count} time(s)", hog.Length > 0 ? $"Biggest user last time: {hog}" : "Resource-Exhaustion-Detector warnings in the System log.",
                    "Close memory-hungry apps (often browsers with many tabs) while gaming, check for memory leaks in the named app, or add more RAM.", new { lowMem.Count, Top = hog }, ruleId: "health.low-memory");
            foreach (var e in lowMem) e.Dispose();
        }

        // 7. Apps that freeze (not responding)
        var hangs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in Evt.Read("Application", "Provider[@Name='Application Hang'] and EventID=1002", TimeSpan.FromDays(30), 300))
            using (e) { var app = Evt.Prop(e, 0); if (app.Length > 0) hangs[app] = hangs.GetValueOrDefault(app) + 1; }
        data["AppHangs"] = hangs;
        foreach (var (app, n) in hangs.Where(k => k.Value >= 3).OrderByDescending(k => k.Value).Take(3))
            ctx.Add(Severity.Low, "Stability", $"{app} froze {n} times in 30 days", "Windows recorded it as 'not responding'.", "Update the app; if it's a game, verify its files and update the graphics driver.", new { App = app, Count = n }, ruleId: "health.app-hang");

        // 8. Windows Update failures
        var wu = Evt.Read("System", "Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and EventID=20", TimeSpan.FromDays(30), 100);
        data["UpdateFailures"] = wu.Count;
        if (wu.Count >= 3)
        {
            var titles = wu.Select(e => Evt.Prop(e, 1)).Where(s => s.Length > 0).Distinct().Take(3).ToList();
            ctx.Add(Severity.Low, "Stability", $"Windows Update failed {wu.Count} times in 30 days", string.Join("\n", titles),
                    "Run the Windows Update troubleshooter (Settings › System › Troubleshoot) and make sure there is enough free disk space. Failing updates leave security holes open.", new { wu.Count }, ruleId: "health.update-failures");
        }
        foreach (var e in wu) e.Dispose();

        // 9. Windows reliability index (Reliability Monitor, 1–10)
        var rel = Wmi.Query("SELECT SystemStabilityIndex, TimeGenerated FROM Win32_ReliabilityStabilityMetrics").OrderByDescending(r => r.S("TimeGenerated")).FirstOrDefault();
        if (rel?.S("SystemStabilityIndex") is string idx && double.TryParse(idx, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var score))
        {
            data["ReliabilityIndex"] = Math.Round(score, 1);
            if (score < 5)
                ctx.Add(score < 3 ? Severity.Medium : Severity.Low, "Stability", $"Windows reliability score is {score:0.0} out of 10", "Windows' own Reliability Monitor rates recent stability as poor.",
                        "Open Reliability Monitor (search 'reliability') to see the day-by-day crashes; the stability findings above show the likely causes.", null, ruleId: "health.reliability");
        }
        return data;
    }
}
