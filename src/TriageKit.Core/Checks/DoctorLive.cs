using System.Diagnostics;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

/// <summary>
/// Limits shared by the PC Doctor findings and the PC Doctor page, so a value the page shows in amber is a value
/// that also produced a finding. The UI receives these with the measurements.
/// </summary>
public static class DoctorLimits
{
    public const double DriverLatencyLow = 5, DriverLatencyMedium = 10;        // % of CPU time, DPC + interrupts
    // One core (usually core 0) takes most hardware interrupts; 20-30% there is common on healthy desktops.
    public const double CoreLatencyLow = 40, CoreLatencyMedium = 70;           // % on one core, 90th percentile
    public const double DiskAvgLowMs = 30, DiskAvgMediumMs = 100;
    public const double DiskSlowSampleMs = 500, DiskVerySlowSampleMs = 2000;   // need SustainedSamples samples over this
    public const int SustainedSamples = 3;
    public const double PageReadsLow = 300, PageReadsMedium = 1000;            // per second
    public const double CommittedPercent = 90, AvailablePercent = 8;
    public const double CpuHogLow = 15, CpuHogMedium = 40;                     // % of the whole CPU
    public const double RailTolerance = 0.05, RailImplausible = 0.10;          // ATX: +/-5%; beyond 10% the sensor is wrong
    public static object ForUi => new
    {
        DriverLatency = DriverLatencyLow, CoreLatency = CoreLatencyLow, DiskAvgMs = DiskAvgLowMs, PageReads = PageReadsLow,
        RailTolerance, CpuHog = CpuHogLow,
    };
}

/// <summary>
/// PC Doctor live measurements. Watches the PC for about 20 seconds: driver latency (DPC/interrupt time, the most
/// common cause of micro-stutter), background CPU hogs, delays on the Windows disk and real memory shortage. Uses PDH
/// with English counter names, so it works on any Windows language.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class LivePerformanceCheck : ICheck
{
    public string Name => "Live performance (20 s)";
    public string Module => "doctor";
    public int Order => 90;          // after the other checks, so TriageKit's own work doesn't skew the numbers
    public bool IsSlow => true;
    public static TimeSpan Duration = TimeSpan.FromSeconds(20);

    public object? Run(CheckContext ctx)
    {
        using var pdh = new Pdh();
        var total = pdh.Add(@"\Processor(_Total)\% Processor Time");
        var dpc = pdh.Add(@"\Processor(_Total)\% DPC Time");
        var isr = pdh.Add(@"\Processor(_Total)\% Interrupt Time");
        var dpcCores = pdh.Add(@"\Processor(*)\% DPC Time");
        var isrCores = pdh.Add(@"\Processor(*)\% Interrupt Time");
        var faults = pdh.Add(@"\Memory\Pages Input/sec");
        var avail = pdh.Add(@"\Memory\Available MBytes");
        var committed = pdh.Add(@"\Memory\% Committed Bytes In Use");
        var diskLat = pdh.Add(@"\PhysicalDisk(*)\Avg. Disk sec/Transfer");
        if (!pdh.Ok || total == IntPtr.Zero || dpc == IntPtr.Zero || isr == IntPtr.Zero)
        {
            CheckContext.Note("Windows performance counters are unavailable (they may need repairing with \"lodctr /R\")");
            return new { Ran = false, Reason = "Windows performance counters are unavailable", Limits = DoctorLimits.ForUi };
        }

        var systemDisk = (Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\").TrimEnd('\\');   // "C:"
        var cpuStart = ProcessTimes();
        var started = Stopwatch.StartNew();
        var s = new Samples();
        string? diskName = null;
        pdh.Collect();
        while (started.Elapsed < Duration && !ctx.Cancellation.IsCancellationRequested)
        {
            Thread.Sleep(500);
            pdh.Collect();
            s.Cpu.Add(pdh.Value(total)); s.Dpc.Add(pdh.Value(dpc)); s.Isr.Add(pdh.Value(isr));
            s.CoreDpcMax.Add(Max(pdh.Array(dpcCores))); s.CoreIsrMax.Add(Max(pdh.Array(isrCores)));
            s.Faults.Add(pdh.Value(faults)); s.Avail.Add(pdh.Value(avail)); s.Committed.Add(pdh.Value(committed));
            // Only the disk Windows runs from: USB sticks (where the portable edition lives) and sleeping data
            // drives spinning up would otherwise be reported as "slow disk".
            var disk = pdh.Array(diskLat).FirstOrDefault(kv => DiskHolds(kv.Key, systemDisk));
            if (disk.Key is not null) { diskName = disk.Key; s.DiskMs.Add(disk.Value * 1000); }
        }
        var seconds = started.Elapsed.TotalSeconds;
        if (s.Dpc.ValidCount() == 0 && s.Cpu.ValidCount() == 0)
        {
            CheckContext.Note("Windows performance counters returned no values (they may need repairing with \"lodctr /R\")");
            return new { Ran = false, Reason = "Windows performance counters returned no values", Limits = DoctorLimits.ForUi };
        }
        var hogs = TopCpu(ctx, cpuStart, seconds);

        double avgLatency = s.Dpc.AvgOrZero() + s.Isr.AvgOrZero();
        // 90th percentile, not the maximum: a single burst from a mouse or network driver is normal.
        double worstCore = Math.Max(s.CoreDpcMax.PercentileOrZero(90), s.CoreIsrMax.PercentileOrZero(90));
        if (avgLatency >= DoctorLimits.DriverLatencyLow || worstCore >= DoctorLimits.CoreLatencyLow)
            ctx.Add(avgLatency >= DoctorLimits.DriverLatencyMedium || worstCore >= DoctorLimits.CoreLatencyMedium ? Severity.Medium : Severity.Low, "Performance",
                "Drivers keep the CPU busy (a common cause of micro-stutter)",
                $"For {seconds:0} seconds, {s.Dpc.AvgOrZero():0.0}% of CPU time went to deferred driver work (DPC) and {s.Isr.AvgOrZero():0.0}% to hardware interrupts; the busiest core spent {worstCore:0}% on them most of the time. On a healthy PC the total stays under about 1 to 2%. High values cause micro-stutter, audio crackling and input lag.",
                "Usual suspects: network/Wi-Fi drivers, GPU driver, audio drivers, RGB/peripheral software and storage drivers. Update chipset, network and GPU drivers first. LatencyMon (free) shows exactly which driver is responsible.",
                new { DpcPercent = s.Dpc.AvgOrZero(), InterruptPercent = s.Isr.AvgOrZero(), WorstCorePercent = worstCore }, ruleId: "perf.dpc-latency");

        // Memory shortage: page reads alone also count normal file reads, and little free memory is normal on an
        // 8 GB PC. Both have to point the same way: lots of reads AND memory really used up.
        var faultAvg = s.Faults.AvgOrZero(); var availMin = s.Avail.MinOrZero(); var commitMax = s.Committed.MaxOrZero();
        var totalMb = TotalMemoryMb();
        bool memoryFull = commitMax >= DoctorLimits.CommittedPercent || (totalMb > 0 && availMin < totalMb * DoctorLimits.AvailablePercent / 100);
        if (faultAvg >= DoctorLimits.PageReadsLow && memoryFull)
            ctx.Add(faultAvg >= DoctorLimits.PageReadsMedium ? Severity.Medium : Severity.Low, "Performance", "The PC is running short of memory",
                $"While being watched, Windows read {faultAvg:0} memory pages per second back from disk, with {availMin:0} MB of {totalMb:0} MB free and {commitMax:0}% of committed memory in use. That causes hitches and stutter, especially in games.",
                "Close browser tabs and background apps while gaming, or add RAM. Task Manager > Processes, sorted by Memory, shows what uses the most.",
                new { AvailableMB = availMin, TotalMB = totalMb, CommittedPercent = commitMax, PageReadsPerSec = faultAvg }, ruleId: "perf.memory-pressure");

        var diskAvg = s.DiskMs.AvgOrZero(); var diskPeak = s.DiskMs.MaxOrZero();
        int slow = s.DiskMs.Count(v => v >= DoctorLimits.DiskSlowSampleMs), verySlow = s.DiskMs.Count(v => v >= DoctorLimits.DiskVerySlowSampleMs);
        if (diskAvg >= DoctorLimits.DiskAvgLowMs || slow >= DoctorLimits.SustainedSamples)
            ctx.Add(diskAvg >= DoctorLimits.DiskAvgMediumMs || verySlow >= DoctorLimits.SustainedSamples ? Severity.Medium : Severity.Low, "Performance", $"The Windows disk ({systemDisk}) responds slowly",
                $"Average answer time {diskAvg:0} ms, worst {diskPeak:0} ms, {slow} of {s.DiskMs.Count} samples over {DoctorLimits.DiskSlowSampleMs:0} ms (disk {diskName}). A healthy SSD answers in under about 5 ms. Slow answers freeze games while they load data and make Windows feel sluggish.",
                "Check that the drive isn't almost full and that no big copy, update or antivirus scan was running, and look at the drive's health above. Hard disks are much slower than SSDs for Windows and games.",
                new { Disk = diskName, AvgMs = diskAvg, PeakMs = diskPeak, SlowSamples = slow }, ruleId: "perf.disk-latency");

        foreach (var h in hogs.Where(h => h.Percent >= DoctorLimits.CpuHogLow && !h.Foreground).Take(3))
        {
            var kind = h.Path is null ? "signature not readable" : h.Microsoft ? "a Windows component" : h.Signed ? $"signed by {h.Signer}" : "unsigned";
            var advice = h.Microsoft
                ? "Windows components such as updates, indexing and Defender scans use a lot of CPU for a while and then settle. If it stays high for hours, restart the PC and check Windows Update."
                : h.Signed
                    ? "If you don't need it running, close it or remove it from startup (Task Manager > Startup apps)."
                    : h.UserFolder && h.Path is not null
                        ? "It's unsigned and runs from a user folder. If you don't recognise it, run a full TriageKit security check: hidden crypto miners look exactly like this."
                        : "If you don't need it running, close it or remove it from startup (Task Manager > Startup apps).";
            ctx.Add(h.Percent >= DoctorLimits.CpuHogMedium && !h.Microsoft ? Severity.Medium : Severity.Low, "Performance", $"{h.Name} uses a lot of CPU in the background",
                $"{h.Path ?? h.Name} ({kind}) used {h.Percent:0}% of the whole CPU on average while TriageKit watched for {seconds:0} seconds.",
                advice, new { h.Name, h.Path, h.Percent, h.Signer }, ruleId: "perf.cpu-hog");
        }

        return new
        {
            Ran = true,
            Seconds = Math.Round(seconds, 1),
            CpuPercent = new { Avg = s.Cpu.AvgOrZero(), Max = s.Cpu.MaxOrZero() },
            DpcPercent = new { Avg = s.Dpc.AvgOrZero(), Max = s.Dpc.MaxOrZero(), WorstCore = s.CoreDpcMax.PercentileOrZero(90) },
            InterruptPercent = new { Avg = s.Isr.AvgOrZero(), Max = s.Isr.MaxOrZero(), WorstCore = s.CoreIsrMax.PercentileOrZero(90) },
            PageReadsPerSec = new { Avg = faultAvg, Max = s.Faults.MaxOrZero() },
            AvailableMB = new { Min = availMin, Total = totalMb },
            CommittedPercent = new { Max = commitMax },
            DiskMs = new { Disk = diskName, Avg = diskAvg, Max = diskPeak },
            TopCpu = hogs.Take(8).ToList(),
            Limits = DoctorLimits.ForUi,
        };
    }

    /// <summary>PhysicalDisk instance names look like "0 C:" or "1 D: E:".</summary>
    internal static bool DiskHolds(string instance, string drive) =>
        instance != "_Total" && instance.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).Any(p => p.Equals(drive, StringComparison.OrdinalIgnoreCase));

    private static double Max(Dictionary<string, double> d) { var v = d.Where(kv => kv.Key != "_Total").Select(kv => kv.Value).ToList(); return v.Count == 0 ? double.NaN : v.Max(); }

    private sealed class Samples
    {
        public List<double> Cpu = new(), Dpc = new(), Isr = new(), CoreDpcMax = new(), CoreIsrMax = new(), Faults = new(), Avail = new(), Committed = new(), DiskMs = new();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX { public uint dwLength, dwMemoryLoad; public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);
    private static double TotalMemoryMb()
    {
        var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref m) ? Math.Round(m.ullTotalPhys / 1048576.0) : 0;
    }

    // Process paths through QueryFullProcessImageName with limited rights: no memory-read handle on every process
    // (Process.MainModule would open lsass and others for reading, which is slow and alarms some security products).
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder name, ref uint size);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int pid);

    internal static string? ImagePath(int pid)
    {
        var h = OpenProcess(0x1000, false, pid);   // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) return null;
        try { var sb = new StringBuilder(1024); uint n = (uint)sb.Capacity; return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString() : null; }
        finally { CloseHandle(h); }
    }

    private static Dictionary<int, (string Name, TimeSpan Cpu)> ProcessTimes()
    {
        var d = new Dictionary<int, (string, TimeSpan)>();
        foreach (var p in Process.GetProcesses())
            using (p)
            {
                try { d[p.Id] = (p.ProcessName, p.TotalProcessorTime); } catch { }
            }
        return d;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W { public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID; public int pcPriClassBase; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32W e);

    /// <summary>All processes started (directly or indirectly) by <paramref name="root"/>, from a process snapshot (no handles opened).</summary>
    internal static HashSet<int> Descendants(int root)
    {
        var parent = new Dictionary<int, int>();
        var snap = CreateToolhelp32Snapshot(0x2 /* TH32CS_SNAPPROCESS */, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return new();
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            for (bool ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e)) parent[(int)e.th32ProcessID] = (int)e.th32ParentProcessID;
        }
        finally { CloseHandle(snap); }
        var result = new HashSet<int>();
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var (pid, ppid) in parent)
                if ((ppid == root || result.Contains(ppid)) && pid != root && result.Add(pid)) changed = true;
        }
        return result;
    }

    public sealed record CpuHog(string Name, string? Path, double Percent, bool Signed, bool Microsoft, string? Signer, bool UserFolder, bool Foreground);

    private static List<CpuHog> TopCpu(CheckContext ctx, Dictionary<int, (string Name, TimeSpan Cpu)> before, double seconds)
    {
        var after = ProcessTimes();
        int self = Environment.ProcessId;
        int fg = 0; try { GetWindowThreadProcessId(GetForegroundWindow(), out fg); } catch { }
        var cores = Environment.ProcessorCount;
        var mine = Descendants(self);   // TriageKit's own window (WebView2) processes
        var top = after.Where(kv => kv.Key != self && !mine.Contains(kv.Key) && kv.Key > 4 && before.ContainsKey(kv.Key))
            .Select(kv => (Pid: kv.Key, kv.Value.Name, Percent: Math.Round((kv.Value.Cpu - before[kv.Key].Cpu).TotalSeconds / seconds / cores * 100, 1)))
            .Where(h => h.Percent > 0.5 && !Regex.IsMatch(h.Name, @"^(Idle|System|Registry|MemCompression|dwm|audiodg|csrss|Secure System)$", RegexOptions.IgnoreCase))
            .OrderByDescending(h => h.Percent).Take(8).ToList();
        var users = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return top.Select(h =>
        {
            var path = ImagePath(h.Pid);
            var fi = path is null ? null : ctx.Files.Get(path, hash: false);
            bool userFolder = path is not null && (path.StartsWith(users, StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Users\Public\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase));
            return new CpuHog(h.Name, path, h.Percent, fi?.IsSigned ?? false, fi?.IsMicrosoft ?? false, fi?.Signer, userFolder, h.Pid == fg);
        }).ToList();
    }

    /// <summary>Minimal PDH wrapper using English counter paths (language independent).</summary>
    private sealed class Pdh : IDisposable
    {
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhOpenQueryW(string? source, IntPtr user, out IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhAddEnglishCounterW(IntPtr query, string path, IntPtr user, out IntPtr counter);
        [DllImport("pdh.dll")] private static extern uint PdhCollectQueryData(IntPtr query);
        [DllImport("pdh.dll")] private static extern uint PdhCloseQuery(IntPtr query);
        [DllImport("pdh.dll")] private static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, IntPtr type, out FmtValue value);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint format, ref uint bufferSize, out uint count, IntPtr buffer);
        private const uint PDH_FMT_DOUBLE = 0x200, PDH_FMT_NOCAP100 = 0x8000;
        private static bool Good(uint status) => status is 0 or 1;   // PDH_CSTATUS_VALID_DATA, PDH_CSTATUS_NEW_DATA

        [StructLayout(LayoutKind.Explicit)] private struct FmtValue { [FieldOffset(0)] public uint Status; [FieldOffset(8)] public double Double; }

        private readonly IntPtr _q;
        public bool Ok { get; private set; }
        public Pdh() { Ok = PdhOpenQueryW(null, IntPtr.Zero, out _q) == 0; }
        public IntPtr Add(string path) { if (!Ok) return IntPtr.Zero; return PdhAddEnglishCounterW(_q, path, IntPtr.Zero, out var c) == 0 ? c : IntPtr.Zero; }
        public void Collect() { if (Ok) PdhCollectQueryData(_q); }
        public double Value(IntPtr c)
        {
            if (c == IntPtr.Zero) return double.NaN;
            return PdhGetFormattedCounterValue(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, IntPtr.Zero, out var v) == 0 && Good(v.Status) ? v.Double : double.NaN;
        }
        public Dictionary<string, double> Array(IntPtr c)
        {
            var d = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            if (c == IntPtr.Zero) return d;
            uint size = 0;
            PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ref size, out _, IntPtr.Zero);
            if (size == 0) return d;
            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (PdhGetFormattedCounterArrayW(c, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ref size, out var n, buf) != 0) return d;
                int item = IntPtr.Size + 16;   // PDH_FMT_COUNTERVALUE_ITEM_W: name pointer + value (status + padding + double)
                for (int i = 0; i < n; i++)
                {
                    var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, i * item)) ?? "";
                    var status = (uint)Marshal.ReadInt32(buf, i * item + IntPtr.Size);
                    var val = BitConverter.Int64BitsToDouble(Marshal.ReadInt64(buf, i * item + IntPtr.Size + 8));
                    if (Good(status)) d[name] = val;
                }
                return d;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        public void Dispose() { if (Ok) PdhCloseQuery(_q); }
    }
}

internal static class SampleStats
{
    private static List<double> Valid(this IEnumerable<double> v) => v.Where(x => !double.IsNaN(x) && !double.IsInfinity(x)).ToList();
    public static int ValidCount(this IEnumerable<double> v) => v.Valid().Count;
    public static double AvgOrZero(this IEnumerable<double> v) { var l = v.Valid(); return l.Count == 0 ? 0 : Math.Round(l.Average(), 2); }
    public static double MaxOrZero(this IEnumerable<double> v) { var l = v.Valid(); return l.Count == 0 ? 0 : Math.Round(l.Max(), 2); }
    public static double MinOrZero(this IEnumerable<double> v) { var l = v.Valid(); return l.Count == 0 ? 0 : Math.Round(l.Min(), 2); }
    public static double PercentileOrZero(this IEnumerable<double> v, double p)
    {
        var l = v.Valid(); if (l.Count == 0) return 0;
        l.Sort();
        var rank = (int)Math.Ceiling(p / 100 * l.Count) - 1;
        return Math.Round(l[Math.Clamp(rank, 0, l.Count - 1)], 2);
    }
}

/// <summary>What kind of PC and CPU this is; limits for voltage and temperature depend on it.</summary>
public sealed record PcProfile(string CpuName, string Vendor, bool Laptop, bool Virtual)
{
    public bool Amd => Vendor == "AMD";
    public bool Intel => Vendor == "Intel";
    /// <summary>Ryzen 7000/8000/9000 desktop parts (AM5, Zen 4/5).</summary>
    public bool Am5 => Amd && !Laptop && Regex.IsMatch(CpuName, @"Ryzen\s+\d\s+(PRO\s+)?[789]\d{3}(X3D|X|G|F|E)?\b", RegexOptions.IgnoreCase);
    public bool X3D => Amd && CpuName.Contains("X3D", StringComparison.OrdinalIgnoreCase);

    /// <summary>Mobile part (H/HS/HX/U), also when it sits in a mini PC rather than a laptop.</summary>
    public bool MobileCpu => Laptop || Regex.IsMatch(CpuName, @"\d{4,5}(HS|HX|H|U|P)\b", RegexOptions.IgnoreCase);

    /// <summary>Temperature where the CPU starts limiting itself (TjMax / Tctl limit). When unsure, the higher value:
    /// a missed warning costs less than telling people a healthy CPU overheats.</summary>
    public double CpuTempLimit => X3D ? 89 : Am5 ? 95 : MobileCpu ? 100 : Amd ? 95 : 100;

    /// <summary>Highest core voltage that is still normal for a short boost on stock settings (board sensors read a
    /// little high, so AM5 gets 1.50 V although the CPU itself stays lower).</summary>
    public double CoreVoltageLimit => Am5 ? 1.50 : 1.55;

    public static PcProfile Detect()
    {
        var cpu = Wmi.Query("SELECT Name, Manufacturer FROM Win32_Processor", optional: true).FirstOrDefault();
        var cs = Wmi.Query("SELECT Manufacturer, Model, PCSystemType FROM Win32_ComputerSystem", optional: true).FirstOrDefault();
        var name = (cpu?.S("Name") ?? "").Trim();
        var mfr = cpu?.S("Manufacturer") ?? "";
        var vendor = mfr.Contains("AMD", StringComparison.OrdinalIgnoreCase) || name.Contains("AMD", StringComparison.OrdinalIgnoreCase) ? "AMD"
                   : mfr.Contains("Intel", StringComparison.OrdinalIgnoreCase) || name.Contains("Intel", StringComparison.OrdinalIgnoreCase) ? "Intel" : "Other";
        var model = $"{cs?.S("Manufacturer")} {cs?.S("Model")}";
        bool vm = Regex.IsMatch(model, @"Virtual|VMware|VirtualBox|QEMU|KVM|Hyper-V|Parallels|Xen", RegexOptions.IgnoreCase);
        var type = cs?.L("PCSystemType");
        return new PcProfile(name, vendor, type is 2, vm);
    }
}

/// <summary>
/// Hardware details that cause stutter or lost performance without anything being "broken": a monitor running below
/// its refresh rate, single-channel or mixed RAM, an NVIDIA card running hot, power-limited or on fewer PCIe lanes.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class HardwareSetupCheck : ICheck
{
    public string Name => "Monitors, RAM & graphics card";
    public string Module => "doctor";

    public object? Run(CheckContext ctx)
    {
        var pc = PcProfile.Detect();
        // Each part on its own: a failure in one (say, the NVIDIA tool) must not lose the others.
        object? Part(string what, Func<object?> f)
        {
            try { return f(); }
            catch (Exception ex) { CheckContext.Minor($"{what} couldn't be read", ex); return null; }
        }
        return new
        {
            Pc = pc,
            Displays = Part("Monitor settings", () => Displays(ctx)),
            Memory = Part("Memory layout", () => Memory(ctx, pc)),
            NvidiaGpus = Part("NVIDIA graphics card", () => Nvidia(ctx, pc)),
            // AMD, Intel and any other card: PCIe link from Windows' own device information (needs no vendor tool).
            // Temperatures and hot spots for every maker come from the sensor tool (SensorsCheck).
            GpuLinks = Part("Graphics card PCIe link", () => GpuLinks(ctx, pc)),
        };
    }

    // ---------------------------------------------------------------- PCIe link of every graphics card (cfgmgr32)
    [StructLayout(LayoutKind.Sequential)] private struct DEVPROPKEY { public Guid fmtid; public uint pid; }
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern int CM_Locate_DevNodeW(out uint devInst, string deviceId, int flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern int CM_Get_DevNode_PropertyW(uint devInst, ref DEVPROPKEY key, out uint type, byte[] buffer, ref uint size, int flags);
    // DEVPKEY_PciDevice_* (pciprop.h): CurrentLinkSpeed 9, CurrentLinkWidth 10, MaxLinkSpeed 11, MaxLinkWidth 12.
    private static readonly Guid PciProps = new("3ab22e31-8264-4b4e-9af5-a8d2d8e33e62");

    private static uint? PciU32(uint inst, uint pid)
    {
        var key = new DEVPROPKEY { fmtid = PciProps, pid = pid };
        var buf = new byte[4]; uint size = 4;
        return CM_Get_DevNode_PropertyW(inst, ref key, out var type, buf, ref size, 0) == 0 && type == 0x7 /* DEVPROP_TYPE_UINT32 */ && size == 4 ? BitConverter.ToUInt32(buf, 0) : null;
    }

    private static List<object> GpuLinks(CheckContext ctx, PcProfile pc)
    {
        var list = new List<object>();
        if (pc.Virtual) return list;
        foreach (var v in Wmi.Query("SELECT Name, PNPDeviceID FROM Win32_VideoController", optional: true))
        {
            var name = v.S("Name") ?? "Graphics card"; var id = v.S("PNPDeviceID");
            if (id is null || !id.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase) || name.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase)) continue;   // NVIDIA: nvidia-smi is more exact
            if (CM_Locate_DevNodeW(out var inst, id, 0) != 0) continue;
            uint? w = PciU32(inst, 10), wm = PciU32(inst, 12), gen = PciU32(inst, 9), genMax = PciU32(inst, 11);
            list.Add(new { Name = name, Width = w, MaxWidth = wm, Gen = gen, MaxGen = genMax });
            // Only real link widths count; anything else means the property isn't what we expect on this system.
            static bool Valid(uint? x) => x is 1 or 2 or 4 or 8 or 16 or 32;
            // Integrated graphics sit inside the CPU and report no external link.
            if (Valid(w) && Valid(wm)) JudgePcieWidth(ctx, name, w!.Value, wm!.Value, pc);
        }
        return list;
    }

    // ---------------------------------------------------------------- monitors
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DISPLAY_DEVICE { public int cb; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString; public int StateFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DEVMODE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public short dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra; public int dmFields;
        public int dmPositionX, dmPositionY, dmDisplayOrientation, dmDisplayFixedOutput;
        public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public short dmLogPixels; public int dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency;
        public int dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2, dmPanningWidth, dmPanningHeight;
    }

    [StructLayout(LayoutKind.Sequential)] private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }

    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool EnumDisplayDevicesW(string? device, int index, ref DISPLAY_DEVICE dd, int flags);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool EnumDisplaySettingsW(string device, int mode, ref DEVMODE dm);
    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
    private const int DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 1, DISPLAY_DEVICE_PRIMARY_DEVICE = 4, DM_INTERLACED = 2;

    private static List<object>? Displays(CheckContext ctx)
    {
        // The service runs in session 0, which has no monitors: say nothing rather than a different answer each time.
        if (Process.GetCurrentProcess().SessionId == 0) return null;
        bool onBattery = GetSystemPowerStatus(out var ps) && ps.ACLineStatus == 0;
        var names = MonitorNames();
        var list = new List<object>();
        var dd = new DISPLAY_DEVICE { cb = Marshal.SizeOf<DISPLAY_DEVICE>() };
        int number = 0;
        for (int i = 0; EnumDisplayDevicesW(null, i, ref dd, 0); i++, dd.cb = Marshal.SizeOf<DISPLAY_DEVICE>())
        {
            if ((dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0) continue;
            number++;
            bool primary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) != 0;
            var cur = new DEVMODE { dmSize = (short)Marshal.SizeOf<DEVMODE>() };
            if (!EnumDisplaySettingsW(dd.DeviceName, -1, ref cur)) continue;   // ENUM_CURRENT_SETTINGS
            int best = cur.dmDisplayFrequency;
            var m = new DEVMODE { dmSize = (short)Marshal.SizeOf<DEVMODE>() };
            for (int k = 0; EnumDisplaySettingsW(dd.DeviceName, k, ref m); k++)
                if (m.dmPelsWidth == cur.dmPelsWidth && m.dmPelsHeight == cur.dmPelsHeight && (m.dmDisplayFlags & DM_INTERLACED) == 0 && m.dmDisplayFrequency > best) best = m.dmDisplayFrequency;
            var monitor = new DISPLAY_DEVICE { cb = Marshal.SizeOf<DISPLAY_DEVICE>() };
            var hasMonitor = EnumDisplayDevicesW(dd.DeviceName, 0, ref monitor, 0);
            var monName = MonitorName(hasMonitor ? monitor.DeviceID : null, hasMonitor ? monitor.DeviceString : null, names, number);
            list.Add(new { Monitor = monName, Adapter = dd.DeviceString, Primary = primary, Resolution = $"{cur.dmPelsWidth}x{cur.dmPelsHeight}", RefreshHz = cur.dmDisplayFrequency, MaxRefreshHz = best });
            if (cur.dmDisplayFrequency > 1 && best >= cur.dmDisplayFrequency + 15)
            {
                // Laptops drop to 60 Hz on battery by design, and a second screen is often kept at 60 Hz on purpose.
                bool important = primary && !onBattery && best >= 100 && cur.dmDisplayFrequency <= 75;
                ctx.Add(important ? Severity.Medium : Severity.Low, "Performance",
                    $"{monName} runs at {cur.dmDisplayFrequency} Hz but supports {best} Hz",
                    $"At {cur.dmPelsWidth}x{cur.dmPelsHeight} this {(primary ? "main " : "")}screen can show {best} frames per second, but Windows is set to {cur.dmDisplayFrequency}. Games and even the mouse cursor look less smooth.{(onBattery ? " The PC is on battery right now, and many laptops lower the refresh rate on battery to save power; plug in and check again." : "")}",
                    "Settings > System > Display > Advanced display > Choose a refresh rate. Use a DisplayPort or HDMI 2.0+ cable if the higher rate isn't offered. If you set a lower rate on purpose, accept this finding.",
                    new { Monitor = monName, Primary = primary, Current = cur.dmDisplayFrequency, Max = best, OnBattery = onBattery }, ruleId: "perf.refresh-rate");
            }
        }
        return list;
    }

    /// <summary>Monitor model names from the EDID (WmiMonitorID), keyed by the PnP hardware id such as "GSM5B7F".</summary>
    private static Dictionary<string, string> MonitorNames()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Wmi.Query("SELECT InstanceName, UserFriendlyName FROM WmiMonitorID", @"root\wmi", TimeSpan.FromSeconds(10), optional: true))
        {
            var id = HardwareId(r.S("InstanceName"));
            if (id is null || r.GetValueOrDefault("UserFriendlyName") is not ushort[] chars) continue;
            var name = new string(chars.TakeWhile(c => c != 0).Select(c => (char)c).ToArray()).Trim();
            if (name.Length > 0) d.TryAdd(id, name);
        }
        return d;
    }

    /// <summary>"DISPLAY\GSM5B7F\5&amp;..." or "MONITOR\GSM5B7F\{...}" gives "GSM5B7F".</summary>
    internal static string? HardwareId(string? pnp)
    {
        if (string.IsNullOrEmpty(pnp)) return null;
        var parts = pnp.Split('\\');
        return parts.Length >= 2 && parts[1].Length > 0 ? parts[1] : null;
    }

    internal static string MonitorName(string? deviceId, string? deviceString, IReadOnlyDictionary<string, string> edidNames, int number)
    {
        if (HardwareId(deviceId) is { } id && edidNames.TryGetValue(id, out var n)) return n;
        if (!string.IsNullOrWhiteSpace(deviceString) && !Regex.IsMatch(deviceString, @"^Generic( PnP| Non-PnP)? Monitor$", RegexOptions.IgnoreCase)) return deviceString;
        return $"Screen {number}";
    }

    // ---------------------------------------------------------------- RAM layout
    public sealed record Stick(long GB, string Part, string Slot, string Bank, int FormFactor);

    private static object Memory(CheckContext ctx, PcProfile pc)
    {
        var sticks = Wmi.Query("SELECT Capacity, PartNumber, DeviceLocator, BankLabel, FormFactor FROM Win32_PhysicalMemory", optional: true)
            .Select(s => new Stick((s.L("Capacity") ?? 0) / 1_073_741_824, s.S("PartNumber")?.Trim() ?? "", s.S("DeviceLocator")?.Trim() ?? "", s.S("BankLabel")?.Trim() ?? "", (int)(s.L("FormFactor") ?? 0))).ToList();
        JudgeMemory(ctx, sticks, pc);
        return sticks;
    }

    internal static void JudgeMemory(CheckContext ctx, List<Stick> sticks, PcProfile pc)
    {
        if (pc.Virtual || sticks.Count == 0) return;   // a virtual machine has virtual memory slots: no advice possible
        // Socketed sticks report DIMM (8) or SODIMM (12). Anything else is usually soldered memory, where moving or
        // adding sticks is impossible.
        bool socketed = sticks.All(s => s.FormFactor is 8 or 12);
        if (sticks.Count == 1)
        {
            if (!socketed || sticks[0].GB <= 0) return;
            ctx.Add(pc.Laptop ? Severity.Low : Severity.Medium, "Performance", "RAM runs in single-channel mode (one memory stick)",
                $"Only one {sticks[0].GB} GB stick is installed. With one stick the CPU gets about half the memory bandwidth, which costs FPS and causes stutter in CPU-heavy games.{(pc.Laptop ? " Some laptops have a second bank of memory soldered to the board, which Windows doesn't always list, so check the laptop's specifications first." : "")}",
                pc.Laptop ? "If the laptop has a free memory slot, add a stick of the same size and speed." : "Add a second identical stick (same size and speed) in the slot your motherboard manual marks for dual-channel, usually A2 and B2.",
                new { sticks[0].GB, sticks[0].Slot }, ruleId: "perf.ram-single-channel");
            return;
        }
        var channels = sticks.Select(s => ChannelOf(s.Slot, s.Bank)).ToList();
        // Only when every stick's slot name is understood: a guess here would send people to move working RAM.
        if (socketed && channels.All(c => c is not null) && channels.Distinct().Count() == 1)
            ctx.Add(Severity.Medium, "Performance", "All RAM sticks are on the same memory channel",
                $"Slots in use: {string.Join(", ", sticks.Select(s => string.IsNullOrEmpty(s.Bank) ? s.Slot : $"{s.Slot} ({s.Bank})"))}. Sticks on one channel run in single-channel mode at about half the bandwidth.",
                "Move the sticks so they sit on different channels. The motherboard manual names the dual-channel slots, usually A2 and B2. Check the manual first: a few boards name their slots unusually.",
                new { Slots = sticks.Select(s => s.Slot), Channel = channels[0] }, ruleId: "perf.ram-same-channel");
        // Laptops often combine soldered and socketed memory of different makes by design.
        var parts = sticks.Select(s => s.Part).Where(p => p.Length > 0 && !Regex.IsMatch(p, @"^(0+|Unknown|Undefined|None|NOT AVAILABLE)$", RegexOptions.IgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (socketed && !pc.Laptop && parts.Count > 1)
            ctx.Add(Severity.Low, "Stability", "Different RAM kits are mixed",
                $"Installed: {string.Join(", ", parts)}. Mixed kits often can't run their rated speed together and are a common cause of random crashes with XMP/EXPO on.",
                "If you see crashes or blue screens, test with only one kit installed, or run all sticks at a lower speed.", new { Parts = parts }, ruleId: "stability.ram-mixed");
    }

    /// <summary>
    /// The memory channel a slot belongs to, from Win32_PhysicalMemory's DeviceLocator and BankLabel, or null when
    /// the naming isn't understood. Boards name slots very differently:
    /// "Controller0-ChannelA-DIMM1" (MSI/ASRock/Gigabyte Intel: the controller is the channel),
    /// "ChannelA-DIMM0", "DIMM 0" + "P0 CHANNEL A" (AMD), "DIMM_A2" + "BANK 1" (ASUS), "Channel0-DIMM0".
    /// </summary>
    internal static string? ChannelOf(string slot, string bank)
    {
        var s = $"{slot} {bank}";
        const RegexOptions o = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
        // Two-socket boards repeat channel names per CPU ("CPU1_DIMM_A1", "NODE 1", "P1 CHANNEL A").
        var socket = Regex.Match(s, @"\b(?:CPU|NODE|SOCKET|P)\s*(\d)(?=[^0-9]|$)", o);
        var prefix = socket.Success ? "S" + socket.Groups[1].Value : "";
        var key = ChannelKey(s, o);
        return key is null ? null : prefix + key;
    }

    private static string? ChannelKey(string s, RegexOptions o)
    {
        var ctl = Regex.Match(s, @"Controller\s*(\d)", o);
        var ch = Regex.Match(s, @"(?<![A-Za-z])Channel\s*([A-H0-7])(?![A-Za-z0-9])", o);
        if (ctl.Success) return "C" + ctl.Groups[1].Value + (ch.Success ? ch.Groups[1].Value.ToUpperInvariant() : "");
        if (ch.Success) return ch.Groups[1].Value.ToUpperInvariant();
        var dimm = Regex.Match(s, @"(?<![A-Za-z])DIMM[_ ]?([A-H])(?:\d|(?![A-Za-z0-9]))", o);
        return dimm.Success ? dimm.Groups[1].Value.ToUpperInvariant() : null;
    }

    // ---------------------------------------------------------------- NVIDIA (via the driver's own nvidia-smi)
    private const string BaseFields = "name,temperature.gpu,power.draw,power.limit,clocks.gr,clocks.max.gr,pcie.link.gen.current,pcie.link.gen.max,pcie.link.width.current,pcie.link.width.max,fan.speed,utilization.gpu";

    private static object? Nvidia(CheckContext ctx, PcProfile pc)
    {
        var exe = new[] { Path.Combine(Environment.SystemDirectory, "nvidia-smi.exe"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"NVIDIA Corporation\NVSMI\nvidia-smi.exe") }.FirstOrDefault(File.Exists);
        if (exe is null) return null;
        // One unknown field makes nvidia-smi reject the whole query. Newer drivers call the throttle bitmask
        // "clocks_event_reasons", older ones "clocks_throttle_reasons"; try both, then without.
        string output = "";
        bool ok = false;
        foreach (var extra in new[] { ",clocks_event_reasons.active", ",clocks_throttle_reasons.active", "" })
        {
            var (code, o) = Proc.Run(exe, $"--query-gpu={BaseFields}{extra} --format=csv,noheader,nounits", TimeSpan.FromSeconds(15));
            if (code == 0) { output = o; ok = true; break; }
        }
        if (!ok) { CheckContext.Minor("NVIDIA's nvidia-smi tool didn't answer"); return null; }
        var gpus = new List<object>();
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (ParseNvidia(line) is { } g) { gpus.Add(g); JudgeNvidia(ctx, g, pc); }
        return gpus;
    }

    public sealed record NvidiaGpu(string Name, double? TempC, double? PowerW, double? PowerLimitW, double? ClockMHz, double? MaxClockMHz, double? PcieGen, double? PcieGenMax,
                                   double? PcieWidth, double? PcieWidthMax, double? FanPercent, double? UsagePercent, string? ThrottleReasons, ulong Reasons);

    internal static NvidiaGpu? ParseNvidia(string line)
    {
        var f = line.Split(',').Select(x => x.Trim()).ToArray();
        if (f.Length < 12) return null;
        double? N(int i) => double.TryParse(f[i], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
        string? raw = f.Length > 12 ? f[12] : null;
        ulong reasons = 0;
        if (raw is not null && raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) ulong.TryParse(raw[2..], System.Globalization.NumberStyles.HexNumber, null, out reasons);
        return new NvidiaGpu(f[0], N(1), N(2), N(3), N(4), N(5), N(6), N(7), N(8), N(9), N(10), N(11), raw, reasons);
    }

    /// <summary>Shared by all graphics card makers. x8 costs a few percent and is by design when an M.2 slot shares the
    /// lanes; x4 or less on a desktop is a real loss. Laptops wire their graphics chip as the maker chose.</summary>
    internal static void JudgePcieWidth(CheckContext ctx, string name, double w, double wm, PcProfile pc)
    {
        if (wm < 8 || w <= 0 || w >= wm) return;
        if (pc.Laptop)
        {
            ctx.Add(Severity.Low, "Performance", $"Graphics chip uses x{w:0} of x{wm:0} PCIe lanes: {name}",
                "In laptops the maker decides how many lanes the graphics chip gets, so this is usually by design. If it changed after a repair or BIOS update, contact the maker.",
                "Nothing to do unless performance dropped recently.", new { name, Width = w, MaxWidth = wm }, ruleId: "perf.gpu-pcie-width");
            return;
        }
        ctx.Add(w <= 4 ? Severity.Medium : Severity.Low, "Performance", $"Graphics card uses only x{w:0} of its x{wm:0} PCIe lanes: {name}",
            $"The card is connected with fewer lanes than it supports. {(w <= 4 ? "At x4 or less this costs noticeable performance. " : "At x8 the loss is usually a few percent. ")}Usually it sits in the wrong slot, isn't fully seated, or an M.2 drive shares its lanes.",
            "Put the card in the top full-length slot, reseat it, and check the motherboard manual for M.2 slots that share lanes with it.", new { name, Width = w, MaxWidth = wm }, ruleId: "perf.gpu-pcie-width");
    }

    // NVML clock event reasons: 0x08 HW slowdown, 0x20 SW thermal, 0x40 HW thermal, 0x80 HW power brake (always with 0x08).
    internal static void JudgeNvidia(CheckContext ctx, NvidiaGpu g, PcProfile pc)
    {
        const string moment = "This was measured at the moment of the check; at idle these values are usually fine, so a warning here means it happened without load or was still going on.";
        if (g.PcieWidth is { } w && g.PcieWidthMax is { } wm)
            JudgePcieWidth(ctx, g.Name, w, wm, pc);
        if (g.TempC >= 87)
            ctx.Add(g.TempC >= 93 ? Severity.Medium : Severity.Low, "Performance", $"Graphics card is hot ({g.TempC:0} °C): {g.Name}",
                $"Above about 85 °C NVIDIA cards lower their clocks to protect themselves, which costs FPS and can cause stutter. {moment}",
                "Clean dust from the card and case fans, improve case airflow, and check the fan curve. Older cards may need new thermal paste.", new { g.Name, g.TempC }, ruleId: "perf.gpu-hot");
        bool brake = (g.Reasons & 0x80) != 0;
        bool thermal = (g.Reasons & 0x60) != 0;
        bool slowdown = (g.Reasons & 0x08) != 0 && !brake;
        if (thermal || slowdown)
            ctx.Add(Severity.Medium, "Performance", $"Graphics card is slowing down to protect itself: {g.Name}",
                $"The driver reports active throttling ({g.ThrottleReasons}): {(thermal ? "temperature" : "hardware slowdown (power or heat)")}. {moment}",
                "Improve cooling, check that the power cables are firmly connected to the card, and remove aggressive overclocks.", new { g.Name, Reasons = g.ThrottleReasons }, ruleId: "perf.gpu-throttle");
        if (brake)
            ctx.Add(Severity.Medium, "Stability", $"Graphics card hit its power brake: {g.Name}",
                $"The card's emergency power brake was active. That usually means the power supply or its cable can't deliver enough power at peaks. {moment}",
                "Use separate PCIe power cables from the power supply (not one split cable), check the 12VHPWR/12V-2x6 connector is fully inserted, and check the power supply is strong enough.", new { g.Name }, ruleId: "stability.gpu-power-brake");
    }
}

/// <summary>
/// Voltages, temperatures, fans and power from HWiNFO or LibreHardwareMonitor when one of them is running.
/// Reading these directly needs a kernel driver, which a read-only tool shouldn't install (Defender flags the
/// common one, WinRing0), so TriageKit reuses the sensor tool the user already trusts.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class SensorsCheck : ICheck
{
    public string Name => "Sensors: voltages & temperatures";
    public string Module => "doctor";

    /// <summary>One sensor reading. Min/Max/Avg are since the sensor tool started (HWiNFO), not since TriageKit started.</summary>
    public sealed record Reading(string Source, string Group, string Label, string Kind, double Value, double? Min, double? Max, string Unit, double? Avg = null);

    public object? Run(CheckContext ctx)
    {
        var (readings, problem) = ReadHwinfo();
        readings ??= ReadLibreHardwareMonitor();
        if (readings is null || readings.Count == 0)
        {
            ctx.Add(Severity.Info, "Performance", "Voltages and temperatures weren't checked",
                (problem is null ? "" : problem + " ") +
                "Windows doesn't share voltage, fan and most temperature readings without a hardware driver. TriageKit doesn't install one; it reads them from HWiNFO or LibreHardwareMonitor if one is running.",
                "For a full hardware check: start HWiNFO (Sensors only, with \"Shared Memory Support\" on; the free version turns sharing off after 12 hours, so restart it if needed) or LibreHardwareMonitor, then run PC Doctor again.", null, ruleId: "doctor.sensors-missing");
            return new { Ran = false, Reason = problem ?? "No sensor app running (HWiNFO or LibreHardwareMonitor)", Source = (string?)null, Problem = problem, Limits = DoctorLimits.ForUi };
        }
        var pc = PcProfile.Detect();
        var window = TimeSpan.FromDays(30);
        var crashes = Evt.Read("System", "EventID=41 and Provider[@Name='Microsoft-Windows-Kernel-Power']", window, 1).Count
                    + Evt.Read("System", "Provider[@Name='Microsoft-Windows-WHEA-Logger']", window, 1).Count > 0;
        Judge(ctx, readings, pc, crashes);
        return new { Source = readings[0].Source, Count = readings.Count, Pc = pc, CrashEvidence = crashes, Readings = readings.Take(400).ToList(), Limits = DoctorLimits.ForUi };
    }

    private static readonly Regex Rail12 = new(@"^\+?12(\.0)?\s?V\b", RegexOptions.IgnoreCase), Rail5 = new(@"^\+?5(\.0)?\s?V\b", RegexOptions.IgnoreCase), Rail33 = new(@"^\+?3\.3\s?V\b", RegexOptions.IgnoreCase);
    private static readonly Regex Standby = new(@"SB|Standby|Stand-by|AUX|Dual|VSB|\bDDR|Memory|PCH|VCCIO|USB", RegexOptions.IgnoreCase);

    /// <param name="crashEvidence">Unexpected shutdowns (Kernel-Power 41) or hardware errors (WHEA) in the last 30 days.</param>
    internal static void Judge(CheckContext ctx, List<Reading> readings, PcProfile pc, bool crashEvidence)
    {
        var evidenceText = crashEvidence ? " Windows also logged unexpected shutdowns or hardware errors in the last 30 days, which fits." : "";

        // ---- Power supply rails. ATX allows +/-5%. Motherboard sensors are often a few percent off, so a value
        // counts only when the current reading AND the average are outside the limit; beyond 10% the sensor is wrong.
        foreach (var (rx, nominal) in new[] { (Rail12, 12.0), (Rail5, 5.0), (Rail33, 3.3) })
            foreach (var r in readings.Where(r => r.Kind == "Voltage" && rx.IsMatch(r.Label) && !Standby.IsMatch(r.Label)))
            {
                double lo = nominal * (1 - DoctorLimits.RailTolerance), hi = nominal * (1 + DoctorLimits.RailTolerance);
                // HWiNFO gives an average; LibreHardwareMonitor only min/max, so their midpoint stands in for it.
                double sustained = r.Avg ?? (r.Min is { } mn && r.Max is { } mx ? (mn + mx) / 2 : r.Value);
                bool outNow = r.Value < lo || r.Value > hi, outAvg = sustained < lo || sustained > hi;
                if (!(outNow && outAvg)) continue;
                double dev = Math.Max(Math.Abs(r.Value - nominal), Math.Abs(sustained - nominal)) / nominal;
                if (dev > DoctorLimits.RailImplausible)
                {
                    ctx.Add(Severity.Info, "Stability", $"{r.Label} sensor reading looks wrong",
                        $"{r.Source} reports {r.Value:0.00} V (average {sustained:0.00} V) for the {nominal:0.#} V rail. A PC can't run with its rail that far off, so this sensor is almost certainly mis-scaled on this motherboard.",
                        "Nothing to do. If you want certainty, measure the rail with a multimeter.", r, ruleId: "stability.psu-rail-sensor");
                    continue;
                }
                ctx.Add(crashEvidence ? Severity.Medium : Severity.Low, "Stability", $"{r.Label} power rail is out of spec",
                    $"The {nominal:0.#} V rail should stay between {lo:0.00} and {hi:0.00} V. {r.Source} reads {r.Value:0.00} V now and {sustained:0.00} V on average (lowest {r.Min ?? r.Value:0.00} V, highest {r.Max ?? r.Value:0.00} V since it started). Out-of-spec rails cause random crashes, reboots under load and stutter.{evidenceText}",
                    "Motherboard sensors can be a few percent off, so confirm with a second tool or a multimeter. If it's real, the power supply is failing or too weak.", r, ruleId: "stability.psu-rail");
            }

        // ---- CPU core voltage. VID is what the CPU asks for, not what it gets, so only measured voltages count.
        // Short boosts to about 1.5 V are normal on stock Ryzen 3000/5000 and patched Intel 13th/14th gen (Intel's
        // fix caps requests at 1.55 V); Ryzen 7000/9000 stay lower.
        var limit = pc.CoreVoltageLimit;
        var vcore = readings.Where(r => r.Kind == "Voltage" && !Regex.IsMatch(r.Label, @"VID|SoC|GFX|GT\b|NB|VDDCR_SOC|Memory|DRAM", RegexOptions.IgnoreCase)
                                        && Regex.IsMatch(r.Label, @"^(Vcore|CPU Core( Voltage)?|Core Voltage|CPU Core Voltage \(SVI[23] TFN\)|VDDCR_CPU)", RegexOptions.IgnoreCase))
                            .Select(r => (r, Peak: r.Max ?? r.Value)).Where(x => x.Peak > limit && x.Peak < 2.5).OrderByDescending(x => x.Peak).FirstOrDefault();
        if (vcore.r is not null)
            ctx.Add(crashEvidence ? Severity.Medium : Severity.Low, "Stability", $"CPU voltage went above {limit:0.00} V",
                $"{vcore.r.Label} reached {vcore.Peak:0.000} V (the highest value since {vcore.r.Source} was started). For {(pc.CpuName.Length > 0 ? pc.CpuName : "this CPU")} that is above the normal stock range. Sustained high voltage wears a CPU out faster.{evidenceText}",
                pc.Intel ? "Update the motherboard BIOS to a version with Intel's 0x12B microcode or newer and choose the \"Intel Default Settings\" profile instead of the board's own auto-overclocking."
                : pc.Amd ? "Check the BIOS for manual core voltage, Precision Boost Overdrive or positive offsets and set them back to Auto/defaults. Update the BIOS if it is old."
                : "Reset the BIOS to defaults and update it, then check again.", vcore.r, ruleId: "stability.cpu-voltage");

        // ---- Temperatures.
        void Hot(IEnumerable<Reading> candidates, double warn, double bad, string what, string detail, string advice, string id)
        {
            var hit = candidates.Select(r => (r, Peak: Math.Max(r.Value, r.Max ?? r.Value))).Where(x => x.Peak >= warn && x.Peak <= 150).OrderByDescending(x => x.Peak).FirstOrDefault();
            if (hit.r is null) return;
            ctx.Add(hit.Peak >= bad ? Severity.Medium : Severity.Low, "Performance", $"{what} reached {hit.Peak:0} °C",
                $"{hit.r.Label}, measured by {hit.r.Source}: highest value since it was started. {detail}", advice, hit.r, ruleId: id);
        }
        var temps = readings.Where(r => r.Kind == "Temperature").ToList();
        bool IsGpu(Reading r) => Regex.IsMatch(r.Group + " " + r.Label, @"\bGPU\b|NVIDIA|GeForce|Radeon|Arc\b|/gpu", RegexOptions.IgnoreCase);

        // CPU: a Ryzen with both Tctl and Tdie reports Tctl with an offset; prefer Tdie.
        var cpuTemps = temps.Where(r => !IsGpu(r) && Regex.IsMatch(r.Label, @"^(CPU Package|CPU \(Tctl/Tdie\)|CPU Tctl|CPU Tdie|Tctl|Tdie|Core Max|CPU Die|Core \(Tctl/Tdie\))", RegexOptions.IgnoreCase)).ToList();
        if (cpuTemps.Any(r => Regex.IsMatch(r.Label, @"Tdie", RegexOptions.IgnoreCase) && !r.Label.Contains("Tctl", StringComparison.OrdinalIgnoreCase)))
            cpuTemps.RemoveAll(r => Regex.IsMatch(r.Label, @"^(CPU )?Tctl$", RegexOptions.IgnoreCase));
        var cpuLimit = pc.CpuTempLimit;
        Hot(cpuTemps, cpuLimit - 2, cpuLimit + 50, "CPU",
            $"That is at the limit where this CPU ({cpuLimit:0} °C) slows itself down. {(pc.Am5 || pc.X3D ? "Ryzen 7000/9000 CPUs are designed to run up to their limit under full load, so this matters most if it happens in games or light work." : "Under sustained load this costs performance and causes uneven frame times.")}",
            "Clean dust from the cooler and case, check the cooler is mounted firmly and its fans run, and replace old thermal paste. A stronger cooler helps if it happens under normal use.", "perf.cpu-hot");

        // HWiNFO's own "thermal throttling" flags are more reliable than temperature limits.
        var throttled = readings.Where(r => r.Kind == "Flag" && (r.Max ?? r.Value) >= 1 && !IsGpu(r) && Regex.IsMatch(r.Label, @"Thermal Throttling|PROCHOT|Critical Temperature", RegexOptions.IgnoreCase)).FirstOrDefault();
        if (throttled is not null)
            ctx.Add(Severity.Low, "Performance", "The CPU slowed itself down because of heat",
                $"{throttled.Source} recorded \"{throttled.Label}\" since it was started. The CPU lowers its speed when it gets too hot, which shows up as stutter and FPS drops.",
                "Clean dust from the cooler and case, check the cooler is mounted firmly, and replace old thermal paste.", throttled, ruleId: "perf.cpu-throttle");

        // GPU: the memory junction (GDDR6X) is specified up to about 105 to 110 °C; the core hot spot differs by maker.
        var memJunction = temps.Where(r => IsGpu(r) && Regex.IsMatch(r.Label, @"Memory Junction|Memory Temperature|VRAM", RegexOptions.IgnoreCase));
        Hot(memJunction, 106, 110, "Graphics memory",
            "Graphics memory (GDDR6X) is designed for up to about 105 to 110 °C, so this is at its limit and the card will slow down.",
            "Improve case airflow and clean the card. If the card is a few years old, new thermal pads on the memory usually fix this.", "perf.gpu-memory-hot");
        var hotSpot = temps.Where(r => IsGpu(r) && Regex.IsMatch(r.Label, @"Hot ?Spot|Junction", RegexOptions.IgnoreCase) && !Regex.IsMatch(r.Label, @"Memory", RegexOptions.IgnoreCase)).ToList();
        bool amdGpu = hotSpot.Any(r => Regex.IsMatch(r.Group, @"AMD|Radeon", RegexOptions.IgnoreCase));
        Hot(hotSpot, amdGpu ? 110 : 105, amdGpu ? 115 : 110, "Graphics chip hot spot",
            "This is at the point where the card limits its speed.",
            "Improve case airflow and clean the card. A big gap between GPU and hot-spot temperature means the card needs new thermal paste or pads.", "perf.gpu-hotspot");

        // Motherboard VRM (not the graphics card's).
        var vrm = temps.Where(r => !IsGpu(r) && Regex.IsMatch(r.Label, @"\bVRM\b|\bMOS\b|MOSFET", RegexOptions.IgnoreCase));
        Hot(vrm, 100, 110, "Motherboard power stage (VRM)",
            "Hot VRMs make the motherboard limit CPU power, which costs performance.",
            "Add airflow over the area around the CPU socket, for example a case fan that blows across it.", "perf.vrm-hot");
        // SSD temperatures come from Windows' own disk health counters (Devices & system health), so they are not repeated here.
    }

    // ---------------------------------------------------------------- HWiNFO shared memory (Global\HWiNFO_SENS_SM2)
    // Layout from the public SM2 interface: header magic 'HWiS' ("DAED" when sharing has stopped), poll time at 12,
    // sensor section at 20/24/28, reading section at 32/36/40. Reading: type 0, sensor index 4, id 8, labels 12/140,
    // unit 268, value 284, min 292, max 300, average 308.
    internal static (List<Reading>? Readings, string? Problem) ReadHwinfo()
    {
        Mutex? mutex = null;
        bool locked = false;
        try
        {
            // HWiNFO running as administrator shares in the Global namespace; without admin rights in the session one.
            MemoryMappedFile? found = null;
            foreach (var name in new[] { @"Global\HWiNFO_SENS_SM2", "HWiNFO_SENS_SM2" })
                try { found = MemoryMappedFile.OpenExisting(name, MemoryMappedFileRights.Read); break; } catch (FileNotFoundException) { }
            if (found is null) return (null, Process.GetProcessesByName("HWiNFO64").Concat(Process.GetProcessesByName("HWiNFO32")).Concat(Process.GetProcessesByName("HWiNFO")).Any()
                ? "HWiNFO is running, but \"Shared Memory Support\" is off (HWiNFO Settings > General / User Interface)." : null);
            using var mmf = found;
            using var v = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
            // HWiNFO updates the section under this mutex; holding it briefly avoids reading half-written values.
            try { if (Mutex.TryOpenExisting(@"Global\HWiNFO_SM2_MUTEX", out mutex)) locked = mutex.WaitOne(100); }
            catch (AbandonedMutexException) { locked = true; }
            catch { }
            var magic = v.ReadUInt32(0);
            if (magic is 0x44454144 or 0x44414544) return (null, "HWiNFO is running, but it has stopped sharing its sensors (the free version does this after 12 hours).");   // "DAED"
            var poll = v.ReadInt64(12);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (poll > 1_400_000_000 && poll < now + 86400 && now - poll > 300) return (null, "HWiNFO's shared sensor data hasn't been updated for over 5 minutes.");
            return (ParseHwinfo(v), null);
        }
        catch (FileNotFoundException) { return (null, null); }
        catch (Exception ex) { CheckContext.Minor("HWiNFO's shared memory couldn't be read", ex); return (null, null); }
        finally
        {
            if (locked) try { mutex!.ReleaseMutex(); } catch { }
            mutex?.Dispose();
        }
    }

    internal static List<Reading>? ParseHwinfo(UnmanagedMemoryAccessor v)
    {
        if (v.ReadUInt32(0) != 0x53695748) return null;   // 'HWiS'
        uint offSensor = v.ReadUInt32(20), sizeSensor = v.ReadUInt32(24), numSensor = v.ReadUInt32(28);
        uint offRead = v.ReadUInt32(32), sizeRead = v.ReadUInt32(36), numRead = v.ReadUInt32(40);
        if (numRead > 20000 || sizeRead < 316 || sizeSensor < 264) return null;
        long capacity = v.Capacity;
        if (offSensor + (long)sizeSensor * Math.Min(numSensor, 2000) > capacity || offRead + (long)sizeRead * numRead > capacity) return null;
        string Str(long pos, int len) { var b = new byte[len]; v.ReadArray(pos, b, 0, len); int z = Array.IndexOf(b, (byte)0); return Encoding.Latin1.GetString(b, 0, z < 0 ? len : z).Trim(); }
        var groups = new List<string>();
        for (uint i = 0; i < Math.Min(numSensor, 2000); i++)
        {
            long p = offSensor + i * sizeSensor;   // id(4) inst(4) nameOrig[128] nameUser[128]
            var user = Str(p + 136, 128); groups.Add(user.Length > 0 ? user : Str(p + 8, 128));
        }
        var list = new List<Reading>();
        for (uint i = 0; i < numRead; i++)
        {
            long p = offRead + i * sizeRead;
            var type = v.ReadUInt32(p);
            var label = Str(p + 140, 128); if (label.Length == 0) label = Str(p + 12, 128);
            var unit = Str(p + 268, 16);
            var kind = type switch { 1 => "Temperature", 2 => "Voltage", 3 => "Fan", 4 => "Current", 5 => "Power", 6 => "Clock", 7 => "Usage", _ => "Other" };
            // Yes/No readings such as "Thermal Throttling" are type "Other" with the unit "Yes/No".
            if (kind == "Other" && unit.Contains("Yes", StringComparison.OrdinalIgnoreCase)) kind = "Flag";
            if (kind is "Other" or "Usage" or "Clock") continue;
            var sensor = (int)v.ReadUInt32(p + 4);
            list.Add(new Reading("HWiNFO", sensor < groups.Count ? groups[sensor] : "", label, kind, v.ReadDouble(p + 284), v.ReadDouble(p + 292), v.ReadDouble(p + 300), unit, v.ReadDouble(p + 308)));
        }
        return list;
    }

    // ---------------------------------------------------------------- LibreHardwareMonitor WMI (root\LibreHardwareMonitor)
    // OpenHardwareMonitor is no longer maintained and misreads current CPUs, so only LibreHardwareMonitor is used.
    private static List<Reading>? ReadLibreHardwareMonitor()
    {
        const string ns = @"root\LibreHardwareMonitor";
        if (!Wmi.NamespaceExists(ns)) return null;
        var rows = Wmi.Query("SELECT Name, SensorType, Value, Min, Max, Parent FROM Sensor", ns, TimeSpan.FromSeconds(15), optional: true);
        if (rows.Count == 0) return null;
        static double? D(object? o) { try { return o is null ? null : Convert.ToDouble(o, System.Globalization.CultureInfo.InvariantCulture); } catch { return null; } }
        return rows.Select(r => new Reading("LibreHardwareMonitor", r.S("Parent") ?? "", r.S("Name") ?? "", r.S("SensorType") ?? "",
                    D(r.GetValueOrDefault("Value")) ?? 0, D(r.GetValueOrDefault("Min")), D(r.GetValueOrDefault("Max")), ""))
            .Where(r => r.Kind is "Temperature" or "Voltage" or "Fan" or "Power" or "Current").ToList();
    }
}
