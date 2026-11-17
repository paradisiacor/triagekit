using System.Text.Json;

namespace TriageKit.Core.Agent;

public sealed class AgentConfig
{
    /// <summary>Local time for the daily scan, "HH:mm".</summary>
    public string DailyScanTime { get; set; } = "12:30";
    public bool QuickScheduledScans { get; set; }
    public int KeepScans { get; set; } = 60;
    public bool NotifyOnNewFindings { get; set; } = true;

    public static AgentConfig Load(string path)
    {
        try { if (File.Exists(path)) return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new(); }
        catch { }
        return new();
    }
}

public static class Schedule
{
    /// <summary>
    /// When the next scheduled scan should run. Catches up immediately (after a short delay) if the last scan is
    /// more than a day old, e.g. because the PC was off at the scheduled time.
    /// </summary>
    public static DateTime NextRun(DateTime now, DateTime? lastScan, string dailyTime, TimeSpan catchUpDelay)
    {
        if (!TimeSpan.TryParse(dailyTime, out var t) || t < TimeSpan.Zero || t >= TimeSpan.FromDays(1)) t = new TimeSpan(12, 30, 0);
        if (lastScan is null || now - lastScan.Value > TimeSpan.FromHours(26)) return now + catchUpDelay;
        var today = now.Date + t;
        var next = now < today ? today : today.AddDays(1);
        // Already scanned today after the scheduled time: wait for tomorrow.
        if (lastScan.Value >= now.Date + t && next == today) next = today.AddDays(1);
        return next;
    }
}
