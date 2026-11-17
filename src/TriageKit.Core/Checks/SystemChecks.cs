using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using TriageKit.Core.Engine;
using TriageKit.Core.Platform;

namespace TriageKit.Core.Checks;

[SupportedOSPlatform("windows")]
public sealed class SystemPostureCheck : ICheck
{
    public string Name => "System posture";

    public object? Run(CheckContext ctx)
    {
        var os = Wmi.Query("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime FROM Win32_OperatingSystem").FirstOrDefault() ?? new();
        var cs = Wmi.Query("SELECT Manufacturer, Model, Domain, PartOfDomain, TotalPhysicalMemory FROM Win32_ComputerSystem").FirstOrDefault() ?? new();
        var bios = Wmi.Query("SELECT Manufacturer, SMBIOSBIOSVersion FROM Win32_BIOS").FirstOrDefault() ?? new();

        const string pol = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        var lua = Reg.Value(Registry.LocalMachine, pol, "EnableLUA") as int?;
        var consent = Reg.Value(Registry.LocalMachine, pol, "ConsentPromptBehaviorAdmin") as int?;
        if (lua == 0)
            ctx.Add(Severity.High, "System", "User Account Control (UAC) is disabled", "Every program runs with full administrator rights, so malware gets total control instantly.",
                    "Turn UAC back on (Control Panel > User Accounts > Change User Account Control settings) and restart.", mitre: "T1548.002", ruleId: "system.uac-disabled");
        else if (consent == 0)
            ctx.Add(Severity.Medium, "System", "UAC elevates silently without asking", "Programs can gain administrator rights without any prompt.",
                    "Set UAC to at least 'Notify me only when apps try to make changes'.", mitre: "T1548.002", ruleId: "system.uac-silent");

        var rdpDeny = Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections") as int?;
        if (rdpDeny == 0)
            ctx.Add(Severity.Low, "System", "Remote Desktop is enabled", "RDP is a common way in for attackers when it is exposed or uses a weak password.",
                    "Turn off Remote Desktop if you do not use it (Settings > System > Remote Desktop).", mitre: "T1021.001", ruleId: "system.rdp-enabled");

        var secureBoot = Reg.Value(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled") as int?;
        if (secureBoot == 0)
            ctx.Add(Severity.Low, "System", "Secure Boot is disabled", "Boot-level malware (bootkits) is easier to install.", "Enable Secure Boot in your UEFI/BIOS settings.", mitre: "T1542", ruleId: "system.secureboot-off");

        // Firewall profiles (MSFT_NetFirewallProfile.Enabled: 1 = true, 0 = false, 2 = not configured -> treated as on)
        var fw = Wmi.Query("SELECT Name, Enabled, DefaultInboundAction FROM MSFT_NetFirewallProfile", @"root\StandardCimv2")
            .Select(p => new { Name = p.S("Name"), Enabled = p.L("Enabled") != 0, DefaultInbound = p.L("DefaultInboundAction") switch { 4 => "Block", 2 => "Allow", _ => "Not configured" } }).ToList();
        foreach (var p in fw.Where(p => !p.Enabled))
            ctx.Add(Severity.Medium, "System", $"Windows Firewall is off for the {p.Name} profile", "Programs on your network can reach this PC directly.",
                    "Turn the firewall on in Windows Security > Firewall & network protection.", mitre: "T1562.004", ruleId: "system.firewall-off");

        var bitlocker = Wmi.Query("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume", @"root\CIMV2\Security\MicrosoftVolumeEncryption")
            .Select(v => new { Drive = v.S("DriveLetter"), Protected = v.L("ProtectionStatus") == 1 }).ToList();
        var sysDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        if (bitlocker.FirstOrDefault(b => string.Equals(b.Drive, sysDrive, StringComparison.OrdinalIgnoreCase)) is { Protected: false })
            ctx.Add(Severity.Low, "System", "System drive is not encrypted", "If the device is lost or stolen, files can be read by anyone.",
                    "Turn on BitLocker or Device encryption (Settings > Privacy & security > Device encryption).", ruleId: "system.bitlocker-off");

        DateTime? lastPatch = null; string? lastKb = null;
        foreach (var q in Wmi.Query("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"))
        {
            var d = ParseHotfixDate(q.S("InstalledOn"));
            if (d is not null && (lastPatch is null || d > lastPatch)) { lastPatch = d; lastKb = q.S("HotFixID"); }
        }
        if (lastPatch is not null && lastPatch < DateTime.Now.AddDays(-60))
            ctx.Add(Severity.Medium, "System", "No Windows updates installed in over 60 days", $"Last update: {lastPatch:yyyy-MM-dd} ({lastKb}). Unpatched systems are the easiest to break into.",
                    "Open Settings > Windows Update and install all updates.", ruleId: "system.patch-age");

        var smartScreen = Reg.Value(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string;
        if (string.Equals(smartScreen, "Off", StringComparison.OrdinalIgnoreCase))
            ctx.Add(Severity.Medium, "System", "SmartScreen for apps is turned off", "Windows will not warn you before running unknown downloaded programs.",
                    "Enable 'Check apps and files' in Windows Security > App & browser control.", ruleId: "system.smartscreen-off");

        var admins = LocalAdministrators();
        if (admins.Count > 2)
            ctx.Add(Severity.Low, "System", $"{admins.Count} accounts are local administrators", string.Join(", ", admins),
                    "Keep administrator accounts to a minimum and use a standard account for everyday work.", mitre: "T1078.003", ruleId: "system.many-admins");

        var vbs = Wmi.Query("SELECT VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard", @"root\Microsoft\Windows\DeviceGuard").FirstOrDefault();
        var boot = os.Date("LastBootUpTime");

        return new
        {
            ComputerName = Environment.MachineName,
            User = $"{Environment.UserDomainName}\\{Environment.UserName}",
            OS = $"{os.S("Caption")} {os.S("Version")} (build {os.S("BuildNumber")})",
            Architecture = os.S("OSArchitecture"),
            InstallDate = os.Date("InstallDate")?.ToString("s"),
            LastBoot = boot?.ToString("s"),
            UptimeHours = boot is null ? (double?)null : Math.Round((DateTime.Now - boot.Value).TotalHours, 1),
            Manufacturer = cs.S("Manufacturer"), Model = cs.S("Model"), Domain = cs.S("Domain"), PartOfDomain = cs.B("PartOfDomain"),
            RAMGB = cs.L("TotalPhysicalMemory") is long ram ? Math.Round(ram / 1073741824.0, 1) : (double?)null,
            BIOS = $"{bios.S("Manufacturer")} {bios.S("SMBIOSBIOSVersion")}".Trim(),
            UACEnabled = lua != 0, UACConsentPromptAdmin = consent,
            RDPEnabled = rdpDeny == 0, SecureBoot = secureBoot is null ? null : (bool?)(secureBoot == 1),
            SmartScreen = smartScreen, VBSRunning = vbs is null ? null : (bool?)(vbs.L("VirtualizationBasedSecurityStatus") == 2),
            LastHotfix = lastPatch is null ? null : $"{lastKb} {lastPatch:yyyy-MM-dd}",
            Firewall = fw, BitLocker = bitlocker, LocalAdmins = admins.Select(a => new { Name = a }).ToList()
        };
    }

    internal static DateTime? ParseHotfixDate(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        // Win32_QuickFixEngineering.InstalledOn is usually M/d/yyyy but can be hex FILETIME or locale-formatted.
        if (Regex.IsMatch(s, "^[0-9A-Fa-f]{16}$")) { try { return DateTime.FromFileTime(Convert.ToInt64(s, 16)); } catch { return null; } }
        string[] formats = { "M/d/yyyy", "MM/dd/yyyy", "yyyyMMdd", "d.M.yyyy", "dd.MM.yyyy", "yyyy-MM-dd" };
        if (DateTime.TryParseExact(s, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) return d;
        // Checks run with the invariant culture, so ask the user's own regional format explicitly.
        foreach (var c in UserCultures())
            if (DateTime.TryParse(s, c, DateTimeStyles.None, out d)) return d;
        return null;
    }

    /// <summary>The user's regional format (Control Panel > Region), then the Windows display language.</summary>
    private static IEnumerable<CultureInfo> UserCultures()
    {
        string? name = null;
        try { name = Microsoft.Win32.Registry.GetValue(@"HKEY_CURRENT_USER\Control Panel\International", "LocaleName", null) as string; } catch { }
        if (!string.IsNullOrEmpty(name))
        {
            CultureInfo? c = null;
            try { c = new CultureInfo(name); } catch { }
            if (c is not null) yield return c;
        }
        yield return CultureInfo.InstalledUICulture;
    }

    private static List<string> LocalAdministrators()
    {
        try
        {
            // The Administrators group name is localised ("Administratoren", "Administrateurs"...), so resolve it by SID.
            var name = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value.Split('\\').Last();
            var machine = Environment.MachineName;
            return Wmi.Query($"SELECT PartComponent FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='{machine}',Name='{name}'\"")
                .Select(r => r.S("PartComponent") ?? "")
                .Select(pc => Regex.Match(pc, "Domain=\"([^\"]+)\",Name=\"([^\"]+)\"")).Where(m => m.Success)
                .Select(m => $"{m.Groups[1].Value}\\{m.Groups[2].Value}").ToList();
        }
        catch { return new(); }
    }
}

[SupportedOSPlatform("windows")]
public sealed class DefenderCheck : ICheck
{
    public string Name => "Antivirus & Defender";
    private const string Ns = @"root\Microsoft\Windows\Defender";

    public object? Run(CheckContext ctx)
    {
        var av = Wmi.Query("SELECT displayName, pathToSignedProductExe, productState FROM AntiVirusProduct", @"root\SecurityCenter2")
            .Select(a => new { Name = a.S("displayName"), Path = a.S("pathToSignedProductExe"), State = a.L("productState") }).ToList();
        var status = Wmi.Query("SELECT * FROM MSFT_MpComputerStatus", Ns).FirstOrDefault();
        var pref = Wmi.Query("SELECT * FROM MSFT_MpPreference", Ns).FirstOrDefault();

        var exclusions = new List<object>();
        // Defender's WMI provider fails when Defender is switched off or broken; the exclusions are still in the
        // registry (readable as SYSTEM or administrator on most builds), and malware leaves them behind.
        var lists = new List<(string Type, IEnumerable<string> Values)>();
        if (pref is not null)
            foreach (var (type, key) in new[] { ("Path", "ExclusionPath"), ("Process", "ExclusionProcess"), ("Extension", "ExclusionExtension"), ("IP", "ExclusionIpAddress") })
                lists.Add((type, pref.A(key)));
        else
        {
            try { using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"); }
            catch (Exception ex) { CheckContext.Note("Defender exclusions are protected and couldn't be read", ex); }
        }
        if (pref is null)
            foreach (var (type, sub) in new[] { ("Path", "Paths"), ("Process", "Processes"), ("Extension", "Extensions"), ("IP", "IpAddresses") })
                lists.Add((type, Reg.Values(Microsoft.Win32.Registry.LocalMachine, $@"SOFTWARE\Microsoft\Windows Defender\Exclusions\{sub}").Select(x => x.Name).Where(n => !string.IsNullOrEmpty(n)).ToList()));
        {
            foreach (var (type, values) in lists)
                foreach (var v in values)
                {
                    if (v.Contains("N/A: Must be an administrator", StringComparison.OrdinalIgnoreCase)) continue;
                    exclusions.Add(new { Type = type, Value = v });
                    var sev = Severity.Medium;
                    if (type == "Extension" && Regex.IsMatch(v, @"^\.?(exe|dll|ps1|vbs|js|bat|cmd|scr)$", RegexOptions.IgnoreCase)) sev = Severity.High;
                    if (type == "Path" && (Regex.IsMatch(v, @"^[a-zA-Z]:\\?$") || Regex.IsMatch(v, @"\\(Temp|AppData|Downloads|Users\\Public|ProgramData)(\\|$)", RegexOptions.IgnoreCase))) sev = Severity.High;
                    ctx.Add(sev, "Defender", $"Defender exclusion: {type} {v}", "Defender does not scan anything matching this exclusion. Malware often adds exclusions for itself.",
                            "Remove the exclusion in Windows Security > Virus & threat protection > Exclusions, unless you know exactly why it is there.",
                            new { Type = type, Value = v }, "T1562.001", "defender.exclusion");
                }
        }

        var names = Wmi.Query("SELECT ThreatID, ThreatName FROM MSFT_MpThreat", Ns)
            .GroupBy(t => t.S("ThreatID") ?? "").ToDictionary(g => g.Key, g => g.First().S("ThreatName"));
        var since = DateTime.Now.AddDays(-90);
        var detections = Wmi.Query("SELECT * FROM MSFT_MpThreatDetection", Ns)
            .Select(d => new
            {
                Time = d.Date("InitialDetectionTime"), Threat = names.GetValueOrDefault(d.S("ThreatID") ?? ""),
                Resources = string.Join("; ", d.A("Resources")), Process = d.S("ProcessName"), User = d.S("DomainUser"), Status = d.L("ThreatStatusID")
            })
            .Where(d => d.Time is null || d.Time > since).OrderByDescending(d => d.Time).Take(50)
            .Select(d => new { Time = d.Time?.ToString("s"), d.Threat, d.Resources, d.Process, d.User, d.Status }).ToList();

        foreach (var d in detections)
        {
            bool generic = ctx.Indicators.GenericDetectionSuffixes.Any(s => d.Threat?.EndsWith(s, StringComparison.OrdinalIgnoreCase) == true);
            ctx.Add(generic ? Severity.Medium : Severity.High, "Defender", $"Defender detected {d.Threat}",
                (generic ? "Generic/heuristic detection - this can be a false positive for unsigned or packed software. " : "Named malware family. ") + $"Detected {d.Time}.",
                generic ? "Check that the file was removed and where it came from. If it was software you trust, verify it on VirusTotal."
                        : "Treat this as a real infection: confirm removal, change passwords from another device, and run a full scan.",
                d, ruleId: generic ? "defender.detection-generic" : "defender.detection-named");
        }

        if (status is not null)
        {
            if (status.B("RealTimeProtectionEnabled") == false)
                ctx.Add(Severity.High, "Defender", "Defender real-time protection is OFF", "New threats are not being blocked.", "Turn real-time protection back on in Windows Security.", mitre: "T1562.001", ruleId: "defender.rtp-off");
            if (status.B("AntivirusEnabled") == false && av.Count <= 1)
                ctx.Add(Severity.High, "Defender", "Antivirus is disabled", "No antivirus appears to be protecting this PC.", "Enable Microsoft Defender or install a reputable antivirus.", mitre: "T1562.001", ruleId: "defender.av-off");
            if (status.B("IsTamperProtected") == false)
                ctx.Add(Severity.Medium, "Defender", "Tamper Protection is off", "Malware with admin rights can switch Defender off.", "Enable Tamper Protection in Windows Security > Virus & threat protection settings.", mitre: "T1562.001", ruleId: "defender.tamper-off");
            if (status.L("AntivirusSignatureAge") is long age && age > 3 && age < 10000)
                ctx.Add(Severity.Medium, "Defender", $"Defender definitions are {age} days old", "Recent threats may not be recognised.", "Run Windows Update or 'Check for updates' in Windows Security.", ruleId: "defender.signatures-old");
            if (status.B("BehaviorMonitorEnabled") == false)
                ctx.Add(Severity.Medium, "Defender", "Defender behavior monitoring is off", "", "Turn behavior monitoring back on.", mitre: "T1562.001", ruleId: "defender.behavior-off");
        }
        if (pref is not null)
        {
            if (pref.L("PUAProtection") == 0)
                ctx.Add(Severity.Low, "Defender", "Blocking of potentially unwanted apps (PUA) is off", "Adware and bundled junk software will not be blocked.", "Enable 'Potentially unwanted app blocking' in Windows Security > App & browser control.", ruleId: "defender.pua-off");
            if (pref.L("EnableControlledFolderAccess") == 0)
                ctx.Add(Severity.Info, "Defender", "Ransomware protection (Controlled Folder Access) is off", "", "Consider enabling it in Windows Security > Ransomware protection.", ruleId: "defender.cfa-off");
        }

        return new
        {
            AntivirusProducts = av,
            Status = status is null ? null : new
            {
                AMProductVersion = status.S("AMProductVersion"), AntivirusEnabled = status.B("AntivirusEnabled"),
                RealTimeProtectionEnabled = status.B("RealTimeProtectionEnabled"), BehaviorMonitorEnabled = status.B("BehaviorMonitorEnabled"),
                IsTamperProtected = status.B("IsTamperProtected"), AntivirusSignatureAge = status.L("AntivirusSignatureAge"),
                QuickScanAge = status.L("QuickScanAge"), FullScanAge = status.L("FullScanAge"), NISEnabled = status.B("NISEnabled")
            },
            ASRRulesConfigured = pref?.A("AttackSurfaceReductionRules_Ids").Length,
            Exclusions = exclusions, RecentDetections = detections
        };
    }
}
