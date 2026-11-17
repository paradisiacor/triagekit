using System.Text;
using System.Text.RegularExpressions;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;

namespace TriageKit.Core.SafeStart;

/// <summary>
/// The tricks malware-laced downloads (cracks, "free" software, fake installers) use, as testable rules. Each rule names
/// one concrete thing a person can verify. Rules only look at names and bytes; nothing is executed.
/// </summary>
public static class RedFlags
{
    public sealed record Flag(Severity Severity, string RuleId, Func<string, string> Title, string Why, string Advice);

    private const RegexOptions I = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    /// <summary>"Invoice.pdf.exe", "Movie.mp4.scr": a harmless-looking extension in front of a program extension.</summary>
    public static readonly Regex DoubleExtension = new(@"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|bmp|webp|mp[34]|mkv|avi|mov|wav|flac|zip|rar|7z|iso)[\s_.\-]*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|hta|lnk|msi|cpl|wsf|ps1)$", I);
    /// <summary>File types that run code when double-clicked but that ordinary downloads almost never need.</summary>
    public static readonly Regex RareRunnable = new(@"\.(scr|pif|cpl|hta|vbs|vbe|jse|wsf|wsh)$", I);
    /// <summary>A shortcut that starts a command interpreter or script host.</summary>
    public static readonly Regex ShortcutRunsInterpreter = new(@"\b(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|msiexec|bitsadmin|certutil|curl|conhost)(\.exe)?\b", I);
    /// <summary>Instructions to switch off protection, typical for malware dressed up as a crack.</summary>
    public static readonly Regex DisableAntivirus = new(
        @"(disable|turn\s*off|switch\s*off|deactivate|pause|close|uninstall|stop)\W{0,3}(\w+\W{1,3}){0,5}?(anti\W?virus|defender|windows\s+security|real\W?time\s+protection|smart\W?screen|virus\s*(and|&)\s*threat|firewall|av\b)" +
        @"|add\W{1,3}(\w+\W{1,3}){0,4}?(to|in)\W{1,3}(the\s+)?(exclusions?|exceptions?|whitelist|allow\W?list)" +
        @"|(antivirus|defender|av)\W{1,3}(\w+\W{1,3}){0,4}?(false\s+positive|will\s+(detect|delete|flag)|may\s+(detect|delete|flag))", I);
    /// <summary>Text files worth reading for instructions (readme, nfo, install notes).</summary>
    public static readonly Regex ReadmeName = new(@"(read\W?me|install|instructions?|how\W?to|crack|important|password|info|steps?)[^\\/]*\.(txt|nfo|md|html?|url)$|\.nfo$", I);

    public static IEnumerable<Flag> ForFile(string name, string kind, byte[] data, bool truncated, string signature, string? signer)
    {
        bool signedValid = signature == "valid";
        if (DoubleExtension.IsMatch(name))
            yield return new(Severity.High, "safestart.double-extension", n => $"Program disguised as another file type: {n}",
                "The name ends in a harmless-looking type followed by a program type, so Windows (which often hides extensions) shows it as a document or video.",
                "Don't open it. Real documents and videos never need to run as programs.");
        if (RareRunnable.IsMatch(name) && !signedValid)
            yield return new(Severity.Medium, "safestart.rare-runnable", n => $"Unusual file type that runs code: {n}",
                "Screen savers, control panel items and Windows script files run with your full rights when double-clicked. Normal downloads rarely contain them.",
                "Don't open it unless you know exactly why it's there.");
        if (kind == "Program")
        {
            var known = GamingAccounts.Installers.FirstOrDefault(i => i.Name.IsMatch(name));
            if (known.Name is not null && !(signedValid && signer is not null && known.Signer.IsMatch(signer)))
                yield return new(signedValid ? Severity.High : Severity.High, "safestart.fake-installer", n => $"Fake {known.App} installer: {n}",
                    signedValid ? $"It's named like the official {known.App} installer, but it's signed by \"{signer}\", not by {known.App}'s maker."
                                : $"It's named like the official {known.App} installer, but the real one is always signed by its maker and this one isn't ({signature}).",
                    $"Delete it and download {known.App} only from its official website.");
            if (signature == "modified after signing")
                yield return new(Severity.High, "safestart.tampered", n => $"Program was changed after it was signed: {n}",
                    $"The file carries {signer ?? "a"}'s signature, but its contents no longer match what was signed. That's how legitimate programs get trojanised.",
                    "Don't run it. Get the program from its official source.");
            foreach (var f in Packers(data, signedValid)) yield return f;
        }
        if (kind == "Text" && !truncated && data.Length <= 1024 * 1024 && ReadmeName.IsMatch(name))
        {
            var text = Encoding.UTF8.GetString(data);
            var m = DisableAntivirus.Match(text);
            if (m.Success)
                yield return new(Severity.High, "safestart.disable-av-instructions", n => $"Instructions to switch off your antivirus: {n}",
                    $"It says: \"{Snippet(text, m.Index, m.Length)}\". Real software never needs your protection switched off. This is the most common way malware gets past antivirus.",
                    "Don't follow these instructions and don't run the download. Delete it.");
        }
        if (kind == "Disk image")
            yield return new(Severity.Medium, "safestart.disk-image", n => $"Disk image can't be looked inside: {n}",
                "ISO, IMG and VHD files are a favourite way to slip programs past Windows' download warnings, and TriageKit can't read inside them yet.",
                "Only open it if you trust the source. If you do mount it, check the mounted drive with Safe Start before running anything from it.");
    }

    /// <summary>Programs that are really scripts wrapped into an exe. Info stealers are very often built this way.</summary>
    internal static IEnumerable<Flag> Packers(byte[] pe, bool signedValid)
    {
        if (signedValid) yield break;
        string? what =
            Has(pe, "PYZ-00.pyz"u8) || Has(pe, "pyi-runtime-tmpdir"u8) || Has(pe, "_MEIPASS"u8) ? "Python (PyInstaller)"
            : Has(pe, "AU3!EA06"u8) || Has(pe, ">>>AUTOIT SCRIPT<<<"u8) ? "AutoIt"
            : Has(pe, "pkg/prelude/bootstrap.js"u8) ? "Node.js (pkg)"
            : Has(pe, "__nuitka"u8) || Has(pe, "NUITKA_ONEFILE_PARENT"u8) ? "Python (Nuitka)"
            : null;
        if (what is not null)
            yield return new(Severity.Medium, "safestart.packed-script", n => $"Script packed into an unsigned program: {n}",
                $"This program is a {what} script wrapped into an .exe and isn't signed. Most info stealers that target gamers are built exactly like this.",
                "Only run it if you trust its author and expected a tool like this.");
    }

    /// <summary>End of the PE image (end of the last section's raw data); anything after it is "overlay".</summary>
    public static long PeImageEnd(byte[] pe)
    {
        try
        {
            if (pe.Length < 0x40 || pe[0] != 'M' || pe[1] != 'Z') return -1;
            int nt = BitConverter.ToInt32(pe, 0x3C);
            if (nt <= 0 || nt + 24 > pe.Length || BitConverter.ToUInt32(pe, nt) != 0x00004550) return -1;
            int sections = BitConverter.ToUInt16(pe, nt + 6);
            int optSize = BitConverter.ToUInt16(pe, nt + 20);
            int table = nt + 24 + optSize;
            long end = 0;
            for (int i = 0; i < sections && table + (i + 1) * 40 <= pe.Length; i++)
            {
                int sh = table + i * 40;
                long raw = BitConverter.ToUInt32(pe, sh + 20), size = BitConverter.ToUInt32(pe, sh + 16);
                end = Math.Max(end, raw + size);
            }
            return end;
        }
        catch { return -1; }
    }

    public static bool MostlyOneByte(ReadOnlySpan<byte> d)
    {
        if (d.Length == 0) return false;
        Span<int> counts = stackalloc int[256];
        foreach (var b in d) counts[b]++;
        int max = 0; foreach (var c in counts) max = Math.Max(max, c);
        return max * 100 >= d.Length * 95;
    }

    internal static void Padded(DownloadCheck.Item item, long size, long imageEnd, DownloadCheck owner) =>
        owner.Flag(item, Severity.High, "safestart.padded", $"Program padded to an unusual size: {DownloadCheck.Short(item.Path)}",
            $"{item.Path}\nThe program is {size / (1024 * 1024):N0} MB, but {(size - imageEnd) / (1024 * 1024):N0} MB of that is filler added after the real program. Malware does this so it's too big for antivirus cloud scans and upload sites.",
            "Don't run it. Real games and installers keep their data in separate files, not as filler inside the .exe.");

    private static bool Has(byte[] d, ReadOnlySpan<byte> needle) => d.AsSpan().IndexOf(needle) >= 0;

    private static string Snippet(string text, int index, int length)
    {
        int from = Math.Max(0, index - 30), to = Math.Min(text.Length, index + length + 40);
        return Regex.Replace(text[from..to], @"\s+", " ").Trim();
    }
}
