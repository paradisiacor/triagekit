using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace TriageKit.Core.Yara;

/// <summary>
/// Reads inside ZIP-based files (ZIP, Office Open XML) entirely in memory. Nothing is ever written to disk and
/// entry names are never used as file paths. Hard limits stop zip bombs and huge archives.
/// </summary>
public static class ZipContents
{
    public const int MaxDepth = 3;
    public const int MaxEntries = 10_000;
    public const long MaxTotalBytes = 200L * 1024 * 1024;
    public const long MaxEntryBytes = 32L * 1024 * 1024;
    public const double MaxRatio = 200;

    public sealed record Entry(string Name, byte[] Data);
    public sealed class Budget { public int Entries; public long Bytes; public bool LimitHit; public bool Encrypted; public string? LimitReason; }

    public static bool IsZip(ReadOnlySpan<byte> d) => d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4;

    /// <summary>Entries whose names match <paramref name="want"/>, recursing into nested ZIPs.</summary>
    public static IEnumerable<Entry> Read(Stream zip, Func<string, bool> want, Budget budget, CancellationToken ct, string prefix = "", int depth = 1)
    {
        // Read the entry count from the end of the file before .NET builds its entry list in memory.
        var declared = DeclaredEntries(zip);
        if (declared > MaxEntries) { budget.LimitHit = true; budget.LimitReason = $"{declared:N0} entries (limit {MaxEntries:N0})"; yield break; }
        ZipArchive archive;
        try { archive = new ZipArchive(zip, ZipArchiveMode.Read, leaveOpen: true); }
        catch (InvalidDataException) { yield break; }
        using (archive)
        {
            foreach (var e in archive.Entries)
            {
                if (ct.IsCancellationRequested) yield break;
                if (++budget.Entries > MaxEntries) { budget.LimitHit = true; budget.LimitReason = "too many entries"; yield break; }
                if (e.FullName.EndsWith('/')) continue;
                bool nested = e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && depth < MaxDepth;
                if (!nested && !want(e.Name)) continue;
                if (e.Length > MaxEntryBytes || (e.CompressedLength > 0 && e.Length > 1_000_000 && (double)e.Length / e.CompressedLength > MaxRatio))
                { budget.LimitHit = true; budget.LimitReason = $"{e.FullName} is too large or too compressed"; continue; }
                byte[]? data = null;
                try
                {
                    using var s = e.Open();
                    data = ReadLimited(s, MaxEntryBytes, budget);
                }
                catch (InvalidDataException) { budget.Encrypted = true; }   // encrypted or unsupported method
                catch (NotSupportedException) { budget.Encrypted = true; }
                if (data is null) continue;
                var name = prefix + e.FullName;
                if (nested && IsZip(data))
                {
                    using var ms = new MemoryStream(data, writable: false);
                    foreach (var inner in Read(ms, want, budget, ct, name + " » ", depth + 1)) yield return inner;
                    continue;
                }
                if (want(e.Name)) yield return new Entry(name, data);
            }
        }
    }

    /// <summary>Entry count from the end-of-central-directory record (ZIP64 aware), or -1 if it can't be read.</summary>
    public static long DeclaredEntries(Stream s)
    {
        try
        {
            if (!s.CanSeek || s.Length < 22) return -1;
            long start = s.Position;
            int tail = (int)Math.Min(s.Length, 65_557);
            var buf = new byte[tail];
            s.Seek(-tail, SeekOrigin.End);
            s.ReadExactly(buf);
            s.Position = start;
            for (int i = tail - 22; i >= 0; i--)
            {
                if (buf[i] != 0x50 || buf[i + 1] != 0x4B || buf[i + 2] != 0x05 || buf[i + 3] != 0x06) continue;
                long n = BitConverter.ToUInt16(buf, i + 10);
                if (n != 0xFFFF) return n;
                // ZIP64: locator sits 20 bytes before the EOCD and points at the ZIP64 EOCD record.
                int loc = i - 20;
                if (loc < 0 || BitConverter.ToUInt32(buf, loc) != 0x07064b50) return -1;
                long z64 = (long)BitConverter.ToUInt64(buf, loc + 8);
                var rec = new byte[56];
                s.Seek(z64, SeekOrigin.Begin); s.ReadExactly(rec); s.Position = start;
                return BitConverter.ToUInt32(rec, 0) == 0x06064b50 ? (long)BitConverter.ToUInt64(rec, 32) : -1;
            }
            return -1;
        }
        catch { return -1; }
    }

    private static byte[]? ReadLimited(Stream s, long max, Budget budget)
    {
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        int n;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            ms.Write(buf, 0, n);
            budget.Bytes += n;
            if (ms.Length > max || budget.Bytes > MaxTotalBytes) { budget.LimitHit = true; budget.LimitReason ??= "expanded size limit reached"; return null; }
        }
        return ms.ToArray();
    }
}

/// <summary>
/// Pulls VBA macro source out of Office files (vbaProject.bin inside OOXML, or legacy .doc/.xls) by finding the
/// compressed module streams and decompressing them (MS-OVBA 2.4.1). Best effort: fragmented streams in large
/// legacy files may decompress partly, which is fine for keyword checks.
/// </summary>
public static class VbaMacros
{
    private static readonly byte[] Marker = Encoding.ASCII.GetBytes("\0Attribut");

    public static bool IsOle(ReadOnlySpan<byte> d) => d.Length >= 8 && d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0;

    public static List<string> ExtractSources(byte[] data, int maxModules = 64)
    {
        var sources = new List<string>();
        int from = 0;
        while (sources.Count < maxModules)
        {
            int idx = data.AsSpan(from).IndexOf(Marker);
            if (idx < 0) break;
            idx += from;
            int start = idx - 3;   // signature byte 0x01, 2-byte chunk header, then the flag byte (the \0 of the marker)
            if (start >= 0 && data[start] == 0x01)
            {
                var text = Decompress(data, start);
                if (text.Length > 10) sources.Add(text);
            }
            from = idx + Marker.Length;
        }
        return sources;
    }

    public static string Decompress(byte[] d, int pos)
    {
        var outp = new List<byte>(4096);
        if (pos >= d.Length || d[pos] != 0x01) return "";
        pos++;
        while (pos + 2 <= d.Length && outp.Count < 4_000_000)
        {
            int header = d[pos] | (d[pos + 1] << 8);
            int size = (header & 0x0FFF) + 3;
            bool compressed = (header & 0x8000) != 0;
            if (((header >> 12) & 0x7) != 0b011) break;   // signature bits must be 011
            int chunkStart = pos + 2, chunkEnd = Math.Min(d.Length, pos + size);
            int decompStart = outp.Count;
            if (!compressed)
            {
                for (int i = chunkStart; i < chunkEnd && i < chunkStart + 4096; i++) outp.Add(d[i]);
                pos = chunkEnd; continue;
            }
            int p = chunkStart;
            while (p < chunkEnd)
            {
                byte flags = d[p++];
                for (int bit = 0; bit < 8 && p < chunkEnd; bit++)
                {
                    if ((flags & (1 << bit)) == 0) { outp.Add(d[p++]); continue; }
                    if (p + 1 >= chunkEnd) { p = chunkEnd; break; }
                    int token = d[p] | (d[p + 1] << 8); p += 2;
                    int dpos = outp.Count - decompStart;
                    int bitCount = Math.Max(BitCount(dpos), 4);
                    int lengthMask = 0xFFFF >> bitCount;
                    int offset = (token >> (16 - bitCount)) + 1;
                    int length = (token & lengthMask) + 3;
                    int src = outp.Count - offset;
                    if (src < decompStart) return Encoding.Latin1.GetString(outp.ToArray());
                    for (int k = 0; k < length; k++) outp.Add(outp[src + k]);
                }
            }
            pos = chunkEnd;
        }
        return Encoding.Latin1.GetString(outp.ToArray());
    }

    private static int BitCount(int dpos)
    {
        int bits = 0; int v = dpos - 1;
        while (v > 0) { bits++; v >>= 1; }
        return bits;
    }

    private static readonly Regex AutoExec = new(@"\b(Auto_?Open|AutoExec|AutoClose|Document_Open|Document_Close|DocumentOpen|Workbook_Open|Workbook_Activate|Auto_Close|Presentation_Open)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Suspicious = new(@"\b(Shell(Execute)?|WScript\.Shell|CreateObject|URLDownloadToFile|XMLHTTP|WinHttp|ADODB\.Stream|powershell|cmd(\.exe)?\s*/c|mshta|regsvr32|rundll32|certutil|bitsadmin|CallByName|Environ|VirtualAlloc|RtlMoveMemory|CreateThread|Chr[BW]?\$?\(|StrReverse|FromBase64String|-enc(odedcommand)?)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed record Verdict(bool HasMacros, List<string> AutoExec, List<string> Suspicious);

    public static Verdict Analyse(IEnumerable<string> sources)
    {
        var list = sources.ToList();
        var auto = list.SelectMany(s => AutoExec.Matches(s).Select(m => m.Value)).Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
        var sus = list.SelectMany(s => Suspicious.Matches(s).Select(m => m.Value.Trim())).Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToList();
        return new Verdict(list.Count > 0, auto, sus);
    }
}

/// <summary>Minimal Windows shortcut (.lnk) reader: target path and command-line arguments (MS-SHLLINK).</summary>
public static class Shortcut
{
    public sealed record Info(string? Target, string? Arguments, string? WorkingDir, string? Icon);

    public static Info? Parse(byte[] d)
    {
        try
        {
            if (d.Length < 0x4C || BitConverter.ToInt32(d, 0) != 0x4C) return null;
            uint flags = BitConverter.ToUInt32(d, 0x14);
            bool hasIdList = (flags & 0x1) != 0, hasLinkInfo = (flags & 0x2) != 0, hasName = (flags & 0x4) != 0, hasRel = (flags & 0x8) != 0,
                 hasWork = (flags & 0x10) != 0, hasArgs = (flags & 0x20) != 0, hasIcon = (flags & 0x40) != 0, unicode = (flags & 0x80) != 0;
            int p = 0x4C;
            if (hasIdList) p += 2 + BitConverter.ToUInt16(d, p);
            string? target = null;
            if (hasLinkInfo)
            {
                int size = BitConverter.ToInt32(d, p);
                int infoFlags = BitConverter.ToInt32(d, p + 8);
                if ((infoFlags & 1) != 0)
                {
                    int baseOff = BitConverter.ToInt32(d, p + 16);
                    target = ReadAnsiZ(d, p + baseOff);
                }
                p += size;
            }
            string? Next(bool present)
            {
                if (!present) return null;
                int count = BitConverter.ToUInt16(d, p); p += 2;
                int bytes = unicode ? count * 2 : count;
                var s = unicode ? Encoding.Unicode.GetString(d, p, bytes) : Encoding.Latin1.GetString(d, p, bytes);
                p += bytes; return s;
            }
            Next(hasName);
            var rel = Next(hasRel);
            var work = Next(hasWork);
            var args = Next(hasArgs);
            var icon = Next(hasIcon);
            return new Info(target ?? rel, args, work, icon);
        }
        catch (ArgumentException) { return null; }
        catch (IndexOutOfRangeException) { return null; }
    }

    private static string ReadAnsiZ(byte[] d, int p)
    {
        int end = Array.IndexOf(d, (byte)0, p);
        if (end < 0) end = d.Length;
        return Encoding.Latin1.GetString(d, p, end - p);
    }

    private static readonly Regex Lolbin = new(@"\\(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|conhost)\.exe$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex BadArgs = new(@"(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|-w(indowstyle)?\s+h(idden)?|iex\b|invoke-expression|downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|http[s]?://|frombase64string|\\\\[^\\]+\\[^\\]+\\|javascript:|vbscript:|\.(hta|vbs|js|jse|ps1)\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Why a shortcut looks dangerous, or null if it doesn't.</summary>
    public static string? Assess(Info i)
    {
        var target = i.Target ?? "";
        var args = i.Arguments ?? "";
        bool lol = Lolbin.IsMatch(target);
        var bad = BadArgs.Match(args);
        if (lol && bad.Success) return $"opens {Path.GetFileName(target)} with suspicious arguments ({bad.Value.Trim()})";
        if (lol && args.Length > 250) return $"opens {Path.GetFileName(target)} with a very long hidden command line ({args.Length} characters)";
        if (args.Length > 1024) return $"has an unusually long command line ({args.Length} characters)";
        return null;
    }
}
