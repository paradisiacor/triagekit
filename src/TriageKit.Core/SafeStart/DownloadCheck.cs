using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TriageKit.Core.Checks;
using TriageKit.Core.Engine;
using TriageKit.Core.Intel;
using TriageKit.Core.Reputation;
using TriageKit.Core.Yara;

namespace TriageKit.Core.SafeStart;

/// <summary>
/// Safe Start › Check a download: inspects a downloaded file, folder or archive WITHOUT running anything in it.
/// Archives (ZIP, RAR, 7z, TAR, GZip) are read in memory, also inside each other; nothing is extracted to disk.
/// Every program and script gets: signature check (in memory for archive members), the built-in malware rules,
/// red-flag heuristics typical for malware-laced downloads (cracks, fake installers, padded loaders, "disable your
/// antivirus" readmes) and, if the user allowed online lookups, a hash reputation lookup.
/// The verdict is honest about what couldn't be checked (password-protected or oversized content).
/// </summary>
public sealed class DownloadCheck
{
    public const int MaxFiles = 25_000;
    public const long MaxInspectBytes = 96L * 1024 * 1024;     // bytes of one file read for rules and heuristics
    public const long MaxArchiveBytes = 8L * 1024 * 1024 * 1024; // archives bigger than this are listed, not opened
    public const int MaxArchiveDepth = 4;
    public static readonly TimeSpan Budget = TimeSpan.FromMinutes(15);

    public enum Verdict { NoThreatsFound, Suspicious, Dangerous, KnownMalware }

    public sealed class Item
    {
        public required string Path { get; init; }             // display path; archive members as "archive.zip » folder/file.exe"
        public required string Kind { get; init; }             // Program, Script, Shortcut, Document, Archive, Disk image, Text, Other
        public long Size { get; init; }
        public string? SHA256 { get; set; }
        public string? Signer { get; set; }
        public string Signature { get; set; } = "n/a";
        public string Risk { get; set; } = "Info";             // Info, Low, Medium, High, Critical
        public List<string> Reasons { get; } = new();
        public string? Note { get; set; }                      // e.g. "too large to inspect"
    }

    public sealed class Result
    {
        public required string Target { get; init; }
        public string Name => System.IO.Path.GetFileName(Target.TrimEnd('\\', '/'));
        public DateTime Started { get; init; }
        public double Seconds { get; set; }
        public Verdict Verdict { get; set; }
        public string Headline { get; set; } = "";
        public string Summary { get; set; } = "";
        public string? DownloadedFrom { get; set; }
        public int Files { get; set; }
        public int Programs { get; set; }
        public int Archives { get; set; }
        public bool OnlineLookups { get; set; }
        public List<string> NotChecked { get; } = new();       // honest coverage gaps
        public List<Item> Items { get; } = new();
        public List<Finding> Findings { get; } = new();
        public bool Stopped { get; set; }
        /// <summary>Files without remarks that were checked but left out of the list to keep it readable.</summary>
        public int ListedItemsCut { get; set; }
    }

    private readonly CheckContext _ctx;
    private readonly YaraScanner _yara;
    private readonly IReadOnlyList<IReputationProvider> _providers;
    private readonly Action<string>? _progress;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private Result _r = null!;
    private readonly List<(Item Item, FileIntel Intel)> _lookups = new();

    public DownloadCheck(CheckContext ctx, IReadOnlyList<IReputationProvider>? providers = null, Action<string>? progress = null, IEnumerable<YaraRule>? rules = null)
    {
        _ctx = ctx; _providers = providers ?? Array.Empty<IReputationProvider>(); _progress = progress;
        _yara = new YaraScanner(rules ?? YaraRuleSet.LoadBuiltIn());
    }

    public Result Run(string target)
    {
        _r = new Result { Target = Path.GetFullPath(target), Started = DateTime.Now };
        if (File.Exists(target))
        {
            _r.DownloadedFrom = GamingAccounts.DownloadOrigin(target);
            InspectDiskFile(new FileInfo(target), Path.GetFileName(target));
        }
        else if (Directory.Exists(target)) InspectFolder(target);
        else throw new FileNotFoundException("The file or folder doesn't exist.", target);

        Lookups();
        Conclude();
        _r.Seconds = Math.Round(_clock.Elapsed.TotalSeconds, 1);
        return _r;
    }

    private bool OutOfTime()
    {
        if (_ctx.Cancellation.IsCancellationRequested) { _r.Stopped = true; return true; }
        if (_clock.Elapsed > Budget) { if (!_r.NotChecked.Contains("Time limit reached")) _r.NotChecked.Add("Time limit reached: the rest wasn't checked"); return true; }
        if (_r.Files >= MaxFiles) { if (!_r.NotChecked.Any(n => n.StartsWith("More than"))) _r.NotChecked.Add($"More than {MaxFiles:N0} files: the rest wasn't checked"); return true; }
        return false;
    }

    // ------------------------------------------------------------------ walking
    private void InspectFolder(string root)
    {
        var stack = new Stack<string>(); stack.Push(root);
        while (stack.Count > 0 && !OutOfTime())
        {
            var dir = stack.Pop();
            IEnumerable<string> files, dirs;
            try { files = Directory.EnumerateFiles(dir).ToList(); dirs = Directory.EnumerateDirectories(dir).ToList(); }
            catch (Exception ex) { _r.NotChecked.Add($"{Rel(root, dir)}: {ex.Message}"); continue; }
            foreach (var d in dirs)
            {
                try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }   // don't follow links out of the folder
                stack.Push(d);
            }
            foreach (var f in files) { if (OutOfTime()) break; InspectDiskFile(new FileInfo(f), Rel(root, f)); }
        }
    }

    private static string Rel(string root, string path) => Path.GetRelativePath(Path.GetDirectoryName(root.TrimEnd('\\', '/')) ?? root, path);

    private void InspectDiskFile(FileInfo fi, string shown)
    {
        _r.Files++;
        _progress?.Invoke(shown);
        if ((fi.Attributes & FileAttributes.Offline) != 0 || (fi.Attributes & (FileAttributes)0x400000) != 0)   // cloud placeholder: reading would download it
        { _r.NotChecked.Add($"{shown}: online-only file (not downloaded)"); return; }
        byte[] head;
        try { using var fs = Open(fi.FullName); head = ReadUpTo(fs, Math.Min(fi.Length, MaxInspectBytes)); }
        catch (Exception ex) { _r.NotChecked.Add($"{shown}: {ex.Message}"); return; }
        var kind = Classify(fi.Name, head);
        if (kind == "Archive")
        {
            _r.Archives++;
            var arch = new Item { Path = shown, Kind = kind, Size = fi.Length };
            Archive(arch, () => Open(fi.FullName), fi.Length, shown, 1);
            Add(arch);
            return;
        }
        var item = new Item { Path = shown, Kind = kind, Size = fi.Length };
        if (IsExecutable(kind))
        {
            _r.Programs++;
            var intel = _ctx.Files.Get(fi.FullName);   // WinVerifyTrust incl. catalogs, full-file SHA-256
            if (intel is not null)
            {
                item.SHA256 = intel.SHA256; item.Signer = intel.Signer; item.Signature = Describe(intel.SignatureStatus);
                if (kind == "Program") _lookups.Add((item, intel));
            }
            else item.SHA256 = Sha256(fi.FullName);
            if (kind == "Program" && fi.Length > MaxInspectBytes) PaddingCheck(item, fi.FullName, fi.Length);
        }
        else if (kind is "Document" or "Shortcut" or "Text" or "Disk image") item.SHA256 = fi.Length <= MaxInspectBytes ? Convert.ToHexString(SHA256.HashData(head)) : null;
        Analyse(item, fi.Name, head, fi.Length > head.Length, onDisk: true);
        Add(item);
    }

    private void Archive(Item arch, Func<Stream> open, long size, string shown, int depth)
    {
        if (depth > MaxArchiveDepth) { arch.Note = "archive nested too deep"; _r.NotChecked.Add($"{shown}: archives nested more than {MaxArchiveDepth} levels deep"); return; }
        if (size > MaxArchiveBytes) { arch.Note = "too large to open"; _r.NotChecked.Add($"{shown}: archive larger than {MaxArchiveBytes / (1024 * 1024 * 1024)} GB"); return; }
        int encrypted = 0, encryptedPrograms = 0;
        try
        {
            using var s = open();
            foreach (var e in ArchiveReader.Entries(s, _ctx.Cancellation, shown.Split(" » ")[^1]))
            {
                if (OutOfTime()) break;
                var name = e.Name.Replace('\\', '/');
                var display = $"{shown} » {name}";
                if (e.Encrypted)
                {
                    encrypted++;
                    if (Regex.IsMatch(name, @"\.(exe|scr|com|dll|msi|bat|cmd|ps1|vbs|js|hta|lnk)$", RegexOptions.IgnoreCase)) encryptedPrograms++;
                    continue;
                }
                _r.Files++;
                _progress?.Invoke(display);
                byte[] data;
                long full = e.Size;
                string? sha = null, cut = null;
                try { (data, sha, full, cut) = e.Read(MaxInspectBytes); }
                catch (Exception ex) { _r.NotChecked.Add($"{display}: {ex.Message}"); continue; }
                if (cut is not null) { _r.NotChecked.Add($"{display}: {cut}, only the start was checked"); if (full <= data.Length) full = data.Length + 1; }
                var kind = Classify(name, data);
                if (kind == "Archive")
                {
                    _r.Archives++;
                    var inner = new Item { Path = display, Kind = kind, Size = full, SHA256 = sha };
                    if (full > data.Length) { inner.Note = "too large to open inside the archive"; _r.NotChecked.Add($"{display}: archive inside an archive larger than {MaxInspectBytes / (1024 * 1024)} MB"); }
                    else Archive(inner, () => new MemoryStream(data, writable: false), data.Length, display, depth + 1);
                    Add(inner);
                    continue;
                }
                var item = new Item { Path = display, Kind = kind, Size = full, SHA256 = sha };
                if (IsExecutable(kind))
                {
                    _r.Programs++;
                    if (kind == "Program")
                    {
                        if (full <= data.Length)
                        {
                            var sig = PeSignature.Verify(data);
                            item.Signer = sig.Signer; item.Signature = Describe(sig.State);
                            if (sha is not null) _lookups.Add((item, new FileIntel { Path = display, SHA256 = sha, Signer = sig.Signer,
                                SignatureStatus = sig.State == PeSignature.State.Valid ? SignatureStatus.Valid : sig.State == PeSignature.State.NotSigned ? SignatureStatus.NotSigned : SignatureStatus.HashMismatch }));
                        }
                        else { item.Signature = "not checked (too large)"; PaddingFromHead(item, data, full); }
                    }
                }
                Analyse(item, Path.GetFileName(name), data, full > data.Length, onDisk: false);
                Add(item);
            }
        }
        catch (ArchiveReader.UnsupportedException ex) { arch.Note = ex.Message; _r.NotChecked.Add($"{shown}: {ex.Message}"); }
        catch (Exception ex) when (ex is not OperationCanceledException) { arch.Note = "couldn't be read completely"; _r.NotChecked.Add($"{shown}: couldn't be read completely ({ex.Message})"); }
        if (encrypted > 0)
        {
            arch.Note = $"{encrypted} password-protected file(s)";
            _r.NotChecked.Add($"{shown}: {encrypted} password-protected file(s) can't be checked");
            if (encryptedPrograms > 0)
                Flag(arch, Severity.Medium, "safestart.encrypted-programs", $"Password-protected programs inside: {Path.GetFileName(shown.Split(" » ")[^1])}",
                     $"{shown}\n{encryptedPrograms} program(s) or script(s) are locked with a password, so neither TriageKit nor your antivirus can look inside until you unpack them. Malware is often delivered this way on purpose.",
                     "Unpack it into a new folder (don't run anything yet), then check that folder with Safe Start.");
        }
    }

    // ------------------------------------------------------------------ judging one file
    private void Analyse(Item item, string fileName, byte[] data, bool truncated, bool onDisk)
    {
        var name = fileName;
        // 1. Malware rules
        if (item.Kind is "Program" or "Script" or "Shortcut" or "Document" || data.Length < 4 * 1024 * 1024)
        {
            bool isPe = data.Length > 1 && data[0] == 'M' && data[1] == 'Z';
            foreach (var m in _yara.Scan(data, _ctx.Options.RuleBudgetPerFile, _ctx.Cancellation, out _))
            {
                var target = m.Rule.Meta.GetValueOrDefault("target", "any");
                if (target == "pe" && !isPe || target == "script" && isPe) continue;
                var sev = Enum.TryParse<Severity>(m.Rule.Meta.GetValueOrDefault("severity", "medium"), true, out var s) ? s : Severity.Medium;
                var desc = m.Rule.Meta.GetValueOrDefault("description", m.Rule.Name);
                Flag(item, sev, "yara." + m.Rule.Name, $"{desc}: {Short(item.Path)}", $"{item.Path}\nRule: {m.Rule.Name}",
                     "Don't run it. Delete the download and get the program from its official website or store.", m.Rule.Meta.GetValueOrDefault("mitre"));
            }
        }
        // 2. Red flags
        var flags = RedFlags.ForFile(name, item.Kind, data, truncated, item.Signature, item.Signer);
        foreach (var f in flags) Flag(item, f.Severity, f.RuleId, f.Title(Short(item.Path)), $"{item.Path}\n{f.Why}", f.Advice);
        // 3. Shortcuts: where they really point
        if (item.Kind == "Shortcut" && Yara.Shortcut.Parse(data) is { } lnk)
        {
            var cmd = $"{lnk.Target} {lnk.Arguments}".Trim();
            if (RedFlags.ShortcutRunsInterpreter.IsMatch(cmd))
                Flag(item, Severity.High, "safestart.lnk-command", $"Shortcut runs a hidden command: {Short(item.Path)}",
                     $"{item.Path}\nTarget: {Trunc(cmd, 300)}\nA shortcut in a download that starts PowerShell, cmd or a script host is a common way to infect a PC.",
                     "Don't open it. Delete the download.");
        }
        // 4. Office macros
        if (item.Kind == "Document" && !truncated)
        {
            var sources = new List<string>();
            if (VbaMacros.IsOle(data)) sources.AddRange(VbaMacros.ExtractSources(data));
            else if (ZipContents.IsZip(data))
                foreach (var e in ZipContents.Read(new MemoryStream(data), n => n.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase), new ZipContents.Budget(), _ctx.Cancellation))
                    sources.AddRange(VbaMacros.ExtractSources(e.Data));
            if (sources.Count > 0)
            {
                var v = VbaMacros.Analyse(sources);
                if (v.AutoExec.Count > 0 && v.Suspicious.Count > 0)
                    Flag(item, Severity.High, "safestart.macro", $"Document runs code when opened: {Short(item.Path)}",
                         $"{item.Path}\nStarts automatically ({string.Join(", ", v.AutoExec.Take(3))}) and uses {string.Join(", ", v.Suspicious.Take(4))}.",
                         "Don't open it, and never click \"Enable content\".");
                else if (v.HasMacros)
                    Flag(item, Severity.Low, "safestart.macro-present", $"Document contains macros: {Short(item.Path)}", item.Path,
                         "Only enable macros if you trust the sender and expected them.");
            }
        }
        if (truncated && item.Kind is "Script" or "Document") item.Note ??= $"only the first {MaxInspectBytes / (1024 * 1024)} MB were checked";
    }

    private void PaddingCheck(Item item, string path, long size)
    {
        try
        {
            using var fs = Open(path);
            var head = ReadUpTo(fs, Math.Min(size, 4 * 1024 * 1024));
            var imageEnd = RedFlags.PeImageEnd(head);
            if (imageEnd <= 0 || size - imageEnd < size / 2) return;
            // Sample the overlay: padding is long runs of the same byte (usually zeros).
            int same = 0, samples = 0; var buf = new byte[4096];
            for (long pos = imageEnd; pos < size && samples < 64; pos += Math.Max(4096, (size - imageEnd) / 64))
            {
                fs.Position = pos; int n = fs.Read(buf, 0, buf.Length); if (n <= 0) break;
                samples++; if (RedFlags.MostlyOneByte(buf.AsSpan(0, n))) same++;
            }
            if (samples > 0 && same * 10 >= samples * 9) RedFlags.Padded(item, size, imageEnd, this);
        }
        catch { }
    }

    private void PaddingFromHead(Item item, byte[] head, long full)
    {
        var imageEnd = RedFlags.PeImageEnd(head);
        if (imageEnd > 0 && full - imageEnd >= full / 2 && head.Length > imageEnd + 4096 && RedFlags.MostlyOneByte(head.AsSpan((int)imageEnd, Math.Min(65536, head.Length - (int)imageEnd))))
            RedFlags.Padded(item, full, imageEnd, this);
    }

    internal void Flag(Item item, Severity sev, string ruleId, string title, string detail, string advice, string? mitre = null)
    {
        item.Reasons.Add(title);
        if (Rank(sev.ToString()) > Rank(item.Risk)) item.Risk = sev.ToString();
        _r.Findings.Add(new Finding { Severity = sev, Category = "Safe Start", Title = title, Detail = detail, Recommendation = advice, RuleId = ruleId, Mitre = mitre, Module = "safestart" });
    }

    // ------------------------------------------------------------------ reputation
    private void Lookups()
    {
        var todo = _lookups.Where(x => x.Intel.SHA256 is not null && x.Item.Signature != "valid").GroupBy(x => x.Intel.SHA256).Select(g => g.First()).ToList();
        if (todo.Count == 0) return;
        foreach (var p in _providers)
        {
            if (_ctx.Cancellation.IsCancellationRequested) break;
            bool local = p is DefenderFileScanProvider;
            bool available; try { available = p.IsAvailable(_ctx); } catch { available = false; }   // online providers are off unless the user allowed lookups
            if (!available) continue;
            if (!local) _r.OnlineLookups = true;
            // Defender scans files on disk only; archive members are covered by the hash lookups.
            var files = todo.Where(x => !local || File.Exists(x.Intel.Path)).Take(Math.Max(0, p.MaxLookups(_ctx))).ToList();
            if (files.Count == 0) continue;
            IReadOnlyDictionary<string, ProviderVerdict>? batch = null;
            try { batch = p.LookupBatch(files.Select(f => f.Intel).ToList(), _ctx); } catch { }
            foreach (var (item, intel) in files)
            {
                if (_ctx.Cancellation.IsCancellationRequested) break;
                ProviderVerdict v;
                try { v = batch is not null ? (batch.TryGetValue(intel.SHA256!, out var b) ? b : new ProviderVerdict { Provider = p.Name }) : p.Lookup(intel, _ctx); }
                catch { continue; }
                if (v.Verdict == Reputation.Verdict.Malicious && !v.Generic)
                    Flag(item, Severity.Critical, "safestart.known-malware", $"{Short(item.Path)} is known malware{(v.Label is null ? "" : $" ({v.Label})")}",
                         $"{item.Path}\nIdentified by: {v.Provider}{(v.Detail is null ? "" : "\n" + v.Detail)}",
                         "Don't run it. Delete the whole download. If you already ran it, run a full TriageKit check and change your passwords from another device.", "T1204.002");
                else if (v.Verdict is Reputation.Verdict.Malicious or Reputation.Verdict.Suspicious)
                    Flag(item, Severity.High, "safestart.flagged", $"{Short(item.Path)} is flagged as suspicious",
                         $"{item.Path}\nFlagged by: {v.Provider}{(v.Feed is null ? "" : $" (listed in {v.Feed})")}{(v.Label is null ? "" : $": {v.Label}")}",
                         "Don't run it unless you're sure where it came from.", "T1204.002");
                if (!local && batch is null && p.Delay(_ctx) > TimeSpan.Zero) Thread.Sleep(p.Delay(_ctx));
            }
        }
    }

    // ------------------------------------------------------------------ verdict
    private void Conclude()
    {
        var worst = _r.Findings.Count == 0 ? Severity.Info : _r.Findings.Min(f => f.Severity);   // Severity: Critical = 0 … Info = 4
        bool known = _r.Findings.Any(f => f.RuleId == "safestart.known-malware");
        _r.Verdict = known ? Verdict.KnownMalware : worst <= Severity.High ? Verdict.Dangerous : worst == Severity.Medium ? Verdict.Suspicious : Verdict.NoThreatsFound;
        if (_r.Stopped) _r.NotChecked.Insert(0, "Stopped before the end: the rest wasn't checked");
        bool gaps = _r.NotChecked.Count > 0;
        (_r.Headline, _r.Summary) = _r.Verdict switch
        {
            Verdict.KnownMalware => ("Known malware. Don't run it.", "At least one file is identified as malware. Delete the whole download."),
            Verdict.Dangerous => ("Dangerous. Don't run it.", "TriageKit found signs that this download is built to infect the PC. Get the program from its official website or store instead."),
            Verdict.Suspicious => ("Suspicious. Be careful.", "Some things here are unusual or couldn't be checked. Only run it if you trust where it came from."),
            _ => gaps
                ? ("No threats found in what could be checked.", "Some parts couldn't be checked (see below), so this isn't a clean bill of health.")
                : ("No threats found.", "Nothing here matches known malware or the usual tricks. That lowers the risk, but no check can prove a download is safe."),
        };
        if (_r.Programs > 0 && _r.Verdict == Verdict.NoThreatsFound)
            _r.Summary += " Tip: use Install Watch when you install it, to see exactly what it changes.";
        _r.Items.Sort((a, b) => Rank(b.Risk).CompareTo(Rank(a.Risk)));
        // Keep the result light for big folders: every file with a remark, then the rest up to a limit.
        const int keep = 3000;
        if (_r.Items.Count > keep)
        {
            var remarks = _r.Items.Where(i => i.Reasons.Count > 0 || i.Note is not null).ToList();
            var rest = _r.Items.Where(i => i.Reasons.Count == 0 && i.Note is null).Take(Math.Max(0, keep - remarks.Count)).ToList();
            _r.ListedItemsCut = _r.Items.Count - remarks.Count - rest.Count;
            _r.Items.Clear(); _r.Items.AddRange(remarks); _r.Items.AddRange(rest);
        }
    }

    // ------------------------------------------------------------------ helpers
    private void Add(Item item) => _r.Items.Add(item);

    internal static int Rank(string risk) => risk switch { "Critical" => 4, "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };
    private static bool IsExecutable(string kind) => kind is "Program" or "Script" or "Shortcut";
    internal static string Short(string display) { var last = display.Split(" » ")[^1]; return last.Replace('\\', '/').Split('/')[^1]; }
    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";
    private static FileStream Open(string p) => new(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
    private static string? Sha256(string p) { try { using var fs = Open(p); return Convert.ToHexString(SHA256.HashData(fs)); } catch { return null; } }

    internal static byte[] ReadUpTo(Stream s, long max)
    {
        var buf = new byte[max];
        int total = 0;
        while (total < max) { int n = s.Read(buf, total, (int)Math.Min(1 << 20, max - total)); if (n <= 0) break; total += n; }
        return total == buf.Length ? buf : buf[..total];
    }

    internal static string Describe(SignatureStatus s) => s switch
    {
        SignatureStatus.Valid => "valid", SignatureStatus.NotSigned => "not signed", SignatureStatus.Revoked => "revoked",
        SignatureStatus.Expired => "expired", SignatureStatus.Untrusted => "untrusted", SignatureStatus.HashMismatch => "modified after signing", _ => "invalid",
    };
    internal static string Describe(PeSignature.State s) => s switch
    {
        PeSignature.State.Valid => "valid", PeSignature.State.NotSigned => "not signed", PeSignature.State.Modified => "modified after signing",
        PeSignature.State.BadSignature => "invalid", PeSignature.State.Untrusted => "untrusted", _ => "unreadable",
    };

    /// <summary>What a file is, by its first bytes first and its name second (a renamed program is still a program).</summary>
    public static string Classify(string name, ReadOnlySpan<byte> head)
    {
        var ext = Path.GetExtension(name).ToLowerInvariant();
        if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z') return "Program";
        if (ArchiveReader.LooksLikeArchive(head) && ext is not (".docx" or ".docm" or ".xlsx" or ".xlsm" or ".pptx" or ".pptm" or ".dotm" or ".xlam" or ".jar" or ".apk" or ".appx" or ".msix" or ".nupkg" or ".vsix")) return "Archive";
        if (head.Length >= 20 && head[0] == 0x4C && head[1] == 0 && head[2] == 0 && head[3] == 0 && head[4] == 0x01 && head[5] == 0x14) return "Shortcut";
        return ext switch
        {
            ".lnk" or ".url" => "Shortcut",
            ".ps1" or ".psm1" or ".bat" or ".cmd" or ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".hta" or ".py" or ".pyw" or ".au3" or ".ahk" or ".reg" or ".msc" => "Script",
            ".exe" or ".dll" or ".scr" or ".com" or ".cpl" or ".sys" or ".ocx" or ".msi" or ".msix" or ".appx" or ".jar" => "Program",
            ".doc" or ".docm" or ".docx" or ".xls" or ".xlsm" or ".xlsx" or ".ppt" or ".pptm" or ".pptx" or ".dotm" or ".xlam" or ".rtf" or ".pdf" or ".one" => "Document",
            ".iso" or ".img" or ".vhd" or ".vhdx" => "Disk image",
            ".txt" or ".nfo" or ".md" or ".html" or ".htm" or ".ini" or ".cfg" => "Text",
            _ => "Other",
        };
    }
}
