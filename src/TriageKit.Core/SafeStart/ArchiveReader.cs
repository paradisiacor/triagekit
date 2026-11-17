using System.Security.Cryptography;
using SharpCompress.Archives;
using SharpCompress.Common;
using SharpCompress.Readers;

namespace TriageKit.Core.SafeStart;

/// <summary>
/// Reads ZIP, RAR (4 and 5), 7z, TAR, GZip, BZip2 and XZ archives entry by entry, in memory. Nothing is extracted to
/// disk and nothing inside is ever run. Defends against archive bombs: every entry is hashed while it is read, at most
/// <see cref="MaxEntryBytes"/> are read per entry and at most <see cref="MaxTotalBytes"/> per archive, and an entry that
/// expands absurdly compared with its packed size is cut off.
/// </summary>
public static class ArchiveReader
{
    public const long MaxEntryBytes = 2L * 1024 * 1024 * 1024;
    public const long MaxTotalBytes = 16L * 1024 * 1024 * 1024;
    public const double MaxRatio = 1000;

    public sealed class UnsupportedException(string message) : Exception(message);

    public sealed class Entry
    {
        public required string Name { get; init; }
        public long Size { get; init; }
        public bool Encrypted { get; init; }
        internal Func<Stream> OpenStream { get; init; } = null!;
        internal long Packed { get; init; }
        internal Budget Budget { get; init; } = null!;

        /// <summary>Reads the entry: the first <paramref name="keep"/> bytes, the SHA-256 of the whole entry and its size.
        /// If a limit cut reading short, Sha256 is null and Cut says why (the bytes read so far are still returned).</summary>
        public (byte[] Data, string? Sha256, long Size, string? Cut) Read(long keep)
        {
            using var s = OpenStream();
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var head = new MemoryStream();
            var buf = new byte[1 << 16];
            long total = 0; bool cut = false;
            int n;
            while ((n = s.Read(buf, 0, buf.Length)) > 0)
            {
                total += n; Budget.Bytes += n;
                if (total > MaxEntryBytes || Budget.Bytes > MaxTotalBytes || (Packed > 0 && total > 64L * 1024 * 1024 && total > Packed * MaxRatio)) { cut = true; break; }
                sha.AppendData(buf, 0, n);
                if (head.Length < keep) head.Write(buf, 0, (int)Math.Min(n, keep - head.Length));
            }
            if (cut) return (head.ToArray(), null, Math.Max(total, Size), Packed > 0 && total > Packed * MaxRatio ? $"expands to more than {MaxRatio:N0} times its packed size" : "is larger than the size limit");
            return (head.ToArray(), Convert.ToHexString(sha.GetHashAndReset()), total, null);
        }
    }

    internal sealed class Budget { public long Bytes; }

    public static bool LooksLikeArchive(ReadOnlySpan<byte> d)
    {
        if (d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && (d[2] == 3 && d[3] == 4 || d[2] == 5 && d[3] == 6 || d[2] == 7 && d[3] == 8)) return true;
        if (d.Length >= 6 && d[0] == 'R' && d[1] == 'a' && d[2] == 'r' && d[3] == '!' && d[4] == 0x1A && d[5] == 0x07) return true;
        if (d.Length >= 6 && d[0] == '7' && d[1] == 'z' && d[2] == 0xBC && d[3] == 0xAF && d[4] == 0x27 && d[5] == 0x1C) return true;
        if (d.Length >= 3 && d[0] == 0x1F && d[1] == 0x8B && d[2] == 8) return true;                      // gzip
        if (d.Length >= 6 && d[0] == 0xFD && d[1] == '7' && d[2] == 'z' && d[3] == 'X' && d[4] == 'Z' && d[5] == 0) return true;   // xz
        if (d.Length >= 3 && d[0] == 'B' && d[1] == 'Z' && d[2] == 'h') return true;                      // bzip2
        if (d.Length >= 262 && d[257] == 'u' && d[258] == 's' && d[259] == 't' && d[260] == 'a' && d[261] == 'r') return true;   // tar
        return false;
    }

    /// <summary>Entries of the archive in <paramref name="s"/> (must be seekable). Directories are skipped.</summary>
    public static IEnumerable<Entry> Entries(Stream s, CancellationToken ct, string archiveName = "")
    {
        // A single gzip stream (.gz, and the outer layer of .tar.gz) is one file: unpack it with .NET's own decoder.
        // A .tar inside is then recognised as an archive of its own.
        Span<byte> magic = stackalloc byte[3];
        s.Position = 0;
        int got = s.Read(magic);
        s.Position = 0;
        if (got == 3 && magic[0] == 0x1F && magic[1] == 0x8B && magic[2] == 8)
        {
            var inner = Path.GetFileName(archiveName);
            inner = inner.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase) ? inner[..^4] + ".tar"
                  : inner.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ? inner[..^3] : inner + ".unpacked";
            yield return new Entry
            {
                Name = inner, Size = -1, Packed = s.Length, Budget = new Budget(),
                OpenStream = () => { s.Position = 0; return new System.IO.Compression.GZipStream(s, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true); },
            };
            yield break;
        }
        IArchive archive;
        try { archive = ArchiveFactory.OpenArchive(s, new ReaderOptions { LeaveStreamOpen = true, LookForHeader = false }); }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException || ex is SharpCompress.Common.CryptographicException || ex.GetType().Name.Contains("Password", StringComparison.Ordinal) || ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase))
        { throw new UnsupportedException("the archive's file list is password-protected, so it can't be checked"); }
        catch (Exception ex) when (ex is InvalidOperationException or InvalidFormatException or ArchiveException or NotSupportedException)
        { throw new UnsupportedException("archive format isn't supported or the file is damaged (" + ex.Message + ")"); }
        using (archive)
        {
            var budget = new Budget();
            foreach (var e in archive.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (e.IsDirectory) continue;
                var entry = e;
                yield return new Entry
                {
                    Name = entry.Key ?? "(unnamed)", Size = entry.Size, Encrypted = entry.IsEncrypted, Packed = entry.CompressedSize, Budget = budget,
                    OpenStream = () => entry.OpenEntryStream(),
                };
            }
        }
    }
}
