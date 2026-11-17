using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace TriageKit.Core.Intel;

/// <summary>
/// Authenticode verification through WinVerifyTrust, the same API Windows itself uses.
/// Checks the embedded signature first, then the system catalogs (most Windows binaries are catalog-signed).
/// Revocation checks are cache-only so the scan never blocks on the network.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Authenticode
{
    public readonly record struct Result(SignatureStatus Status, string? Signer, string? Type);

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_REVOKE_WHOLECHAIN = 1, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);
    private const int CRYPT_E_REVOKED = unchecked((int)0x80092010);
    public const string NotMicrosoftIssued = " (certificate not issued by Microsoft)";

    public static Result Verify(string path)
    {
        int embedded = VerifyEmbedded(path);
        if (embedded == 0) return new(SignatureStatus.Valid, SignerOf(path), "Embedded");
        if (embedded == TRUST_E_BAD_DIGEST) return new(SignatureStatus.HashMismatch, SignerOf(path), "Embedded");
        if (embedded is CERT_E_REVOKED or CRYPT_E_REVOKED or TRUST_E_EXPLICIT_DISTRUST) return new(SignatureStatus.Revoked, SignerOf(path), "Embedded");
        if (embedded == CERT_E_EXPIRED) return new(SignatureStatus.Expired, SignerOf(path), "Embedded");
        if (embedded is CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CRYPT_E_SECURITY_SETTINGS)
            return new(SignatureStatus.Untrusted, SignerOf(path), "Embedded");

        // No (valid) embedded signature: look the file up in the system catalogs.
        (int catStatus, string? catalogFile) = (-1, null);
        try { (catStatus, catalogFile) = VerifyCatalog(path); } catch { /* locked or unreadable file */ }
        if (catStatus == 0) return new(SignatureStatus.Valid, catalogFile is null ? "Microsoft Windows" : SignerOf(catalogFile) ?? "Microsoft Windows", "Catalog");

        return embedded is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN
            ? new(SignatureStatus.NotSigned, null, null)
            : new(SignatureStatus.Untrusted, SignerOf(path), "Embedded");
    }

    private static string? SignerOf(string signedFile)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
#pragma warning restore SYSLIB0057
            var name = cert.GetNameInfo(X509NameType.SimpleName, false);
            // Microsoft's own signing certificates are issued by Microsoft CAs. A certificate that merely calls itself
            // "Microsoft ..." but comes from another CA must not be treated as Microsoft's (several checks trust those).
            // Newer Windows files are issued by "Windows Production PCA 2023", so the issuer's name isn't enough: a chain that
            // ends in one of Microsoft's own roots counts too.
            if (name?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) == true &&
                !(cert.GetNameInfo(X509NameType.SimpleName, true)?.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false) &&
                !ChainsToMicrosoftRoot(signedFile, cert))
                return name + NotMicrosoftIssued;
            return name;
        }
        catch { return null; }
    }


    /// <summary>SHA-1 thumbprints of Microsoft's code-signing roots.</summary>
    internal static readonly HashSet<string> MicrosoftRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        "CDD4EEAE6000AC7F40C3802C171E30148030C072",   // Microsoft Root Certificate Authority
        "A43489159A520F0D93D032CCAF37E7FE20A8B419",   // Microsoft Root Authority
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",   // Microsoft Root Certificate Authority 2010
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE",   // Microsoft Root Certificate Authority 2011
        "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",   // Microsoft Identity Verification Root Certificate Authority 2020
    };

    /// <summary>Builds the signer's chain from the certificates inside the signature (no downloads, no revocation)
    /// and reports whether it ends in a Microsoft root. Thumbprints come from the certificates' bytes, so they can't be faked.</summary>
    internal static bool ChainsToMicrosoftRoot(string signedFile, X509Certificate2 signer)
    {
        try
        {
            var pkcs7 = SignatureBlob(signedFile);
            if (pkcs7 is null) return false;
            var extra = new X509Certificate2Collection();
#pragma warning disable SYSLIB0057
            extra.Import(pkcs7);
#pragma warning restore SYSLIB0057
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority | X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;
            chain.ChainPolicy.ExtraStore.AddRange(extra);
            chain.Build(signer);
            if (chain.ChainElements.Count < 2) return false;
            var root = chain.ChainElements[^1].Certificate;
            return root.SubjectName.RawData.AsSpan().SequenceEqual(root.IssuerName.RawData) && MicrosoftRoots.Contains(root.Thumbprint);
        }
        catch { return false; }
    }

    /// <summary>The PKCS#7 signature of a PE file (its certificate table) or a catalog file (the whole file).</summary>
    internal static byte[]? SignatureBlob(string file)
    {
        var info = new FileInfo(file);
        if (!info.Exists || info.Length < 64) return null;
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var br = new BinaryReader(fs);
        if (br.ReadUInt16() != 0x5A4D) return info.Length <= 64 * 1024 * 1024 ? File.ReadAllBytes(file) : null;   // catalog (.cat) files are PKCS#7
        fs.Position = 0x3C; long pe = br.ReadUInt32();
        if (pe <= 0 || pe > info.Length - 200) return null;
        fs.Position = pe + 24; ushort magic = br.ReadUInt16();
        long dir = pe + 24 + (magic == 0x20B ? 112 : 96) + 4 * 8;                    // data directory 4: certificate table
        if (dir + 8 > info.Length) return null;
        fs.Position = dir; long off = br.ReadUInt32(); int size = (int)Math.Min(br.ReadUInt32(), 16u * 1024 * 1024);
        if (off <= 0 || size <= 8 || off + size > info.Length) return null;
        fs.Position = off + 8;                                                        // skip WIN_CERTIFICATE header
        return br.ReadBytes(size - 8);
    }

    private static int VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            return Call(WTD_CHOICE_FILE, pFile);
        }
        finally { Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile); Marshal.FreeHGlobal(pFile); }
    }

    private static (int Status, string? Catalog) VerifyCatalog(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        // Try SHA256 catalogs first, then legacy SHA1 catalogs.
        foreach (var alg in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var hAdmin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
            IntPtr hCatInfo = IntPtr.Zero;
            try
            {
                uint cb = 0;
                CryptCATAdminCalcHashFromFileHandle2(hAdmin, fs.SafeFileHandle, ref cb, null, 0);
                if (cb == 0) continue;
                var hash = new byte[cb];
                if (!CryptCATAdminCalcHashFromFileHandle2(hAdmin, fs.SafeFileHandle, ref cb, hash, 0)) continue;
                IntPtr prev = IntPtr.Zero;
                hCatInfo = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, cb, 0, ref prev);
                if (hCatInfo == IntPtr.Zero) continue;

                var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref ci, 0)) continue;

                string tag = Convert.ToHexString(hash);
                IntPtr pHash = Marshal.AllocHGlobal(hash.Length);
                IntPtr pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                try
                {
                    Marshal.Copy(hash, 0, pHash, hash.Length);
                    var wci = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), pcwszCatalogFilePath = ci.wszCatalogFile,
                        pcwszMemberTag = tag, pcwszMemberFilePath = path, pbCalculatedFileHash = pHash,
                        cbCalculatedFileHash = (uint)hash.Length, hCatAdmin = hAdmin
                    };
                    Marshal.StructureToPtr(wci, pCat, false);
                    int r = Call(WTD_CHOICE_CATALOG, pCat);
                    Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
                    if (r == 0) return (0, ci.wszCatalogFile);
                }
                finally { Marshal.FreeHGlobal(pHash); Marshal.FreeHGlobal(pCat); }
            }
            finally
            {
                if (hCatInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(hAdmin, hCatInfo, 0);
                CryptCATAdminReleaseContext(hAdmin, 0);
            }
        }
        return (-1, null);
    }

    /// <summary>
    /// Verifies with revocation checking against what Windows has cached (never online, so the scan stays offline and
    /// fast). When no revocation data is cached, verifies again without it: only a confirmed revocation counts.
    /// </summary>
    private static int Call(uint unionChoice, IntPtr unionPtr)
    {
        int r = CallOnce(unionChoice, unionPtr, revocation: true);
        // Only a confirmed revocation (or a clean pass) counts from the first call. Anything else, including
        // revocation errors we don't know, is decided by the normal check without revocation.
        return r is 0 or CERT_E_REVOKED or CRYPT_E_REVOKED ? r : CallOnce(unionChoice, unionPtr, revocation: false);
    }

    private static int CallOnce(uint unionChoice, IntPtr unionPtr, bool revocation)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = WTD_UI_NONE, fdwRevocationChecks = revocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice, pUnion = unionPtr, dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = (revocation ? WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT : WTD_REVOCATION_CHECK_NONE) | WTD_CACHE_ONLY_URL_RETRIEVAL
        };
        IntPtr pData = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_DATA>());
        try
        {
            Marshal.StructureToPtr(data, pData, false);
            int result = WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, pData);
            // Always release provider state.
            var closed = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
            closed.dwStateAction = WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(closed, pData, true);
            WinVerifyTrust(new IntPtr(-1), GenericVerifyV2, pData);
            return result;
        }
        finally { Marshal.FreeHGlobal(pData); }
    }

    // ---------------------------------------------------------------- interop

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
