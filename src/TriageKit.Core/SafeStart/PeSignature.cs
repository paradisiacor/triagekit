using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace TriageKit.Core.SafeStart;

/// <summary>
/// Authenticode check for a program held in memory (for example a file inside an archive), so nothing has to be
/// extracted to disk. It verifies that (1) the signature is cryptographically valid, (2) the file's own hash matches
/// the hash that was signed (so the file wasn't changed after signing) and (3) the signer's chain ends in a root this
/// PC trusts. Revocation isn't checked (offline). Files on disk are checked with Windows' own WinVerifyTrust instead.
/// </summary>
public static class PeSignature
{
    public enum State { NotSigned, Valid, Modified, BadSignature, Untrusted, Unreadable }
    public sealed record Result(State State, string? Signer);

    public static Result Verify(byte[] pe, bool checkTrust = true)
    {
        try
        {
            if (!TryLayout(pe, out var checksumOff, out var dirOff, out var certOff, out var certLen)) return new(State.Unreadable, null);
            if (certLen == 0) return new(State.NotSigned, null);
            if (certOff < 0 || certLen < 8 || certOff + certLen > pe.Length) return new(State.Unreadable, null);
            var blob = pe.AsSpan(certOff + 8, Math.Min(certLen, BitConverter.ToInt32(pe, certOff)) - 8).ToArray();
            var cms = new SignedCms();
            cms.Decode(blob);
            var signerInfo = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
            var cert = signerInfo?.Certificate;
            var signer = cert?.GetNameInfo(X509NameType.SimpleName, false);
            try { cms.CheckSignature(verifySignatureOnly: true); }
            catch (CryptographicException) { return new(State.BadSignature, signer); }

            var (oid, signedDigest) = IndirectDigest(cms.ContentInfo.Content);
            using HashAlgorithm h = oid switch
            {
                "1.3.14.3.2.26" => SHA1.Create(),
                "2.16.840.1.101.3.4.2.1" => SHA256.Create(),
                "2.16.840.1.101.3.4.2.2" => SHA384.Create(),
                "2.16.840.1.101.3.4.2.3" => SHA512.Create(),
                _ => throw new CryptographicException("Unknown digest algorithm " + oid),
            };
            var actual = AuthenticodeHash(h, pe, checksumOff, dirOff, certOff, certLen);
            if (!actual.AsSpan().SequenceEqual(signedDigest)) return new(State.Modified, signer);
            if (!checkTrust || cert is null) return new(State.Valid, signer);
            return new(Trusted(cert, cms.Certificates) ? State.Valid : State.Untrusted, signer);
        }
        catch { return new(State.Unreadable, null); }
    }

    /// <summary>Offsets of the PE checksum, the certificate-table directory entry and the certificate table itself.</summary>
    internal static bool TryLayout(byte[] pe, out int checksumOff, out int dirOff, out int certOff, out int certLen)
    {
        checksumOff = dirOff = certOff = certLen = 0;
        if (pe.Length < 0x40 || pe[0] != 'M' || pe[1] != 'Z') return false;
        int nt = BitConverter.ToInt32(pe, 0x3C);
        if (nt <= 0 || nt > pe.Length - 0x100 || BitConverter.ToUInt32(pe, nt) != 0x00004550) return false;   // "PE\0\0"
        int opt = nt + 24;
        ushort magic = BitConverter.ToUInt16(pe, opt);
        if (magic != 0x10B && magic != 0x20B) return false;
        checksumOff = opt + 64;
        dirOff = opt + (magic == 0x20B ? 144 : 128);                 // data directory 4 = certificate table
        if (dirOff + 8 > pe.Length) return false;
        certOff = BitConverter.ToInt32(pe, dirOff);                    // a file offset, not an RVA
        certLen = BitConverter.ToInt32(pe, dirOff + 4);
        return true;
    }

    /// <summary>Authenticode digest: the whole file except the checksum, the certificate directory entry and the
    /// certificate table (the layout used by signing tools for well-formed files).</summary>
    internal static byte[] AuthenticodeHash(HashAlgorithm h, byte[] pe, int checksumOff, int dirOff, int certOff, int certLen)
    {
        void Part(int from, int to) { if (to > from) h.TransformBlock(pe, from, to - from, null, 0); }
        Part(0, checksumOff);
        Part(checksumOff + 4, dirOff);
        int end = certLen > 0 ? certOff : pe.Length;
        Part(dirOff + 8, end);
        if (certLen > 0) Part(certOff + certLen, pe.Length);
        h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return h.Hash!;
    }

    /// <summary>SpcIndirectDataContent ::= SEQUENCE { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }.</summary>
    internal static (string Oid, byte[] Digest) IndirectDigest(byte[] content)
    {
        var r = new AsnReader(content, AsnEncodingRules.BER);
        var seq = r.ReadSequence();
        seq.ReadEncodedValue();                                          // SpcAttributeTypeAndOptionalValue
        var digestInfo = seq.ReadSequence();
        var alg = digestInfo.ReadSequence();
        var oid = alg.ReadObjectIdentifier();
        return (oid, digestInfo.ReadOctetString());
    }

    private static bool Trusted(X509Certificate2 cert, X509Certificate2Collection extra)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;
        chain.ChainPolicy.ExtraStore.AddRange(extra);
        return chain.Build(cert);
    }
}
