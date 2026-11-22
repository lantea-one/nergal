using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nergal.RemoteTransport;

/// <summary>Canonical certificate pinning, validity window, and X.509 EKU helpers for TLS 1.3 mTLS.</summary>
public static class TlsThumbprintPolicy
{
    /// <summary>TLS Web Server Authentication EKU OID (1.3.6.1.5.5.7.3.1).</summary>
    public const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";

    /// <summary>TLS Web Client Authentication EKU OID (1.3.6.1.5.5.7.3.2).</summary>
    public const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    /// <summary>Normalizes a 64-character hexadecimal SHA-256 certificate thumbprint into lowercase canonical form.</summary>
    /// <exception cref="ArgumentException">Thumbprint is missing, not 64 hex characters, or contains separators.</exception>
    public static string NormalizeThumbprint(string sha256Hex)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256Hex);
        if (sha256Hex.Length != 64)
        {
            throw new ArgumentException("SHA-256 certificate thumbprints must contain exactly 64 hex characters.", nameof(sha256Hex));
        }

        Span<char> normalized = stackalloc char[64];
        for (var i = 0; i < 64; i++)
        {
            var ch = sha256Hex[i];
            if (ch is >= '0' and <= '9' or >= 'a' and <= 'f')
            {
                normalized[i] = ch;
            }
            else if (ch is >= 'A' and <= 'F')
            {
                normalized[i] = (char)(ch + ('a' - 'A'));
            }
            else
            {
                throw new ArgumentException("SHA-256 certificate thumbprints must contain only hexadecimal characters.", nameof(sha256Hex));
            }
        }

        return new string(normalized);
    }

    /// <summary>Computes the canonical lowercase 64-hex-character SHA-256 thumbprint of <paramref name="certificate"/>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
    public static string ComputeSha256Thumbprint(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Convert.ToHexStringLower(certificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    /// <summary>Checks whether <paramref name="utcNow"/> falls within the inclusive UTC validity window of <paramref name="certificate"/>.</summary>
    public static bool IsWithinValidityWindow(X509Certificate2 certificate, DateTimeOffset utcNow)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var current = utcNow.UtcDateTime;
        return certificate.NotBefore.ToUniversalTime() <= current && current <= certificate.NotAfter.ToUniversalTime();
    }

    /// <summary>Checks whether <paramref name="certificate"/> carries an explicit EKU extension containing <paramref name="requiredOid"/>.</summary>
    public static bool HasEnhancedKeyUsage(X509Certificate2 certificate, string requiredOid)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentException.ThrowIfNullOrWhiteSpace(requiredOid);

        foreach (var extension in certificate.Extensions)
        {
            if (extension is not X509EnhancedKeyUsageExtension eku)
            {
                continue;
            }

            foreach (var oid in eku.EnhancedKeyUsages)
            {
                if (string.Equals(oid.Value, requiredOid, StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }

    internal static bool IsCertificateAuthority(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509BasicConstraintsExtension basic && basic.CertificateAuthority)
            {
                return true;
            }
        }

        return false;
    }

    internal static bool MatchesAnyPinnedThumbprint(X509Certificate2 certificate, IReadOnlyList<byte[]> pinnedSha256Digests)
    {
        var presented = certificate.GetCertHash(HashAlgorithmName.SHA256);
        var matched = false;
        foreach (var pin in pinnedSha256Digests)
        {
            if (CryptographicOperations.FixedTimeEquals(presented, pin))
            {
                matched = true;
            }
        }

        return matched;
    }

    internal static bool ValidatePeerCertificate(
        X509Certificate? certificate,
        IReadOnlyList<byte[]> pinnedDigests,
        string requiredEkuOid,
        DateTimeOffset utcNow)
    {
        if (certificate is null)
        {
            return false;
        }

        X509Certificate2? owned = null;
        try
        {
            if (certificate is not X509Certificate2 x509)
            {
                owned = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
                x509 = owned;
            }

            if (IsCertificateAuthority(x509))
            {
                return false;
            }

            if (!IsWithinValidityWindow(x509, utcNow))
            {
                return false;
            }

            if (!HasEnhancedKeyUsage(x509, requiredEkuOid))
            {
                return false;
            }

            return MatchesAnyPinnedThumbprint(x509, pinnedDigests);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            owned?.Dispose();
        }
    }

    internal static IReadOnlyList<byte[]> DecodePins(IEnumerable<string> rawThumbprints, out IReadOnlySet<string> normalizedSet)
    {
        ArgumentNullException.ThrowIfNull(rawThumbprints);
        var normalized = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in rawThumbprints)
        {
            normalized.Add(NormalizeThumbprint(item));
        }

        if (normalized.Count == 0)
        {
            throw new ArgumentException("At least one pinned SHA-256 thumbprint is required.", nameof(rawThumbprints));
        }

        var digests = new List<byte[]>(normalized.Count);
        foreach (var hex in normalized)
        {
            digests.Add(Convert.FromHexString(hex));
        }

        normalizedSet = normalized;
        return digests;
    }
}
