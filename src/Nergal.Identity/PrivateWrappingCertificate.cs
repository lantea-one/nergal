using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Nergal.Identity;

/// <summary>Loads an operator-provisioned PKCS#12 wrapping credential from a private local file into process memory.</summary>
[SupportedOSPlatform("linux")]
public static class PrivateWrappingCertificate
{
    /// <summary>Requires a service-owned 0700 parent and a 0600 single-link regular file. The PKCS#12 uses an empty transport password.</summary>
    /// <remarks>The private directory and trusted ancestors protect this credential at rest. The caller disposes the certificate.</remarks>
    public static X509Certificate2 Load(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.Contains('\0'))
        { throw new ArgumentException("An absolute wrapping credential path is required.", nameof(path)); }
        path = Path.GetFullPath(path);
        PrivateIdentityPath.RequireDirectory(Path.GetDirectoryName(path) ?? throw new ArgumentException("A wrapping credential file is required.", nameof(path)));
        if (PrivateIdentityPath.ReadFile(path) is null) { throw new AccountStoreException("keys.credentialMissing"); }
        using var file = File.OpenRead(path);
        if (file.Length is < 1 or > 65536) { throw new AccountStoreException("keys.credentialSize"); }
        var bytes = new byte[file.Length];
        try
        {
            file.ReadExactly(bytes);
            if (file.ReadByte() != -1) { throw new AccountStoreException("keys.credentialSize"); }
            return X509CertificateLoader.LoadPkcs12(bytes, null, X509KeyStorageFlags.EphemeralKeySet);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
