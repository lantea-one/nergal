using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

namespace Nergal.Identity;

/// <summary>Explicit isolated certificate-encrypted persistent Data Protection provider; enables no browser sessions or machine-profile fallback.</summary>
/// <remarks>Caller provisions the private directory/certificates and retains wrapping private keys for recovery. Same-account/root and hostile-parent attacks remain outside this prototype.</remarks>
[SupportedOSPlatform("linux")]
public sealed class ProtectedSessionKeyRing : IDataProtectionProvider, IDisposable
{
    private ProviderBundle? bundle;
    private readonly ProtectedSessionKeyOptions options;
    private readonly PrivateSessionKeyRepository repository;
    private readonly X509Certificate2[] certificates;
    private readonly object gate = new();
    private bool disposed;

    private ProtectedSessionKeyRing(ProtectedSessionKeyOptions options, ProviderBundle bundle, PrivateSessionKeyRepository repository, X509Certificate2[] certificates)
    {
        this.options = options;
        this.bundle = bundle;
        this.repository = repository;
        this.certificates = certificates;
    }

    /// <summary>Opens only the explicitly configured key directory, verifies all retained descriptors are readable, and snapshots certificate handles.</summary>
    /// <param name="options">Private directory and stable application discriminator.</param>
    /// <param name="encryptionCertificate">Currently valid RSA certificate/private key, at least 3072 bits. A self-signed wrapping certificate is supported.</param>
    /// <param name="retainedDecryptionCertificates">At most seven previous RSA/private certificates; expiration is allowed for decryption-only history.</param>
    /// <exception cref="ArgumentNullException">Options or encryption certificate is null.</exception>
    /// <exception cref="ArgumentException">Certificates are missing private RSA material, weak, duplicate, disposed or invalid for current encryption.</exception>
    /// <exception cref="SessionKeyStoreException">Storage, XML, complete key loading or retained-key decryption fails; no ephemeral fallback is returned.</exception>
    /// <exception cref="PlatformNotSupportedException">Platform is not Linux x64/arm64.</exception>
    public static ProtectedSessionKeyRing Open(ProtectedSessionKeyOptions options, X509Certificate2 encryptionCertificate,
        IEnumerable<X509Certificate2>? retainedDecryptionCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(encryptionCertificate);
        if (!OperatingSystem.IsLinux() || RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
        { throw new PlatformNotSupportedException("Protected session keys require Linux x64 or arm64."); }
        var old = retainedDecryptionCertificates?.Take(8).ToArray() ?? [];
        if (old.Length > 7) { throw new ArgumentException("At most seven retained wrapping certificates are supported.", nameof(retainedDecryptionCertificates)); }
        var copies = new List<X509Certificate2>();
        try
        {
            copies.Add(CopyCertificate(encryptionCertificate, encryption: true));
            foreach (var certificate in old) { copies.Add(CopyCertificate(certificate, encryption: false)); }
            if (copies.Select(certificate => certificate.Thumbprint).Distinct(StringComparer.OrdinalIgnoreCase).Count() != copies.Count)
            { throw new ArgumentException("Wrapping certificates must be distinct.", nameof(retainedDecryptionCertificates)); }
            var snapshot = copies.ToArray();
            var repository = new PrivateSessionKeyRepository(options, snapshot);
            return new(options, BuildProvider(options, repository, snapshot), repository, snapshot);
        }
        catch
        {
            foreach (var certificate in copies) { certificate.Dispose(); }
            throw;
        }
    }

    private static ProviderBundle BuildProvider(ProtectedSessionKeyOptions options, PrivateSessionKeyRepository repository, X509Certificate2[] certificates)
    {
        ServiceProvider? built = null;
        try
        {
            var expectedKeys = repository.GetAllElements().Count(element => element.Name == "key");
            var generation = repository.Generation;
            var collection = new ServiceCollection();
            collection.AddDataProtection().SetApplicationName(options.ApplicationName)
                .UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
                { EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC, ValidationAlgorithm = ValidationAlgorithm.HMACSHA256 })
                .ProtectKeysWithCertificate(certificates[0]).UnprotectKeysWithAnyCertificate(certificates.Skip(1).ToArray());
            collection.Configure<KeyManagementOptions>(keys => keys.XmlRepository = repository);
            built = collection.BuildServiceProvider();
            var loaded = built.GetRequiredService<IKeyManager>().GetAllKeys();
            if (loaded.Count != expectedKeys) { throw new SessionKeyStoreException("keys.incomplete"); }
            // Force lazy descriptor decryption now. A wrong/missing historical
            // certificate must not silently produce a replacement empty key ring.
            foreach (var key in loaded) { _ = key.Descriptor; }
            if (repository.Generation != generation) { throw new SessionKeyStoreException("keys.concurrentChange"); }
            return new(built, built.GetRequiredService<IDataProtectionProvider>(), generation);
        }
        catch (Exception error)
        {
            built?.Dispose();
            if (error is CryptographicException or InvalidOperationException)
            { throw new SessionKeyStoreException("keys.decrypt"); }
            throw;
        }
    }

    /// <summary>Creates a purpose-isolated protector backed only by this protected key ring.</summary>
    /// <exception cref="ArgumentNullException">Purpose is null.</exception>
    /// <exception cref="ObjectDisposedException">The ring is disposed.</exception>
    public IDataProtector CreateProtector(string purpose)
    {
        ArgumentNullException.ThrowIfNull(purpose);
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return new CheckedProtector(this, [purpose]);
        }
    }

    private byte[] Execute(string[] purposes, byte[] input, bool protect)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                _ = repository.GetAllElements();
                var active = bundle ?? throw new ObjectDisposedException(nameof(ProtectedSessionKeyRing));
                if (active.Generation != repository.Generation)
                {
                    var refreshed = BuildProvider(options, repository, certificates);
                    bundle = refreshed;
                    active.Services.Dispose();
                    active = refreshed;
                }
                IDataProtectionProvider current = active.Provider;
                IDataProtector? protector = null;
                foreach (var purpose in purposes) { protector = current.CreateProtector(purpose); current = protector; }
                byte[]? result = null;
                try
                {
                    result = protect ? protector!.Protect(input) : protector!.Unprotect(input);
                    _ = repository.GetAllElements();
                    if (active.Generation == repository.Generation)
                    {
                        var accepted = result;
                        result = null;
                        return accepted;
                    }
                }
                finally { if (result is not null) { CryptographicOperations.ZeroMemory(result); } }
                // Append during crypto (including first key generation) requires a
                // fresh provider and reevaluation; cached keys cannot bypass revocation.
            }
            throw new SessionKeyStoreException("keys.concurrentChange");
        }
    }

    /// <summary>Disposes the private provider and owned certificate handles; previously created protectors can no longer operate.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) { return; }
            disposed = true;
            var previous = bundle;
            bundle = null;
            try { previous?.Services.Dispose(); }
            finally { foreach (var certificate in certificates) { certificate.Dispose(); } }
        }
    }

    private static X509Certificate2 CopyCertificate(X509Certificate2 certificate, bool encryption)
    {
        if (certificate is null) { throw new ArgumentException("Wrapping certificates cannot be null."); }
        X509Certificate2? copy = null;
        try
        {
            copy = new X509Certificate2(certificate);
            using var rsa = copy.GetRSAPrivateKey();
            if (rsa is null || rsa.KeySize < 3072) { throw new ArgumentException("A private RSA wrapping key of at least 3072 bits is required."); }
            if (encryption && (copy.NotBefore.ToUniversalTime() > DateTime.UtcNow || copy.NotAfter.ToUniversalTime() <= DateTime.UtcNow))
            { throw new ArgumentException("The current wrapping certificate must be valid now."); }
            foreach (var usage in copy.Extensions.OfType<X509KeyUsageExtension>())
            {
                if (!usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                { throw new ArgumentException("The wrapping certificate must permit key encipherment."); }
            }
            return copy;
        }
        catch (Exception error) when (error is CryptographicException or ObjectDisposedException)
        { copy?.Dispose(); throw new ArgumentException("The wrapping certificate is unavailable or invalid."); }
        catch { copy?.Dispose(); throw; }
    }
    private sealed record ProviderBundle(ServiceProvider Services, IDataProtectionProvider Provider, long Generation);

    private sealed class CheckedProtector(ProtectedSessionKeyRing owner, string[] purposes) : IDataProtector
    {
        public IDataProtector CreateProtector(string purpose)
        {
            ArgumentNullException.ThrowIfNull(purpose);
            lock (owner.gate)
            {
                ObjectDisposedException.ThrowIf(owner.disposed, owner);
                return new CheckedProtector(owner, [.. purposes, purpose]);
            }
        }
        public byte[] Protect(byte[] plaintext)
        {
            ArgumentNullException.ThrowIfNull(plaintext);
            return owner.Execute(purposes, plaintext, protect: true);
        }
        public byte[] Unprotect(byte[] protectedData)
        {
            ArgumentNullException.ThrowIfNull(protectedData);
            return owner.Execute(purposes, protectedData, protect: false);
        }
    }
}
