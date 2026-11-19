using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Nergal.Identity;

namespace Nergal.LocalState.Tests;

/// <summary>Uses real framework cryptography and synthetic private certificates/files, never machine profiles or production secrets.</summary>
[SupportedOSPlatform("linux")]
public sealed class ProtectedSessionKeyTests
{
    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("synthetic protected fixture value");

    /// <summary>Encrypted private keys survive a new provider, while caller certificate disposal cannot invalidate a configured ring.</summary>
    [Fact]
    public void Persistence_EncryptsPrivateKeysAndSurvivesRestart()
    {
        using var fixture = new Fixture();
        using var retained = new X509Certificate2(fixture.Certificate);
        byte[] protectedValue;
        using (var first = fixture.Open())
        {
            fixture.Certificate.Dispose();
            protectedValue = first.CreateProtector("fixture").Protect(Plaintext);
            Assert.Equal(Plaintext, first.CreateProtector("fixture").Unprotect(protectedValue));
        }
        var file = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        var document = XElement.Load(file);
        Assert.True(document.Descendants().Any(node => node.Name.LocalName == "encryptedSecret"), "Persisted key secret was not encrypted.");
        Assert.False(document.Descendants().Any(node => node.Name.LocalName == "masterKey"), "Plaintext master key was persisted.");
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        Assert.Empty(Directory.GetFiles(fixture.Keys, "*.tmp"));
        using var reopened = ProtectedSessionKeyRing.Open(fixture.Options, retained);
        Assert.Equal(Plaintext, reopened.CreateProtector("fixture").Unprotect(protectedValue));
    }

    /// <summary>Purpose/application isolation and authenticated payload integrity reject altered or mis-scoped tokens.</summary>
    [Fact]
    public void Protection_RejectsWrongPurposeApplicationAndTamperedPayload()
    {
        using var fixture = new Fixture();
        using var ring = fixture.Open();
        var payload = ring.CreateProtector("fixture").CreateProtector("nested").Protect(Plaintext);
        Assert.Equal(Plaintext, ring.CreateProtector("fixture").CreateProtector("nested").Unprotect(payload));
        Assert.ThrowsAny<CryptographicException>(() => ring.CreateProtector("other").Unprotect(payload));
        using var other = ProtectedSessionKeyRing.Open(new(fixture.Keys, "nergal.fixture.other"), fixture.Certificate);
        Assert.ThrowsAny<CryptographicException>(() => other.CreateProtector("fixture").CreateProtector("nested").Unprotect(payload));
        payload[^1] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => ring.CreateProtector("fixture").CreateProtector("nested").Unprotect(payload));
    }

    /// <summary>Missing historical wrapping keys fail at open without replacing state; retaining them permits rotation and new encrypted keys.</summary>
    [Fact]
    public void Rotation_RequiresHistoricalCertificateAndSnapshotsRetainedHandles()
    {
        using var fixture = new Fixture();
        byte[] oldPayload;
        using (var first = fixture.Open()) { oldPayload = first.CreateProtector("fixture").Protect(Plaintext); }
        var oldFile = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        // A synthetic past lifetime causes normal framework rotation without sleeping.
        var oldXml = XElement.Load(oldFile);
        oldXml.Element("creationDate")!.Value = DateTimeOffset.UtcNow.AddDays(-200).ToString("O");
        oldXml.Element("activationDate")!.Value = DateTimeOffset.UtcNow.AddDays(-200).ToString("O");
        oldXml.Element("expirationDate")!.Value = DateTimeOffset.UtcNow.AddDays(-100).ToString("O");
        oldXml.Save(oldFile);
        using var current = Certificate();
        var before = File.ReadAllBytes(oldFile);
        Reject("keys.certificateMissing", () => ProtectedSessionKeyRing.Open(fixture.Options, current));
        Assert.True(before.SequenceEqual(File.ReadAllBytes(oldFile)), "Failed open modified historical key material.");
        var previous = new List<X509Certificate2> { fixture.Certificate };
        byte[] newPayload;
        using (var rotated = ProtectedSessionKeyRing.Open(fixture.Options, current, previous))
        {
            previous.Clear();
            fixture.Certificate.Dispose();
            Assert.Equal(Plaintext, rotated.CreateProtector("fixture").Unprotect(oldPayload));
            newPayload = rotated.CreateProtector("fixture").Protect(Plaintext);
            Assert.Equal(Plaintext, rotated.CreateProtector("fixture").Unprotect(newPayload));
        }
        var newFile = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"), file => file != oldFile);
        using var separate = new Fixture();
        var copied = Path.Combine(separate.Keys, Path.GetFileName(newFile));
        File.Copy(newFile, copied);
        File.SetUnixFileMode(copied, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        using var onlyNew = ProtectedSessionKeyRing.Open(separate.Options, current);
        Assert.Equal(Plaintext, onlyNew.CreateProtector("fixture").Unprotect(newPayload));
    }

    /// <summary>New revocation records invalidate already-created protectors instead of being hidden by framework key caches.</summary>
    [Fact]
    public void Revocation_IsObservedByExistingProtectors()
    {
        using var fixture = new Fixture();
        using var ring = fixture.Open();
        var protector = ring.CreateProtector("fixture");
        var oldPayload = protector.Protect(Plaintext);
        var oldKey = XElement.Load(Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"))).Attribute("id")!.Value;
        fixture.Write(new XElement("revocation", new XAttribute("version", 1),
            new XElement("revocationDate", DateTimeOffset.UtcNow), new XElement("key", new XAttribute("id", oldKey)),
            new XElement("reason", "synthetic fixture revocation")).ToString());
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(oldPayload));
        var fresh = protector.Protect(Plaintext);
        Assert.Equal(Plaintext, protector.Unprotect(fresh));
        Assert.ThrowsAny<CryptographicException>(() => protector.Unprotect(oldPayload));
    }

    /// <summary>Expired historical certificates remain usable for retained-key decryption; they cannot be the current wrapping certificate.</summary>
    [Fact]
    public void Rotation_DecryptsWithExpiredHistoricalCertificate()
    {
        using var fixture = new Fixture();
        using var expired = Certificate(expired: true);
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, expired));
        byte[] payload;
        // Test-only framework setup simulates a historical key wrapped by an expired certificate.
        var services = new ServiceCollection();
        services.AddDataProtection().SetApplicationName(fixture.Options.ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(fixture.Keys)).ProtectKeysWithCertificate(expired);
        using (var old = services.BuildServiceProvider())
        { payload = old.GetRequiredService<IDataProtectionProvider>().CreateProtector("fixture").Protect(Plaintext); }
        var oldFile = Assert.Single(Directory.GetFiles(fixture.Keys, "*.xml"));
        File.Move(oldFile, Path.Combine(fixture.Keys, "key-" + Guid.NewGuid().ToString("N") + ".xml"));
        using var reopened = ProtectedSessionKeyRing.Open(fixture.Options, fixture.Certificate, [expired]);
        Assert.Equal(Plaintext, reopened.CreateProtector("fixture").Unprotect(payload));
    }

    /// <summary>Unsafe filesystem metadata, changed immutable bytes and deletion deny even an already-loaded provider without fallback.</summary>
    [Fact]
    public void CachedProvider_CannotBypassPrivateStoreChecks()
    {
        using var fixture = new Fixture();
        using var ring = fixture.Open();
        var protector = ring.CreateProtector("fixture");
        var payload = protector.Protect(Plaintext);
        var file = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        var original = File.ReadAllBytes(file);
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        Reject("path.mode", () => protector.Unprotect(payload));
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.AppendAllText(file, "\n"); // Still valid XML; immutable-byte comparison must catch the change.
        Reject("keys.changed", () => protector.Protect(Plaintext));
        File.WriteAllBytes(file, original);
        var duplicate = fixture.Write(Encoding.UTF8.GetString(original));
        Reject("keys.duplicate", () => protector.Unprotect(payload));
        File.Delete(duplicate);
        var saved = Path.Combine(fixture.Root, "saved.xml");
        File.Move(file, saved);
        Reject("keys.missing", () => protector.Unprotect(payload));
        File.Move(saved, file);
        Assert.Equal(Plaintext, protector.Unprotect(payload));
    }

    /// <summary>Symlink and shared-inode key files are rejected before content loading; original encrypted bytes remain intact.</summary>
    [Fact]
    public void Storage_RejectsSymlinkAndSharedInode()
    {
        using var fixture = new Fixture();
        using var ring = fixture.Open();
        var protector = ring.CreateProtector("fixture");
        var payload = protector.Protect(Plaintext);
        var file = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        var alias = Path.Combine(fixture.Root, "alias.xml");
        Assert.Equal(0, link(file, alias));
        Reject("path.hardLink", () => protector.Unprotect(payload));
        File.Delete(alias);
        var saved = Path.Combine(fixture.Root, "saved.xml");
        File.Move(file, saved);
        File.CreateSymbolicLink(file, saved);
        Reject("path.symlink", () => protector.Unprotect(payload));
        File.Delete(file);
        File.Move(saved, file);
        Assert.Equal(Plaintext, protector.Unprotect(payload));
    }

    /// <summary>Known private incomplete writes remain inert and unchanged; unknown names are never adopted or silently removed.</summary>
    [Fact]
    public void InterruptedPendingFile_IsNotAuthorityOrAutomaticallyDeleted()
    {
        using var fixture = new Fixture();
        var pending = fixture.Write("synthetic interrupted write", ".pending-" + Guid.NewGuid().ToString("N") + ".tmp");
        using var ring = fixture.Open();
        var protector = ring.CreateProtector("fixture");
        var payload = protector.Protect(Plaintext);
        Assert.Equal(Plaintext, protector.Unprotect(payload));
        Assert.Equal("synthetic interrupted write", File.ReadAllText(pending));
        var foreign = fixture.Write("foreign sentinel", "foreign.xml");
        Reject("keys.name", () => protector.Unprotect(payload));
        Assert.Equal("foreign sentinel", File.ReadAllText(foreign));
    }

    /// <summary>Invalid committed XML is never skipped in favor of a new key, including DTD and plaintext-key input.</summary>
    [Theory]
    [InlineData("<unrelated/>", "keys.format")]
    [InlineData("<key version=\"1\"><masterKey>synthetic</masterKey></key>", "keys.format")]
    [InlineData("<key", "keys.xml")]
    [InlineData("<!DOCTYPE key [<!ENTITY outside SYSTEM 'file:///nonexistent-synthetic-fixture'>]><key>&outside;</key>", "keys.xml")]
    public void Storage_RejectsInvalidCommittedXmlWithoutRepair(string xml, string code)
    {
        using var fixture = new Fixture();
        var file = fixture.Write(xml);
        var before = File.ReadAllBytes(file);
        Reject(code, () => fixture.Open());
        Assert.True(before.SequenceEqual(File.ReadAllBytes(file)), "Rejected committed file was modified.");
        Assert.Single(Directory.GetFiles(fixture.Keys));
    }

    /// <summary>Metadata and deserializer/decryptor identifiers must match the supported framework format before type activation.</summary>
    [Theory]
    [InlineData("date", "keys.format")]
    [InlineData("deserializer", "keys.algorithm")]
    [InlineData("decryptor", "keys.algorithm")]
    [InlineData("encryption", "keys.algorithm")]
    [InlineData("validation", "keys.algorithm")]
    public void Storage_RejectsUnsupportedMetadataAndTypes(string damage, string code)
    {
        using var fixture = new Fixture();
        using (var ring = fixture.Open()) { _ = ring.CreateProtector("fixture").Protect(Plaintext); }
        var file = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        var xml = XElement.Load(file);
        if (damage == "date") { xml.Element("creationDate")!.Remove(); }
        else if (damage == "deserializer") { xml.Element("descriptor")!.SetAttributeValue("deserializerType", "unsupported-type"); }
        else if (damage == "decryptor") { xml.Descendants().Single(node => node.Name.LocalName == "encryptedSecret").SetAttributeValue("decryptorType", "unsupported-type"); }
        else { xml.Descendants(damage).Single().SetAttributeValue("algorithm", "unsupported-algorithm"); }
        xml.Save(file);
        Reject(code, () => fixture.Open());
    }

    /// <summary>Only an explicit supplied private-certificate envelope is accepted; ambient key names and URI/store resolution cannot become fallback authority.</summary>
    [Theory]
    [InlineData("keyName", "keys.envelope")]
    [InlineData("retrieval", "keys.envelope")]
    [InlineData("cipherReference", "keys.envelope")]
    [InlineData("certificate", "keys.certificateMissing")]
    public void Storage_RefusesAmbientKeyAndCertificateFallbacks(string damage, string code)
    {
        using var fixture = new Fixture();
        using (var ring = fixture.Open()) { _ = ring.CreateProtector("fixture").Protect(Plaintext); }
        var file = Assert.Single(Directory.GetFiles(fixture.Keys, "key-*.xml"));
        var xml = XElement.Load(file);
        XNamespace encryption = "http://www.w3.org/2001/04/xmlenc#";
        XNamespace signature = "http://www.w3.org/2000/09/xmldsig#";
        var data = xml.Descendants(encryption + "EncryptedData").Single();
        var wrapped = data.Element(signature + "KeyInfo")!.Element(encryption + "EncryptedKey")!;
        if (damage == "keyName")
        { data.Element(signature + "KeyInfo")!.ReplaceNodes(new XElement(signature + "KeyName", "synthetic-ambient-key")); }
        else if (damage == "retrieval")
        { wrapped.Element(signature + "KeyInfo")!.ReplaceNodes(new XElement(signature + "RetrievalMethod", new XAttribute("URI", "file:///nonexistent-synthetic-fixture"))); }
        else if (damage == "cipherReference")
        { data.Element(encryption + "CipherData")!.ReplaceNodes(new XElement(encryption + "CipherReference", new XAttribute("URI", "file:///nonexistent-synthetic-fixture"))); }
        else
        {
            using var other = Certificate();
            xml.Descendants(signature + "X509Certificate").Single().Value = Convert.ToBase64String(other.RawData);
        }
        xml.Save(file);
        Reject(code, () => fixture.Open());
    }

    /// <summary>Input resource limits stop oversized/deep documents and excessive files without partial key loading.</summary>
    [Theory]
    [InlineData("size", "keys.tooLarge")]
    [InlineData("depth", "keys.xmlDepth")]
    [InlineData("count", "keys.tooMany")]
    public void Storage_EnforcesResourceBounds(string kind, string code)
    {
        using var fixture = new Fixture();
        if (kind == "size") { fixture.Write(new string('x', 65537)); }
        else if (kind == "depth") { fixture.Write(string.Concat(Enumerable.Repeat("<x>", 20)) + string.Concat(Enumerable.Repeat("</x>", 20))); }
        else { for (var index = 0; index < 257; index++) { fixture.Write("", ".pending-" + Guid.NewGuid().ToString("N") + ".tmp"); } }
        Reject(code, () => fixture.Open());
    }

    /// <summary>Large but valid certificate metadata cannot make persistence allocate/write an unbounded key document.</summary>
    [Fact]
    public void Persistence_RejectsOversizedEncryptedOutputBeforeDiskWrite()
    {
        using var fixture = new Fixture();
        using var huge = Certificate(extraBytes: 70000);
        using var ring = ProtectedSessionKeyRing.Open(fixture.Options, huge);
        var failed = Assert.ThrowsAny<CryptographicException>(() => ring.CreateProtector("fixture").Protect(Plaintext));
        Assert.Equal("keys.tooLarge", Assert.IsType<SessionKeyStoreException>(failed.InnerException).Code);
        Assert.Empty(Directory.GetFiles(fixture.Keys));
    }

    /// <summary>Explicit configuration rejects missing directories, invalid identities and unsuitable certificate/private keys.</summary>
    [Fact]
    public void Configuration_RequiresPrivateDirectoryAndSuitableCertificates()
    {
        using var fixture = new Fixture();
        Assert.Throws<ArgumentException>(() => new ProtectedSessionKeyOptions("relative"));
        Assert.Throws<ArgumentException>(() => new ProtectedSessionKeyOptions(fixture.Keys, "bad/name"));
        Assert.Throws<ArgumentException>(() => new ProtectedSessionKeyOptions(fixture.Keys, new string('a', 129)));
        using var weak = Certificate(bits: 2048);
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, weak));
        using var signingOnly = Certificate(encipherment: false);
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, signingOnly));
        using var publicOnly = X509CertificateLoader.LoadCertificate(fixture.Certificate.Export(X509ContentType.Cert));
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, publicOnly));
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, fixture.Certificate, [fixture.Certificate]));
        Assert.Throws<ArgumentException>(() => ProtectedSessionKeyRing.Open(fixture.Options, fixture.Certificate, Enumerable.Repeat(fixture.Certificate, 8)));
        Directory.Delete(fixture.Keys);
        Reject("path.directoryMissing", () => fixture.Open());
        Assert.False(Directory.Exists(fixture.Keys));
    }

    /// <summary>Disposal invalidates all existing purpose chains and releases the owned provider/certificate handles.</summary>
    [Fact]
    public void Disposal_InvalidatesExistingProtectors()
    {
        using var fixture = new Fixture();
        var ring = fixture.Open();
        var protector = ring.CreateProtector("fixture").CreateProtector("nested");
        var payload = protector.Protect(Plaintext);
        ring.Dispose();
        ring.Dispose();
        Assert.Throws<ObjectDisposedException>(() => protector.Unprotect(payload));
        Assert.Throws<ObjectDisposedException>(() => ring.CreateProtector("fixture"));
    }

    private static void Reject(string code, Action action)
        => Assert.Equal(code, Assert.Throws<SessionKeyStoreException>(action).Code);

    [DllImport("libc", SetLastError = true)]
    private static extern int link(string existing, string newPath);

    private static X509Certificate2 Certificate(int bits = 3072, bool expired = false, bool encipherment = true, int extraBytes = 0)
    {
        using var rsa = RSA.Create(bits);
        var request = new CertificateRequest("CN=nergal-synthetic-wrapping-fixture", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(encipherment ? X509KeyUsageFlags.KeyEncipherment : X509KeyUsageFlags.DigitalSignature, true));
        if (extraBytes > 0) { request.CertificateExtensions.Add(new X509Extension("1.3.6.1.4.1.55555.1", new byte[extraBytes], false)); }
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(expired ? -2 : -1), DateTimeOffset.UtcNow.AddDays(expired ? -1 : 1));
    }

    private sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "nergal-session-keys-" + Guid.NewGuid().ToString("N"));
        internal string Keys => Path.Combine(Root, "keys");
        internal X509Certificate2 Certificate { get; } = ProtectedSessionKeyTests.Certificate();
        internal ProtectedSessionKeyOptions Options { get; }
        internal Fixture()
        {
            Directory.CreateDirectory(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(Keys, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Options = new(Keys);
        }
        internal ProtectedSessionKeyRing Open() => ProtectedSessionKeyRing.Open(Options, Certificate);
        internal string Write(string text, string? name = null)
        {
            var path = Path.Combine(Keys, name ?? ("key-" + Guid.NewGuid().ToString("N") + ".xml"));
            using var file = new FileStream(path, new FileStreamOptions
            { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
            file.Write(Encoding.UTF8.GetBytes(text));
            return path;
        }
        public void Dispose() { Certificate.Dispose(); Directory.Delete(Root, recursive: true); }
    }
}
