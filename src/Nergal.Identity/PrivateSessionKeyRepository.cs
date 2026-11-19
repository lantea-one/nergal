using System.Runtime.Versioning;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Nergal.Linux;

namespace Nergal.Identity;

// Append-only bounded persistence. No caller-provided filename, overwrite, deletion API or fallback store.
[SupportedOSPlatform("linux")]
internal sealed class PrivateSessionKeyRepository : IXmlRepository
{
    private readonly ProtectedSessionKeyOptions options;
    private readonly CertificateMaterial[] wrappingCertificates;
    private const int MaximumBytes = 65536;
    private const int MaximumEntries = 256;
    private static readonly XName EncryptedSecret = XName.Get("encryptedSecret", "http://schemas.asp.net/2015/03/dataProtection");
    private readonly object gate = new();
    private readonly Dictionary<string, byte[]> committedDigests = new(StringComparer.Ordinal);
    private long generation;
    internal long Generation { get { lock (gate) { return generation; } } }
    internal PrivateSessionKeyRepository(ProtectedSessionKeyOptions options, IEnumerable<X509Certificate2> certificates)
    {
        this.options = options;
        wrappingCertificates = certificates.Select(certificate =>
        {
            using var rsa = certificate.GetRSAPublicKey() ?? throw new ArgumentException("An RSA wrapping certificate is required.");
            return new CertificateMaterial(certificate.RawData, rsa.KeySize / 8);
        }).ToArray();
    }

    public IReadOnlyCollection<XElement> GetAllElements() => Guard(() =>
    {
        PrivateIdentityPath.RequireDirectory(options.Directory);
        var files = Directory.EnumerateFileSystemEntries(options.Directory).Take(MaximumEntries + 1).Order(StringComparer.Ordinal).ToArray();
        if (files.Length > MaximumEntries) { throw new SessionKeyStoreException("keys.tooMany"); }
        var elements = new List<XElement>();
        var keyIds = new HashSet<Guid>();
        var observed = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var path in files)
        {
            _ = PrivateIdentityPath.ReadFile(path) ?? throw new SessionKeyStoreException("keys.missing");
            var name = Path.GetFileName(path);
            var pending = KnownName(name, ".pending-", ".tmp");
            if (!pending && !KnownName(name, "key-", ".xml")) { throw new SessionKeyStoreException("keys.name"); }
            var bytes = ReadBounded(path);
            if (!pending)
            {
                var digest = SHA256.HashData(bytes);
                if (committedDigests.TryGetValue(path, out var prior) && !CryptographicOperations.FixedTimeEquals(prior, digest))
                { throw new SessionKeyStoreException("keys.changed"); }
                observed.Add(path, digest);
                var element = Parse(bytes);
                if (element.Name == "key" && !keyIds.Add(Guid.Parse(element.Attribute("id")!.Value)))
                { throw new SessionKeyStoreException("keys.duplicate"); }
                elements.Add(element);
            }
        }
        if (committedDigests.Keys.Any(path => !observed.ContainsKey(path))) { throw new SessionKeyStoreException("keys.missing"); }
        if (observed.Keys.Any(path => !committedDigests.ContainsKey(path))) { generation++; }
        foreach (var item in observed) { committedDigests[item.Key] = item.Value; }
        return (IReadOnlyCollection<XElement>)elements.AsReadOnly();
    });

    public void StoreElement(XElement element, string friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        Guard(() =>
        {
            // Serialize into a bounded independent snapshot before touching disk.
            using var buffer = new KeyBuffer();
            using (var source = element.CreateReader())
            {
                var count = 0;
                while (source.Read())
                {
                    if (source.Depth > 16 || ++count > 32768) { throw new SessionKeyStoreException("keys.xmlDepth"); }
                }
            }
            using (var writer = XmlWriter.Create(buffer, new XmlWriterSettings { Encoding = new UTF8Encoding(false), CloseOutput = false }))
            { element.Save(writer); }
            var bytes = buffer.ToArray();
            _ = Parse(bytes);
            _ = GetAllElements(); // Never append over an invalid committed key set.
            var entries = Directory.EnumerateFileSystemEntries(options.Directory).Take(MaximumEntries + 1).Count();
            if (entries >= MaximumEntries) { throw new SessionKeyStoreException("keys.tooMany"); }
            // friendlyName is deliberately unused: it cannot become a path or expose input in filenames.
            var id = Guid.NewGuid().ToString("N");
            var pending = Path.Combine(options.Directory, ".pending-" + id + ".tmp");
            var committed = Path.Combine(options.Directory, "key-" + id + ".xml");
            LinuxNodeMetadata? created = null;
            try
            {
                using (var file = new FileStream(pending, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                }))
                {
                    created = PrivateIdentityPath.ReadFile(pending) ?? throw new SessionKeyStoreException("keys.missing");
                    file.Write(bytes);
                    file.Flush(true);
                }
                if (PrivateIdentityPath.ReadFile(pending) != created) { throw new SessionKeyStoreException("keys.pathChanged"); }
                File.Move(pending, committed, overwrite: false);
                if (PrivateIdentityPath.ReadFile(committed) != created) { throw new SessionKeyStoreException("keys.pathChanged"); }
                LinuxDirectoryDurability.Synchronize(options.Directory);
                committedDigests.Add(committed, SHA256.HashData(bytes));
                generation++;
            }
            finally
            {
                if (created is { } own && PrivateIdentityPath.ReadFile(pending) is { } current)
                {
                    if (own != current) { throw new SessionKeyStoreException("keys.pathChanged"); }
                    File.Delete(pending);
                }
            }
            return true;
        });
    }

    private static byte[] ReadBounded(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var bytes = new byte[MaximumBytes + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = stream.Read(bytes.AsSpan(count));
            if (read == 0) { return bytes.AsSpan(0, count).ToArray(); }
            count += read;
        }
        throw new SessionKeyStoreException("keys.tooLarge");
    }

    private XElement Parse(byte[] bytes)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumBytes,
            MaxCharactersFromEntities = 0
        };
        using var stream = new MemoryStream(bytes, writable: false);
        using (var check = XmlReader.Create(stream, settings))
        {
            while (check.Read())
            {
                if (check.Depth > 16 || check.NodeType == XmlNodeType.ProcessingInstruction)
                { throw new SessionKeyStoreException("keys.xmlDepth"); }
            }
        }
        stream.Position = 0;
        using var reader = XmlReader.Create(stream, settings);
        var element = XElement.Load(reader);
        var key = element.Name == "key";
        if ((!key && element.Name != "revocation") || (string?)element.Attribute("version") != "1" ||
            element.DescendantsAndSelf().Any(node => node.Name.LocalName == "masterKey"))
        { throw new SessionKeyStoreException("keys.format"); }
        if (key)
        {
            if (!Guid.TryParseExact((string?)element.Attribute("id"), "D", out var id) || id == Guid.Empty ||
                element.Descendants(EncryptedSecret).Count() != 1 ||
                element.Descendants("descriptor").Count(node => node.Attribute("deserializerType") is not null) != 1)
            { throw new SessionKeyStoreException("keys.format"); }
            if (!element.Elements().Select(node => node.Name.ToString()).Order(StringComparer.Ordinal)
                .SequenceEqual(new[] { "activationDate", "creationDate", "descriptor", "expirationDate" }))
            { throw new SessionKeyStoreException("keys.format"); }
            try
            {
                var created = XmlConvert.ToDateTimeOffset(element.Element("creationDate")!.Value);
                var active = XmlConvert.ToDateTimeOffset(element.Element("activationDate")!.Value);
                var expired = XmlConvert.ToDateTimeOffset(element.Element("expirationDate")!.Value);
                if (expired <= active || expired < created) { throw new SessionKeyStoreException("keys.format"); }
            }
            catch (FormatException) { throw new SessionKeyStoreException("keys.format"); }
            if ((string?)element.Descendants(EncryptedSecret).Single().Attribute("decryptorType") != typeof(EncryptedXmlDecryptor).AssemblyQualifiedName)
            { throw new SessionKeyStoreException("keys.algorithm"); }
            var definitions = element.Element("descriptor")!.Elements().ToArray();
            if (definitions.Length != 1 || definitions[0].Name != "descriptor") { throw new SessionKeyStoreException("keys.format"); }
            var definition = definitions[0];
            if ((string?)definition.Element("encryption")?.Attribute("algorithm") != "AES_256_CBC" ||
                (string?)definition.Element("validation")?.Attribute("algorithm") != "HMACSHA256")
            { throw new SessionKeyStoreException("keys.algorithm"); }
            RequireEnvelope(element.Descendants(EncryptedSecret).Single());
        }
        else
        {
            if (!element.Elements().Select(node => node.Name.ToString()).Order(StringComparer.Ordinal)
                .SequenceEqual(new[] { "key", "reason", "revocationDate" }))
            { throw new SessionKeyStoreException("keys.format"); }
            try { _ = XmlConvert.ToDateTimeOffset(element.Element("revocationDate")!.Value); }
            catch (FormatException) { throw new SessionKeyStoreException("keys.format"); }
            var target = (string?)element.Element("key")!.Attribute("id");
            if (target != "*" && (!Guid.TryParseExact(target, "D", out var id) || id == Guid.Empty))
            { throw new SessionKeyStoreException("keys.format"); }
        }
        foreach (var attribute in element.DescendantsAndSelf().Attributes())
        {
            if ((attribute.Name.LocalName == "deserializerType" && attribute.Value != typeof(AuthenticatedEncryptorDescriptorDeserializer).AssemblyQualifiedName) ||
                (attribute.Name.LocalName == "decryptorType" && attribute.Value != typeof(EncryptedXmlDecryptor).AssemblyQualifiedName))
            { throw new SessionKeyStoreException("keys.algorithm"); }
        }
        return element;
    }

    private void RequireEnvelope(XElement secret)
    {
        XNamespace encryption = "http://www.w3.org/2001/04/xmlenc#";
        XNamespace signature = "http://www.w3.org/2000/09/xmldsig#";
        RequireChildren(secret, encryption + "EncryptedData");
        var data = secret.Element(encryption + "EncryptedData")!;
        RequireChildren(data, encryption + "EncryptionMethod", signature + "KeyInfo", encryption + "CipherData");
        RequireChildren(data.Element(encryption + "EncryptionMethod")!);
        if ((string?)data.Attribute("Type") != "http://www.w3.org/2001/04/xmlenc#Element" ||
            (string?)data.Element(encryption + "EncryptionMethod")!.Attribute("Algorithm") != "http://www.w3.org/2001/04/xmlenc#aes256-cbc")
        { throw new SessionKeyStoreException("keys.envelope"); }
        var keyInfo = data.Element(signature + "KeyInfo")!;
        RequireChildren(keyInfo, encryption + "EncryptedKey");
        var key = keyInfo.Element(encryption + "EncryptedKey")!;
        RequireChildren(key, encryption + "EncryptionMethod", signature + "KeyInfo", encryption + "CipherData");
        RequireChildren(key.Element(encryption + "EncryptionMethod")!);
        if ((string?)key.Element(encryption + "EncryptionMethod")!.Attribute("Algorithm") != "http://www.w3.org/2001/04/xmlenc#rsa-1_5")
        { throw new SessionKeyStoreException("keys.envelope"); }
        var certificateInfo = key.Element(signature + "KeyInfo")!;
        RequireChildren(certificateInfo, signature + "X509Data");
        var certificateData = certificateInfo.Element(signature + "X509Data")!;
        RequireChildren(certificateData, signature + "X509Certificate");
        try
        {
            var encoded = certificateData.Element(signature + "X509Certificate")!;
            RequireChildren(encoded);
            var publicCertificate = Convert.FromBase64String(encoded.Value);
            var configured = wrappingCertificates.SingleOrDefault(certificate => certificate.PublicDer.AsSpan().SequenceEqual(publicCertificate));
            if (configured is null) { throw new SessionKeyStoreException("keys.certificateMissing"); }
            var wrapped = Cipher(key.Element(encryption + "CipherData")!, encryption);
            var encrypted = Cipher(data.Element(encryption + "CipherData")!, encryption);
            if (wrapped.Length != configured.RsaBytes || encrypted.Length < 32 || encrypted.Length % 16 != 0)
            { throw new SessionKeyStoreException("keys.envelope"); }
        }
        catch (FormatException) { throw new SessionKeyStoreException("keys.envelope"); }
        // Requiring one exact configured private-certificate envelope prevents
        // EncryptedXml's ambient X509Store/key-name/retrieval fallbacks.
    }
    private static byte[] Cipher(XElement cipherData, XNamespace encryption)
    {
        RequireChildren(cipherData, encryption + "CipherValue");
        var value = cipherData.Element(encryption + "CipherValue")!;
        RequireChildren(value);
        return Convert.FromBase64String(value.Value);
    }
    private static void RequireChildren(XElement element, params XName[] children)
    {
        if (!element.Elements().Select(child => child.Name).OrderBy(name => name.ToString(), StringComparer.Ordinal)
            .SequenceEqual(children.OrderBy(name => name.ToString(), StringComparer.Ordinal)))
        { throw new SessionKeyStoreException("keys.envelope"); }
    }
    private sealed record CertificateMaterial(byte[] PublicDer, int RsaBytes);

    private static bool KnownName(string name, string prefix, string suffix)
    {
        if (!name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(suffix, StringComparison.Ordinal)) { return false; }
        var middle = name.AsSpan(prefix.Length, name.Length - prefix.Length - suffix.Length);
        return Guid.TryParseExact(middle, "N", out var id) && id != Guid.Empty && middle.SequenceEqual(id.ToString("N"));
    }
    private T Guard<T>(Func<T> action)
    {
        lock (gate)
        {
            try { return action(); }
            catch (AccountStoreException error) { throw new SessionKeyStoreException(error.Code); }
            catch (Exception error) when (error is IOException and not SessionKeyStoreException or UnauthorizedAccessException)
            { throw new SessionKeyStoreException("keys.io"); }
            catch (Exception error) when (error is XmlException or InvalidOperationException)
            { throw new SessionKeyStoreException("keys.xml"); }
        }
    }
    private sealed class KeyBuffer : Stream
    {
        private readonly MemoryStream contents = new();
        internal byte[] ToArray() => contents.ToArray();
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => contents.Length;
        public override long Position { get => contents.Position; set => throw new NotSupportedException(); }
        public override void Flush() => contents.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (Position + buffer.Length > MaximumBytes) { throw new SessionKeyStoreException("keys.tooLarge"); }
            contents.Write(buffer);
        }
        public override void WriteByte(byte value)
        {
            if (Position == MaximumBytes) { throw new SessionKeyStoreException("keys.tooLarge"); }
            contents.WriteByte(value);
        }
        protected override void Dispose(bool disposing) { if (disposing) { contents.Dispose(); } base.Dispose(disposing); }
    }
}
