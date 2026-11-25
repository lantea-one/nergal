using System.Collections.ObjectModel;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace Nergal.Identity;

internal sealed record LdapWireEntry(string DistinguishedName, IReadOnlyDictionary<string, IReadOnlyList<byte[]>> Attributes);

internal enum LdapWireResult
{
    Success = 0,
    CompareFalse = 5,
    CompareTrue = 6,
    InvalidCredentials = 49
}

/// <summary>Encodes and reads the bounded LDAPv3 authentication subset of RFC 4511.</summary>
internal static class LdapWireCodec
{
    internal const int MaxFrameContentBytes = 32 * 1024;
    internal const int MaxSearchEntries = 2;
    internal const int MaxAttributes = 8;

    private const int MaxDnBytes = 2048;
    private const int MaxPasswordBytes = 4096;
    private const int MaxAttributeNameBytes = 64;
    private const int MaxAttributeValueBytes = 2048;
    private const int MaxValuesPerAttribute = 8;
    private const int MaxDiagnosticBytes = 2048;
    private const string NoAttributes = "1.1";
    private static readonly UTF8Encoding Utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    internal static readonly Asn1Tag BindResponse = Application(1);
    internal static readonly Asn1Tag SearchEntry = Application(4);
    internal static readonly Asn1Tag SearchDone = Application(5);
    internal static readonly Asn1Tag CompareResponse = Application(15);

    private enum SearchScope { BaseObject = 0, WholeSubtree = 2 }
    private enum DerefAliases { Never = 0 }

    internal static byte[] EncodeBind(int messageId, string distinguishedName, string password)
    {
        if (password is not { Length: > 0 and <= MaxPasswordBytes } || password.Contains('\0'))
        { throw InvalidRequest(); }
        var name = EncodeText(distinguishedName, MaxDnBytes, distinguishedNameField: true);
        var secret = EncodeText(password, MaxPasswordBytes);
        try
        {
            // Reserve room for both fields and their BER headers so the writer keeps one credential-bearing buffer.
            return EncodeRequest(messageId, Application(0), writer =>
            {
                writer.WriteInteger(3);
                writer.WriteOctetString(name);
                writer.WriteOctetString(secret, new Asn1Tag(TagClass.ContextSpecific, 0));
            }, name.Length + secret.Length + 64);
        }
        finally { CryptographicOperations.ZeroMemory(secret); }
    }

    internal static byte[] EncodeSearch(int messageId, string baseDn, bool subtree, string filterAttribute,
        string filterValue, IReadOnlyList<string> attributes)
    {
        var name = EncodeText(baseDn, MaxDnBytes, distinguishedNameField: true);
        ValidateAttributeDescription(filterAttribute);
        var assertion = EncodeText(filterValue, MaxAttributeValueBytes);
        if (attributes.Count > MaxAttributes) { throw InvalidRequest(); }

        var selected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in attributes)
        {
            if (attribute == NoAttributes && attributes.Count == 1) { break; }
            ValidateAttributeDescription(attribute);
            if (!selected.Add(attribute)) { throw InvalidRequest(); }
        }

        return EncodeRequest(messageId, Application(3), writer =>
        {
            writer.WriteOctetString(name);
            writer.WriteEnumeratedValue(subtree ? SearchScope.WholeSubtree : SearchScope.BaseObject);
            writer.WriteEnumeratedValue(DerefAliases.Never);
            writer.WriteInteger(MaxSearchEntries);
            writer.WriteInteger(10); // Also bound server work if the client disconnects.
            writer.WriteBoolean(false);
            // BER equalityMatch takes a literal assertion value, bypassing textual filter parsing.
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            {
                writer.WriteOctetString(Utf8.GetBytes(filterAttribute));
                writer.WriteOctetString(assertion);
            }
            using (writer.PushSequence())
            {
                if (selected.Count == 0) { writer.WriteOctetString("1.1"u8); }
                foreach (var attribute in selected) { writer.WriteOctetString(Utf8.GetBytes(attribute)); }
            }
        });
    }

    internal static byte[] EncodeCompare(int messageId, string groupDn, string userDn)
    {
        var group = EncodeText(groupDn, MaxDnBytes, distinguishedNameField: true);
        var user = EncodeText(userDn, MaxDnBytes, distinguishedNameField: true);
        return EncodeRequest(messageId, Application(14), writer =>
        {
            writer.WriteOctetString(group);
            using (writer.PushSequence())
            {
                writer.WriteOctetString("member"u8);
                writer.WriteOctetString(user);
            }
        });
    }

    internal static (Asn1Tag Tag, AsnReader Fields) ReadResponse(ReadOnlyMemory<byte> frame, int messageId)
    {
        if (messageId <= 0 || frame.Length > MaxFrameContentBytes + 6) { throw InvalidResponse(); }
        var packet = new AsnReader(frame, AsnEncodingRules.BER);
        var envelope = ReadSequence(packet, Asn1Tag.Sequence);
        packet.ThrowIfNotEmpty();
        if (!envelope.TryReadInt32(out var actualId) || actualId != messageId) { throw InvalidResponse(); }

        var tag = envelope.PeekTag();
        if (tag != BindResponse && tag != SearchEntry && tag != SearchDone && tag != CompareResponse)
        { throw InvalidResponse(); }

        var fields = ReadSequence(envelope, tag);
        envelope.ThrowIfNotEmpty(); // This subset accepts no controls, including noncritical ones.
        return (tag, fields);
    }

    internal static LdapWireResult ReadResult(AsnReader fields)
    {
        var result = fields.ReadEnumeratedValue<LdapWireResult>();
        var matchedDn = ReadOctets(fields, MaxDnBytes);
        var diagnostic = ReadOctets(fields, MaxDiagnosticBytes);
        // Validate UTF-8 without materializing or propagating the server's diagnostic text.
        _ = Utf8.GetCharCount(matchedDn.Span);
        _ = Utf8.GetCharCount(diagnostic.Span);
        if (matchedDn.Length != 0 && result is LdapWireResult.Success or LdapWireResult.CompareFalse or
            LdapWireResult.CompareTrue or LdapWireResult.InvalidCredentials)
        { throw InvalidResponse(); }
        fields.ThrowIfNotEmpty(); // Includes referrals and SASL-only bind fields.
        return result;
    }

    internal static LdapWireEntry ReadEntry(AsnReader fields, IReadOnlySet<string> requestedAttributes)
    {
        var dnBytes = ReadOctets(fields, MaxDnBytes);
        var distinguishedName = Utf8.GetString(dnBytes.Span);
        if (string.IsNullOrWhiteSpace(distinguishedName) || distinguishedName.Contains('\0'))
        { throw InvalidResponse(); }

        var attributes = ReadSequence(fields, Asn1Tag.Sequence);
        fields.ThrowIfNotEmpty();
        var entry = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        while (attributes.HasData)
        {
            if (entry.Count >= MaxAttributes) { throw InvalidResponse(); }
            var attribute = ReadSequence(attributes, Asn1Tag.Sequence);
            var name = Utf8.GetString(ReadOctets(attribute, MaxAttributeNameBytes).Span);
            if (name == NoAttributes || !requestedAttributes.Contains(name) || entry.ContainsKey(name))
            { throw InvalidResponse(); }

            RequireDefiniteLength(attribute, Asn1Tag.SetOf);
            var values = attribute.ReadSetOf(skipSortOrderValidation: true);
            attribute.ThrowIfNotEmpty();
            var decoded = new List<byte[]>();
            while (values.HasData)
            {
                if (decoded.Count >= MaxValuesPerAttribute) { throw InvalidResponse(); }
                decoded.Add(ReadOctets(values, MaxAttributeValueBytes).ToArray());
            }
            entry.Add(name, decoded.AsReadOnly());
        }
        return new LdapWireEntry(distinguishedName, new ReadOnlyDictionary<string, IReadOnlyList<byte[]>>(entry));
    }

    private static byte[] EncodeRequest(int messageId, Asn1Tag operation, Action<AsnWriter> writeFields,
        int initialCapacity = 0)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER, initialCapacity);
        try
        {
            using (writer.PushSequence())
            {
                writer.WriteInteger(messageId);
                using (writer.PushSequence(operation)) { writeFields(writer); }
            }
            return writer.Encode();
        }
        finally { writer.Reset(); }
    }

    private static byte[] EncodeText(string text, int maxBytes, bool distinguishedNameField = false)
    {
        // Check UTF-16 length before scanning for the encoded size, then allocate only within the byte bound.
        if (string.IsNullOrEmpty(text) || text.Length > maxBytes || Utf8.GetByteCount(text) > maxBytes ||
            (distinguishedNameField && (string.IsNullOrWhiteSpace(text) || text.Contains('\0'))))
        { throw InvalidRequest(); }
        return Utf8.GetBytes(text);
    }

    private static void ValidateAttributeDescription(string attribute)
    {
        // The supported selectors are literal descriptors. Wildcards, ranges and options could return other data.
        if (attribute is not { Length: > 0 and <= MaxAttributeNameBytes } || !char.IsAsciiLetter(attribute[0]) ||
            attribute.Any(character => !char.IsAsciiLetterOrDigit(character) && character != '-'))
        { throw InvalidRequest(); }
    }

    private static ReadOnlyMemory<byte> ReadOctets(AsnReader fields, int maxBytes)
    {
        if (!fields.TryReadPrimitiveOctetString(out var bytes) || bytes.Length > maxBytes)
        { throw InvalidResponse(); }
        return bytes;
    }

    private static AsnReader ReadSequence(AsnReader fields, Asn1Tag tag)
    {
        RequireDefiniteLength(fields, tag);
        return fields.ReadSequence(tag);
    }

    private static void RequireDefiniteLength(AsnReader fields, Asn1Tag tag)
    {
        // Supported constructed tags all occupy one octet. BER permits indefinite lengths, but LDAP does not.
        if (fields.PeekTag() != tag || fields.PeekEncodedValue().Span[1] == 0x80) { throw InvalidResponse(); }
    }

    private static Asn1Tag Application(int value) => new(TagClass.Application, value, isConstructed: true);

    private static IOException InvalidRequest() => new("Invalid LDAP request.");

    private static IOException InvalidResponse() => new("Invalid LDAP response.");
}
