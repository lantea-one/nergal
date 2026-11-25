using System.Formats.Asn1;
using System.Text;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises the LDAP wire boundary using bounded synthetic messages and no network access.</summary>
public sealed class LdapWireCodecTests
{
    /// <summary>Preserves Unicode and filter punctuation as one equality value and encodes an explicit empty attribute selection.</summary>
    [Fact]
    public void Search_EncodesLiteralAssertionAndNoAttributeSelection()
    {
        const string name = "a*()\\é";
        var packet = new AsnReader(LdapWireCodec.EncodeSearch(1, "dc=example", true, "uid", name, []), AsnEncodingRules.BER);
        var envelope = packet.ReadSequence();
        Assert.Equal(1, (int)envelope.ReadInteger());
        var search = envelope.ReadSequence(new Asn1Tag(TagClass.Application, 3, isConstructed: true));
        Assert.Equal("dc=example", Encoding.UTF8.GetString(search.ReadOctetString()));
        Assert.Equal(2, (int)search.ReadEnumeratedValue<SearchOption>());
        Assert.Equal(0, (int)search.ReadEnumeratedValue<SearchOption>());
        Assert.Equal(2, (int)search.ReadInteger());
        Assert.InRange((int)search.ReadInteger(), 1, 10);
        Assert.False(search.ReadBoolean());

        var equality = search.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true));
        Assert.Equal("uid", Encoding.UTF8.GetString(equality.ReadOctetString()));
        Assert.Equal(name, Encoding.UTF8.GetString(equality.ReadOctetString()));
        equality.ThrowIfNotEmpty();

        var selection = search.ReadSequence();
        Assert.Equal("1.1", Encoding.UTF8.GetString(selection.ReadOctetString()));
        selection.ThrowIfNotEmpty();
        search.ThrowIfNotEmpty();
        envelope.ThrowIfNotEmpty();
        packet.ThrowIfNotEmpty();
    }

    /// <summary>Rejects replies that cannot belong to the outstanding operation and refuses search referrals.</summary>
    [Theory]
    [InlineData(2, 5)]
    [InlineData(0, 5)]
    [InlineData(1, 19)]
    public void Response_RejectsUncorrelatedAndUnsupportedOperations(int messageId, int operation)
    {
        Assert.Throws<IOException>(() => LdapWireCodec.ReadResponse(Message(messageId, operation), 1));
    }

    /// <summary>Rejects an LDAP result carrying unsupported trailing fields such as a referral.</summary>
    [Fact]
    public void Result_RejectsTrailingFields()
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteEnumeratedValue(LdapWireResult.Success);
            writer.WriteOctetString([]);
            writer.WriteOctetString([]);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            { writer.WriteOctetString("ldaps://other.example.test"u8); }
        }
        var result = new AsnReader(writer.Encode(), AsnEncodingRules.BER).ReadSequence();

        Assert.Throws<AsnContentException>(() => LdapWireCodec.ReadResult(result));
    }

    /// <summary>Accepted bind, search and compare results must have an empty matched DN.</summary>
    [Theory]
    [InlineData(1, 0)]
    [InlineData(5, 0)]
    [InlineData(15, 5)]
    [InlineData(15, 6)]
    public void Result_RejectsUnexpectedMatchedDn(int operation, int result)
    {
        var frame = Message(1, operation, writer =>
        {
            writer.WriteEnumeratedValue((LdapWireResult)result);
            writer.WriteOctetString("dc=example"u8);
            writer.WriteOctetString([]);
        });

        var response = LdapWireCodec.ReadResponse(frame, 1);
        Assert.Throws<IOException>(() => LdapWireCodec.ReadResult(response.Fields));
    }

    /// <summary>Refuses unsolicited attributes and duplicate names even when their case differs.</summary>
    [Theory]
    [InlineData("entryUUID", "userPassword")]
    [InlineData("entryUUID", "ENTRYUUID")]
    public void SearchEntry_RejectsAmbiguousOrUnrequestedAttributes(string first, string second)
    {
        var frame = Message(1, 4, writer =>
        {
            writer.WriteOctetString("uid=user,dc=example"u8);
            using (writer.PushSequence())
            {
                foreach (var name in new[] { first, second })
                {
                    using (writer.PushSequence())
                    {
                        writer.WriteOctetString(Encoding.ASCII.GetBytes(name));
                        using (writer.PushSetOf())
                        { writer.WriteOctetString("example value"u8); }
                    }
                }
            }
        });
        var response = LdapWireCodec.ReadResponse(frame, 1);
        var requested = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "entryUUID" };

        Assert.Throws<IOException>(() => LdapWireCodec.ReadEntry(response.Fields, requested));
    }

    private static byte[] Message(int messageId, int operation, Action<AsnWriter>? fields = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.BER);
        using (writer.PushSequence())
        {
            writer.WriteInteger(messageId);
            using (writer.PushSequence(new Asn1Tag(TagClass.Application, operation, isConstructed: true)))
            { fields?.Invoke(writer); }
        }
        return writer.Encode();
    }

    private enum SearchOption { Never = 0, WholeSubtree = 2 }
}
