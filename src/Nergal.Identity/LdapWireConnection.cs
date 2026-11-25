using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Nergal.Identity;

/// <summary>One authenticated TLS transport to an exact address, with at most one outstanding LDAPv3 request.</summary>
internal sealed class LdapWireConnection : IDisposable
{
    private readonly TcpClient client;
    private readonly SslStream stream;
    private int lastMessageId;
    private int operationInProgress;
    private int disposed;

    private LdapWireConnection(TcpClient client, SslStream stream)
    {
        this.client = client;
        this.stream = stream;
    }

    /// <summary>Dials the supplied address once and validates the configured peer name using system trust.</summary>
    internal static async Task<LdapWireConnection> OpenAsync(IPAddress address, string peerName, int port,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(peerName) || port is < 1 or > 65535)
        { throw new IOException("Invalid LDAPS endpoint."); }

        var client = new TcpClient(address.AddressFamily);
        SslStream? stream = null;
        var opened = false;
        try
        {
            await client.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            stream = new SslStream(client.GetStream());
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = peerName,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                AllowRenegotiation = false,
                AllowTlsResume = false,
                CertificateChainPolicy = new X509ChainPolicy
                {
                    // An untrusted peer cannot add network destinations through certificate extensions.
                    TrustMode = X509ChainTrustMode.System,
                    DisableCertificateDownloads = true,
                    RevocationMode = X509RevocationMode.NoCheck
                }
            }, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            opened = true;
            return new LdapWireConnection(client, stream);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException or SocketException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new IOException("LDAPS connection failed.");
        }
        finally
        {
            if (!opened)
            {
                stream?.Dispose();
                client.Dispose();
            }
        }
    }

    /// <summary>Performs a nonempty LDAPv3 simple bind. Invalid credentials return false and close the connection.</summary>
    internal Task<bool> BindAsync(string distinguishedName, string password, CancellationToken cancellationToken) =>
        ExchangeAsync(async messageId =>
        {
            await WriteRequestAsync(LdapWireCodec.EncodeBind(messageId, distinguishedName, password), cancellationToken)
                .ConfigureAwait(false);
            var result = await ReadResultAsync(messageId, LdapWireCodec.BindResponse, cancellationToken).ConfigureAwait(false);
            return result switch
            {
                LdapWireResult.Success => true,
                LdapWireResult.InvalidCredentials => false,
                _ => throw OperationFailed()
            };
        }, cancellationToken, closeAfterResult: static bound => !bound);

    /// <summary>Returns at most two entries after a correlated successful search completion.</summary>
    internal Task<IReadOnlyList<LdapWireEntry>> SearchAsync(string baseDn, bool subtree, string filterAttribute,
        string filterValue, IReadOnlyList<string> attributes, CancellationToken cancellationToken) =>
        ExchangeAsync<IReadOnlyList<LdapWireEntry>>(async messageId =>
        {
            var attributeCount = attributes.Count;
            if (attributeCount is < 0 or > LdapWireCodec.MaxAttributes) { throw OperationFailed(); }
            var selection = new string[attributeCount];
            for (var index = 0; index < selection.Length; index++) { selection[index] = attributes[index]; }
            var requestedAttributes = new HashSet<string>(selection, StringComparer.OrdinalIgnoreCase);
            await WriteRequestAsync(LdapWireCodec.EncodeSearch(messageId, baseDn, subtree, filterAttribute,
                filterValue, selection), cancellationToken).ConfigureAwait(false);

            var entries = new List<LdapWireEntry>(LdapWireCodec.MaxSearchEntries);
            while (true)
            {
                var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
                var (tag, fields) = LdapWireCodec.ReadResponse(frame, messageId);
                if (tag == LdapWireCodec.SearchDone)
                {
                    if (LdapWireCodec.ReadResult(fields) != LdapWireResult.Success) { throw OperationFailed(); }
                    return entries.AsReadOnly();
                }
                if (tag != LdapWireCodec.SearchEntry || entries.Count >= LdapWireCodec.MaxSearchEntries)
                { throw OperationFailed(); }
                entries.Add(LdapWireCodec.ReadEntry(fields, requestedAttributes));
            }
        }, cancellationToken);

    /// <summary>Asks the directory to apply its equality matching rule to the group's direct member attribute.</summary>
    internal Task<bool> CompareMemberAsync(string groupDn, string userDn, CancellationToken cancellationToken) =>
        ExchangeAsync(async messageId =>
        {
            await WriteRequestAsync(LdapWireCodec.EncodeCompare(messageId, groupDn, userDn), cancellationToken)
                .ConfigureAwait(false);
            var result = await ReadResultAsync(messageId, LdapWireCodec.CompareResponse, cancellationToken)
                .ConfigureAwait(false);
            return result switch
            {
                LdapWireResult.CompareTrue => true,
                LdapWireResult.CompareFalse => false,
                _ => throw OperationFailed()
            };
        }, cancellationToken);

    /// <summary>Closes the TLS stream and socket without issuing any further LDAP requests.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) { return; }
        try { stream.Dispose(); }
        finally { client.Dispose(); }
    }

    private async Task<T> ExchangeAsync<T>(Func<int, Task<T>> exchange, CancellationToken cancellationToken,
        Func<T, bool>? closeAfterResult = null)
    {
        if (Interlocked.CompareExchange(ref operationInProgress, 1, 0) != 0)
        {
            Dispose();
            throw OperationFailed();
        }

        var completed = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref disposed) != 0 || lastMessageId == int.MaxValue) { throw OperationFailed(); }
            var result = await exchange(++lastMessageId).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref disposed) != 0) { throw OperationFailed(); }
            if (closeAfterResult?.Invoke(result) == true) { Dispose(); }
            completed = true;
            return result;
        }
        catch (Exception exception) when (exception is IOException or SocketException or AsnContentException or
            DecoderFallbackException or EncoderFallbackException or ObjectDisposedException or AuthenticationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw OperationFailed();
        }
        finally
        {
            // Cancellation or failure can leave request bytes or unread responses on the connection.
            try
            {
                if (!completed) { Dispose(); }
            }
            finally { Volatile.Write(ref operationInProgress, 0); }
        }
    }

    private async Task WriteRequestAsync(byte[] request, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            await stream.WriteAsync(request.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(request); }
    }

    private async Task<LdapWireResult> ReadResultAsync(int messageId, Asn1Tag expectedTag,
        CancellationToken cancellationToken)
    {
        var frame = await ReadFrameAsync(cancellationToken).ConfigureAwait(false);
        var (tag, fields) = LdapWireCodec.ReadResponse(frame, messageId);
        if (tag != expectedTag) { throw OperationFailed(); }
        return LdapWireCodec.ReadResult(fields);
    }

    private async Task<byte[]> ReadFrameAsync(CancellationToken cancellationToken)
    {
        // LDAPMessage has a one-octet SEQUENCE tag and a definite BER length.
        var header = new byte[6];
        await stream.ReadExactlyAsync(header.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
        if (header[0] != 0x30) { throw OperationFailed(); }

        var headerLength = 2;
        uint contentLength = header[1];
        if (contentLength >= 0x80)
        {
            var lengthOctets = header[1] & 0x7f;
            if (lengthOctets is < 1 or > 4) { throw OperationFailed(); }
            await stream.ReadExactlyAsync(header.AsMemory(2, lengthOctets), cancellationToken).ConfigureAwait(false);
            headerLength += lengthOctets;
            contentLength = 0;
            for (var index = 2; index < headerLength; index++)
            { contentLength = (contentLength << 8) | header[index]; }
        }
        if (contentLength is 0 or > LdapWireCodec.MaxFrameContentBytes) { throw OperationFailed(); }

        var frame = new byte[headerLength + (int)contentLength];
        header.AsSpan(0, headerLength).CopyTo(frame);
        await stream.ReadExactlyAsync(frame.AsMemory(headerLength), cancellationToken).ConfigureAwait(false);
        return frame;
    }

    private static IOException OperationFailed() => new("LDAP operation failed.");
}
