using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies defensive response handling over a real TLS socket in the disposable LDAP fixture.</summary>
[SupportedOSPlatform("linux")]
public sealed class LdapWireLoopbackTests
{
    /// <summary>Requires the opt-in fixture to provide the synthetic trusted leaf and key.</summary>
    public static bool FixtureEnabled => Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_TLS_CERTIFICATE") is not null &&
        Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_TLS_KEY") is not null;

    /// <summary>Cancelling a pending bind closes the owned connection even while the peer withholds its reply.</summary>
    [Fact(Skip = "Requires the disposable fixture certificate.", SkipUnless = nameof(FixtureEnabled))]
    public async Task PendingBind_CancellationClosesConnection()
    {
        using var guard = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        guard.CancelAfter(TimeSpan.FromSeconds(5));
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var proof = StartProof(listener, attempt.Token);
        using var peer = await listener.AcceptTcpClientAsync(guard.Token);
        using var certificate = LoadCertificate();
        using var tls = new SslStream(peer.GetStream());
        await ReadBindAsync(tls, certificate, guard.Token);

        attempt.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => proof);
        // No second request can be sent on a canceled connection.
        var received = await tls.ReadAsync(new byte[1], guard.Token);
        Assert.Equal(0, received);
    }

    /// <summary>A declared response length above the limit is refused without waiting for the advertised body.</summary>
    [Fact(Skip = "Requires the disposable fixture certificate.", SkipUnless = nameof(FixtureEnabled))]
    public async Task PendingBind_OversizedFrameIsRejectedBeforeBody()
    {
        using var guard = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        guard.CancelAfter(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var proof = StartProof(listener, guard.Token);
        using var peer = await listener.AcceptTcpClientAsync(guard.Token);
        using var certificate = LoadCertificate();
        using var tls = new SslStream(peer.GetStream());
        await ReadBindAsync(tls, certificate, guard.Token);
        await tls.WriteAsync(new byte[] { 0x30, 0x82, 0x80, 0x01 }, guard.Token);

        Assert.Null(await proof);
    }

    private static Task<LdapDirectoryProof?> StartProof(TcpListener listener, CancellationToken cancellationToken)
    {
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var settings = new LdapDirectorySettings(Guid.Parse("6ee19299-2842-488f-9add-0291fd9a05af"),
            $"ldaps://directory.example.test:{port}", "ou=people,dc=example,dc=test", "cn=reader,dc=example,dc=test",
            "uid", "cn=administrators,dc=example,dc=test", "cn=auditors,dc=example,dc=test", new());
        return new LdapDirectoryAuthenticator().VerifyAsync(settings, IPAddress.Loopback, "fixture-reader-password",
            "administrator", "fixture-user-password", cancellationToken);
    }

    private static X509Certificate2 LoadCertificate() => X509Certificate2.CreateFromPemFile(
        Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_TLS_CERTIFICATE")!,
        Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_TLS_KEY")!);

    private static async Task ReadBindAsync(SslStream tls, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate },
            cancellationToken);
        var header = new byte[2];
        await tls.ReadExactlyAsync(header, cancellationToken);
        Assert.Equal(0x30, header[0]);
        var length = header[1];
        Assert.InRange((int)length, 1, 127);
        var request = new byte[length];
        await tls.ReadExactlyAsync(request, cancellationToken);
        Assert.Equal(0x60, request[3]); // Small message ID, followed by the LDAP BindRequest application tag.
    }
}
