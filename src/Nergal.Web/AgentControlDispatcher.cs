using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Linux;
using Nergal.LocalTransport;
using Nergal.RemoteTransport;

namespace Nergal.Web;

/// <summary>Dispatches typed control requests to an enrolled host agent over Unix or TLS mTLS transport.</summary>
public interface IAgentControlDispatcher
{
    /// <summary>Sends one typed control request to <paramref name="host"/> and verifies the reply.</summary>
    Task<AgentControlReply> SendAsync(
        ManagedHostRecord host,
        AgentControlRequest request,
        CancellationToken cancellationToken = default);
}

internal sealed record ControllerTlsClientConfig(string? CertificatePemPath, string? PrivateKeyPemPath)
{
    internal bool HasClientCertificate => CertificatePemPath is not null && PrivateKeyPemPath is not null;

    [SupportedOSPlatform("linux")]
    internal static ControllerTlsClientConfig FromConfiguration(IConfiguration config)
    {
        var certPath = string.IsNullOrWhiteSpace(config["TlsClientCertificatePath"])
            ? null
            : config["TlsClientCertificatePath"]!.Trim();
        var keyPath = string.IsNullOrWhiteSpace(config["TlsClientKeyPath"])
            ? null
            : config["TlsClientKeyPath"]!.Trim();

        if ((certPath is null) != (keyPath is null))
        {
            throw new InvalidOperationException("tls.clientConfigInvalid");
        }

        if (certPath is not null && keyPath is not null)
        {
            ValidateClientPemPaths(certPath, keyPath);
            using var validated = X509Certificate2.CreateFromPemFile(certPath, keyPath);
        }

        return new ControllerTlsClientConfig(certPath, keyPath);
    }

    [SupportedOSPlatform("linux")]
    internal static void ValidateClientPemPaths(string certPath, string keyPath)
    {
        if (!Path.IsPathRooted(certPath) || !Path.IsPathRooted(keyPath))
        {
            throw new InvalidOperationException("tls.clientConfigInvalid");
        }

        var fullCert = Path.GetFullPath(certPath);
        var fullKey = Path.GetFullPath(keyPath);
        EnsureNoSymlinkAncestors(Path.GetDirectoryName(fullCert), "tls.certInvalid");
        EnsureNoSymlinkAncestors(Path.GetDirectoryName(fullKey), "tls.keyPermissions");

        var certNode = LinuxFileSystem.Read(fullCert);
        if (certNode is null || certNode.Value.Type != LinuxNodeType.RegularFile || certNode.Value.LinkCount != 1)
        {
            throw new InvalidOperationException("tls.certInvalid");
        }

        var owner = LinuxProcessIdentity.EffectiveUserId;
        var keyParentPath = Path.GetDirectoryName(fullKey) ?? throw new InvalidOperationException("tls.keyPermissions");
        var keyParent = LinuxFileSystem.Read(keyParentPath);
        if (keyParent is null ||
            keyParent.Value.Type != LinuxNodeType.Directory ||
            keyParent.Value.OwnerUserId != owner ||
            (keyParent.Value.Permissions & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) != 0)
        {
            throw new InvalidOperationException("tls.keyPermissions");
        }

        var keyNode = LinuxFileSystem.Read(fullKey);
        if (keyNode is null ||
            keyNode.Value.Type != LinuxNodeType.RegularFile ||
            keyNode.Value.LinkCount != 1 ||
            keyNode.Value.OwnerUserId != owner ||
            keyNode.Value.Permissions != (UnixFileMode.UserRead | UnixFileMode.UserWrite))
        {
            throw new InvalidOperationException("tls.keyPermissions");
        }
    }

    private static void EnsureNoSymlinkAncestors(string? directory, string errorCode)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new InvalidOperationException(errorCode);
        }

        for (DirectoryInfo? part = new(directory); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
            {
                throw new InvalidOperationException(errorCode);
            }
        }
    }
}

[SupportedOSPlatform("linux")]
internal sealed class DefaultAgentControlDispatcher(ControllerTlsClientConfig tlsConfig) : IAgentControlDispatcher
{
    public async Task<AgentControlReply> SendAsync(
        ManagedHostRecord host,
        AgentControlRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(request);

        return host.TransportKind switch
        {
            AgentTransportKind.Unix => await SendUnixAsync(host, request, cancellationToken).ConfigureAwait(false),
            AgentTransportKind.Tls => await SendTlsAsync(host, request, cancellationToken).ConfigureAwait(false),
            _ => new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.unsupported"),
        };
    }

    private static async Task<AgentControlReply> SendUnixAsync(
        ManagedHostRecord host,
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        if (host.ExpectedServerUserId is null)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.unixInvalid");
        }

        try
        {
            var options = new UnixControlClientOptions(
                host.Endpoint,
                host.ExpectedServerUserId.Value,
                host.SocketGroupId,
                TimeSpan.FromSeconds(20));
            return await UnixControlClient.SendAsync(options, request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (LocalTransportException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.localUnavailable");
        }
        catch (Exception ex) when (ex is IOException or TimeoutException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.unavailable");
        }
    }

    private async Task<AgentControlReply> SendTlsAsync(
        ManagedHostRecord host,
        AgentControlRequest request,
        CancellationToken cancellationToken)
    {
        if (!tlsConfig.HasClientCertificate)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "tls.clientCertMissing");
        }

        if (string.IsNullOrEmpty(host.PinnedServerThumbprint) ||
            !TryParseHostPort(host.Endpoint, out var targetHost, out var port))
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.tlsInvalid");
        }

        try
        {
            ControllerTlsClientConfig.ValidateClientPemPaths(tlsConfig.CertificatePemPath!, tlsConfig.PrivateKeyPemPath!);
            using var clientCert = X509Certificate2.CreateFromPemFile(tlsConfig.CertificatePemPath!, tlsConfig.PrivateKeyPemPath!);
            var sni = IPAddress.TryParse(targetHost, out _) ? "nergal-agent" : targetHost;
            var options = new TlsControlClientOptions(
                targetHost,
                port,
                clientCert,
                [host.PinnedServerThumbprint],
                serverNameIndication: sni,
                exchangeTimeout: TimeSpan.FromSeconds(20));
            return await TlsControlClient.SendAsync(options, request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InvalidOperationException err) when (err.Message is "tls.certInvalid" or "tls.keyPermissions" or "tls.clientConfigInvalid")
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: err.Message);
        }
        catch (RemoteTransportException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.tlsUnavailable");
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or CryptographicException or ArgumentException)
        {
            return new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "transport.unavailable");
        }
    }

    private static bool TryParseHostPort(string endpoint, out string host, out int port)
    {
        host = "";
        port = 0;
        var colon = endpoint.LastIndexOf(':');
        if (colon <= 0 || colon >= endpoint.Length - 1)
        {
            return false;
        }

        if (!int.TryParse(endpoint.AsSpan(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) ||
            port is < 1 or > 65535)
        {
            return false;
        }

        var rawHost = endpoint[..colon];
        if (rawHost.Length >= 2 && rawHost[0] == '[' && rawHost[^1] == ']')
        {
            rawHost = rawHost[1..^1];
        }

        if (string.IsNullOrWhiteSpace(rawHost) || rawHost.Any(char.IsWhiteSpace))
        {
            return false;
        }

        host = rawHost;
        return true;
    }
}
