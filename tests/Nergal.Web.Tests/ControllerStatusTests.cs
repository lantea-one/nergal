using System.Runtime.Versioning;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Nergal.Core.Agent;

namespace Nergal.Web.Tests;

/// <summary>Checks browser-visible status without creating a socket, opening a journal or observing a firewall.</summary>
[SupportedOSPlatform("linux")]
public sealed class ControllerStatusTests
{
    /// <summary>Omitted numeric identities must never bind to zero and implicitly trust root or a default group.</summary>
    [Theory]
    [InlineData("SocketGroupId", "ServerUserId")]
    [InlineData("ServerUserId", "SocketGroupId")]
    public void Configuration_RequiresExplicitIdentities(string supplied, string missing)
    {
        var values = new Dictionary<string, string?> { ["AgentStatus:" + supplied] = "0" };
        var settings = new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("AgentStatus");
        var services = new ServiceCollection();
        var error = Assert.Throws<InvalidOperationException>(() => ControllerStatus.Configure(services, settings));
        Assert.Contains(missing, error.Message);
        Assert.Empty(services);
    }

    /// <summary>All failures have the same HTTP status and empty body, without agent diagnostics or resource metadata.</summary>
    [Theory]
    [InlineData(AgentStatusOutcome.Unavailable)]
    [InlineData(AgentStatusOutcome.Denied)]
    [InlineData(AgentStatusOutcome.InvalidRequest)]
    public async Task Failures_DiscloseNoMetadata(AgentStatusOutcome outcome)
    {
        var (status, body) = await Render(new(outcome));
        Assert.Equal(503, status);
        Assert.Empty(body);
    }

    /// <summary>The authenticated presentation preserves each recognized resource classification and the entire unsigned revision.</summary>
    [Theory]
    [InlineData(AgentStatusOutcome.Unbound, "unbound")]
    [InlineData(AgentStatusOutcome.Drift, "drift")]
    [InlineData(AgentStatusOutcome.Matched, "matched")]
    public async Task ResourceStatus_PreservesExactRevision(AgentStatusOutcome outcome, string name)
    {
        var (status, body) = await Render(new(outcome, ulong.MaxValue));
        Assert.Equal(200, status);
        Assert.Equal($$"""{"schemaVersion":1,"outcome":"{{name}}","revision":"18446744073709551615"}""", body);
    }

    private static async Task<(int Status, string Body)> Render(AgentStatusReply reply)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var http = new DefaultHttpContext { RequestServices = services };
        using var stream = new MemoryStream();
        http.Response.Body = stream;
        await ControllerStatus.Response(reply).ExecuteAsync(http);
        return (http.Response.StatusCode, Encoding.UTF8.GetString(stream.ToArray()));
    }
}
