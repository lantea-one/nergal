using System.Runtime.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;
using Nergal.Core.Agent;
using Nergal.Linux;
using Nergal.LocalTransport;

namespace Nergal.Web;

/// <summary>One explicitly configured read-only local resource. Browser input never selects a socket, host, identity or command.</summary>
[SupportedOSPlatform("linux")]
internal static class ControllerStatus
{
    internal static void Configure(IServiceCollection services, IConfigurationSection settings)
    {
        var server = settings.GetValue<uint?>("ServerUserId") ?? throw new InvalidOperationException("AgentStatus:ServerUserId is required.");
        var group = settings.GetValue<uint?>("SocketGroupId") ?? throw new InvalidOperationException("AgentStatus:SocketGroupId is required.");
        var controller = LinuxProcessIdentity.EffectiveUserId;
        var overflow = LinuxProcessIdentity.ReadOverflowUserId();
        if (controller == 0 || controller == overflow || server == controller || server == overflow)
        { throw new InvalidOperationException("Agent status requires separate, unambiguous service identities and an unprivileged controller."); }
        var client = new UnixStatusClient(new UnixStatusClientOptions(settings["SocketPath"] ?? "", server, group));
        services.AddSingleton(client);
        services.AddRateLimiter(options => options.AddConcurrencyLimiter("local-status", limiter =>
        {
            limiter.PermitLimit = 4;
            limiter.QueueLimit = 0;
        }));
        services.AddAuthorization(options => options.AddPolicy("LocalAgentStatus", policy =>
            policy.AddAuthenticationSchemes(IdentityConstants.ApplicationScheme).RequireAuthenticatedUser()));
    }

    internal static void Map(WebApplication app)
    {
        app.MapGet("/agent/status", QueryAsync).WithName("local-agent-status")
            .RequireAuthorization("LocalAgentStatus").RequireRateLimiting("local-status");
    }

    private static async Task<IResult> QueryAsync(HttpContext context, UnixStatusClient client)
    {
        if (context.Request.Query.Count != 0 || context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody != false)
        { return Results.BadRequest(); }
        AgentStatusReply reply;
        try { reply = await client.QueryAsync(context.RequestAborted); }
        catch (LocalTransportException) { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        return Response(reply);
    }

    internal static IResult Response(AgentStatusReply reply) => reply.Outcome switch
    {
        AgentStatusOutcome.Matched or AgentStatusOutcome.Drift or AgentStatusOutcome.Unbound =>
            Results.Bytes(AgentStatusCodec.EncodeReply(reply), "application/json"),
        _ => Results.StatusCode(StatusCodes.Status503ServiceUnavailable)
    };
}
