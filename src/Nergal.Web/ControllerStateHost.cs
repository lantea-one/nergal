using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web;

[SupportedOSPlatform("linux")]
internal static class ControllerStateHost
{
    internal static void Configure(IServiceCollection services, IConfigurationSection config)
    {
        var options = new ControllerStateOptions(config["Directory"] ?? "");
        var store = ControllerStateStore.Open(options);
        services.AddSingleton(store);
    }

    internal static void Map(WebApplication app)
    {
        app.MapGet("/controller/audit", ListAuditAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapGet("/controller/hosts", ListHostsAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapGet("/controller/policies", ListPoliciesAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapPost("/controller/hosts", RegisterHostAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapDelete("/controller/hosts/{id}", DeleteHostAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapControllerRoute("manage-dashboard", "manage", new { controller = "Management", action = "Index" });
        app.MapControllerRoute("manage-hosts-add", "manage/hosts/add", new { controller = "Management", action = "AddHost" });
        app.MapControllerRoute("manage-hosts-delete", "manage/hosts/delete", new { controller = "Management", action = "DeleteHost" });
        app.MapControllerRoute("manage-policies", "manage/policies", new { controller = "Management", action = "Policies" });
        app.MapControllerRoute("manage-policies-preview", "manage/policies/preview", new { controller = "Management", action = "PreviewPolicy" });
        app.MapControllerRoute("manage-policies-save", "manage/policies/save", new { controller = "Management", action = "SavePolicy" });
        app.MapControllerRoute("manage-audit", "manage/audit", new { controller = "Management", action = "Audit" });
    }

    internal static IResult ListAudit(HttpContext context, ControllerStateStore store)
    {
        if (!ControllerAuthorization.TryResolveActor(context.User, out var actorId, out var role))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var entries = store.ListAuditEntries().Select(entry => new
        {
            sequence = entry.Sequence,
            timestampUtc = entry.TimestampUtc,
            actorId = entry.ActorId,
            actorRole = entry.ActorRole,
            action = entry.Action,
            target = entry.Target,
            revision = entry.Revision?.ToString(CultureInfo.InvariantCulture),
            outcome = entry.Outcome,
            detailCode = entry.DetailCode,
        });

        return Results.Json(new { actorId, role, entries });
    }

    private static Task<IResult> ListAuditAsync(HttpContext context, ControllerStateStore store) =>
        Task.FromResult(ListAudit(context, store));

    private static Task<IResult> ListHostsAsync(HttpContext context, ControllerStateStore store)
    {
        if (!ControllerAuthorization.TryResolveActor(context.User, out _, out _))
        {
            return Task.FromResult(Results.StatusCode(StatusCodes.Status403Forbidden));
        }

        var hosts = store.ListHosts().Select(h => new
        {
            id = h.Id,
            name = h.Name,
            transportKind = h.TransportKind == AgentTransportKind.Unix ? "unix" : "tls",
            endpoint = h.Endpoint,
            expectedServerUserId = h.ExpectedServerUserId,
            socketGroupId = h.SocketGroupId,
            pinnedServerThumbprint = h.PinnedServerThumbprint,
            lastKnownRevision = h.LastKnownRevision.ToString(CultureInfo.InvariantCulture),
            createdAtUtc = h.CreatedAtUtc,
        });

        return Task.FromResult(Results.Json(new { hosts }));
    }

    private static Task<IResult> ListPoliciesAsync(HttpContext context, ControllerStateStore store)
    {
        if (!ControllerAuthorization.TryResolveActor(context.User, out _, out _))
        {
            return Task.FromResult(Results.StatusCode(StatusCodes.Status403Forbidden));
        }

        var revisions = store.ListPolicyRevisions().Select(r => new
        {
            revision = r.Revision.ToString(CultureInfo.InvariantCulture),
            candidateDigest = r.CandidateDigest,
            createdByActor = r.CreatedByActor,
            createdAtUtc = r.CreatedAtUtc,
            summary = r.Summary,
        });

        return Task.FromResult(Results.Json(new { revisions }));
    }

    private static async Task<IResult> RegisterHostAsync(
        HttpContext context,
        ControllerStateStore store,
        IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        if (!ControllerAuthorization.TryResolveActor(context.User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var parsed = await TryParseHostSubmissionAsync(context);
        if (parsed is null)
        {
            return Results.BadRequest();
        }

        try
        {
            store.RegisterHost(parsed, actorId, role);
            return Results.Json(new
            {
                id = parsed.Id,
                name = parsed.Name,
                transportKind = parsed.TransportKind == AgentTransportKind.Unix ? "unix" : "tls",
                endpoint = parsed.Endpoint,
            }, statusCode: StatusCodes.Status201Created);
        }
        catch (ControllerStateException ex) when (ex.Code == "host.duplicate")
        {
            return Results.Conflict(new { error = ex.Code });
        }
    }

    private static async Task<IResult> DeleteHostAsync(
        HttpContext context,
        string id,
        ControllerStateStore store,
        IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        if (!ControllerAuthorization.TryResolveActor(context.User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        if (!Guid.TryParseExact(id, "D", out var hostId) || hostId == Guid.Empty)
        {
            return Results.BadRequest();
        }

        return store.DeleteHost(hostId, actorId, role)
            ? Results.NoContent()
            : Results.NotFound();
    }

    private static async Task<ManagedHostRecord?> TryParseHostSubmissionAsync(HttpContext context)
    {
        string? name = null;
        string? kindText = null;
        string? endpoint = null;
        uint? uid = null;
        uint? gid = null;
        string? pin = null;

        var contentType = context.Request.ContentType?.Split(';')[0].Trim();
        if (string.Equals(contentType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            name = form["name"].SingleOrDefault();
            kindText = form["transportKind"].SingleOrDefault();
            endpoint = form["endpoint"].SingleOrDefault();
            var uidText = form["expectedServerUserId"].SingleOrDefault();
            if (!string.IsNullOrEmpty(uidText))
            {
                if (!uint.TryParse(uidText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedUid)) { return null; }
                uid = parsedUid;
            }
            var gidText = form["socketGroupId"].SingleOrDefault();
            if (!string.IsNullOrEmpty(gidText))
            {
                if (!uint.TryParse(gidText, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedGid)) { return null; }
                gid = parsedGid;
            }
            pin = string.IsNullOrEmpty(form["pinnedServerThumbprint"].SingleOrDefault()) ? null : form["pinnedServerThumbprint"].SingleOrDefault();
        }
        else if (string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var doc = await JsonDocument.ParseAsync(context.Request.Body, new JsonDocumentOptions { MaxDepth = 8 }, context.RequestAborted);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object) { return null; }
                name = ReadOptionalString(root, "name");
                kindText = ReadOptionalString(root, "transportKind");
                endpoint = ReadOptionalString(root, "endpoint");
                if (root.TryGetProperty("expectedServerUserId", out var uidEl) && uidEl.ValueKind != JsonValueKind.Null)
                {
                    if (uidEl.ValueKind != JsonValueKind.Number || !uidEl.TryGetUInt32(out var u)) { return null; }
                    uid = u;
                }
                if (root.TryGetProperty("socketGroupId", out var gidEl) && gidEl.ValueKind != JsonValueKind.Null)
                {
                    if (gidEl.ValueKind != JsonValueKind.Number || !gidEl.TryGetUInt32(out var g)) { return null; }
                    gid = g;
                }
                pin = ReadOptionalString(root, "pinnedServerThumbprint");
            }
            catch (JsonException)
            {
                return null;
            }
        }
        else
        {
            return null;
        }

        AgentTransportKind? kind = kindText switch
        {
            "unix" => AgentTransportKind.Unix,
            "tls" => AgentTransportKind.Tls,
            _ => null,
        };
        if (kind is null || name is null || endpoint is null)
        {
            return null;
        }

        try
        {
            return new ManagedHostRecord(Guid.NewGuid(), name, kind.Value, endpoint, uid, gid, pin);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string? ReadOptionalString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;
}
