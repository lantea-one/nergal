using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Deployment;
using Nergal.Core.Identity;

namespace Nergal.Web;

[SupportedOSPlatform("linux")]
internal static class ControllerStateHost
{
    internal static void Configure(IServiceCollection services, IConfigurationSection config)
    {
        var options = new ControllerStateOptions(config["Directory"] ?? "");
        var store = ControllerStateStore.Open(options);
        var tlsConfig = ControllerTlsClientConfig.FromConfiguration(config);
        services.AddSingleton(store);
        services.AddSingleton(tlsConfig);
        services.AddSingleton<IAgentControlDispatcher, DefaultAgentControlDispatcher>();
        services.AddSingleton<ApplyWorkflowService>();
    }

    internal static void Map(WebApplication app)
    {
        app.MapGet("/controller/audit", ListAuditAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapGet("/controller/hosts", ListHostsAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapGet("/controller/policies", ListPoliciesAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapGet("/controller/apply/status", QueryApplyStatusAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Reader);

        app.MapPost("/controller/hosts", RegisterHostAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapDelete("/controller/hosts/{id}", DeleteHostAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapPost("/controller/apply/start", StartApplyApiAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapPost("/controller/apply/confirm", ConfirmApplyApiAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapPost("/controller/apply/rollback", RollbackApplyApiAsync)
            .RequireAuthorization(ControllerAuthorizationPolicies.Administrator);

        app.MapControllerRoute("manage-dashboard", "manage", new { controller = "Management", action = "Index" });
        app.MapControllerRoute("manage-hosts-add", "manage/hosts/add", new { controller = "Management", action = "AddHost" });
        app.MapControllerRoute("manage-hosts-delete", "manage/hosts/delete", new { controller = "Management", action = "DeleteHost" });
        app.MapControllerRoute("manage-policies", "manage/policies", new { controller = "Management", action = "Policies" });
        app.MapControllerRoute("manage-policies-preview", "manage/policies/preview", new { controller = "Management", action = "PreviewPolicy" });
        app.MapControllerRoute("manage-policies-save", "manage/policies/save", new { controller = "Management", action = "SavePolicy" });
        app.MapControllerRoute("manage-rule-state", "manage/policies/rules/state", new { controller = "Management", action = "SetRuleState" });
        app.MapControllerRoute("manage-policy-object", "manage/policies/objects", new { controller = "Management", action = "SetPolicyObject" });
        app.MapControllerRoute("manage-policies-rule-add", "manage/policies/rules/add", new { controller = "Management", action = "AddFilterRule" });
        app.MapControllerRoute("manage-policies-rule-edit", "manage/policies/rules/edit", new { controller = "Management", action = "EditFilterRule" });
        app.MapControllerRoute("manage-policies-rule-remove", "manage/policies/rules/remove", new { controller = "Management", action = "RemoveFilterRule" });
        app.MapControllerRoute("manage-policies-rule-move", "manage/policies/rules/move", new { controller = "Management", action = "MoveFilterRule" });
        app.MapControllerRoute("manage-policies-filter-defaults", "manage/policies/filter/defaults", new { controller = "Management", action = "UpdateFilterDefaults" });
        app.MapControllerRoute("manage-policies-nat-dnat-add", "manage/policies/nat/dnat/add", new { controller = "Management", action = "AddDnatRule" });
        app.MapControllerRoute("manage-policies-nat-dnat-edit", "manage/policies/nat/dnat/edit", new { controller = "Management", action = "EditDnatRule" });
        app.MapControllerRoute("manage-policies-nat-dnat-remove", "manage/policies/nat/dnat/remove", new { controller = "Management", action = "RemoveDnatRule" });
        app.MapControllerRoute("manage-policies-nat-snat-add", "manage/policies/nat/snat/add", new { controller = "Management", action = "AddSnatRule" });
        app.MapControllerRoute("manage-policies-nat-snat-edit", "manage/policies/nat/snat/edit", new { controller = "Management", action = "EditSnatRule" });
        app.MapControllerRoute("manage-policies-nat-snat-remove", "manage/policies/nat/snat/remove", new { controller = "Management", action = "RemoveSnatRule" });
        app.MapControllerRoute("manage-policies-nat-clear", "manage/policies/nat/clear", new { controller = "Management", action = "ClearNat" });
        app.MapControllerRoute("manage-policies-bridge-defaults", "manage/policies/bridge/defaults", new { controller = "Management", action = "UpdateBridgeDefaults" });
        app.MapControllerRoute("manage-policies-bridge-add", "manage/policies/bridge/rules/add", new { controller = "Management", action = "AddBridgeRule" });
        app.MapControllerRoute("manage-policies-bridge-edit", "manage/policies/bridge/rules/edit", new { controller = "Management", action = "EditBridgeRule" });
        app.MapControllerRoute("manage-policies-bridge-remove", "manage/policies/bridge/rules/remove", new { controller = "Management", action = "RemoveBridgeRule" });
        app.MapControllerRoute("manage-policies-bridge-clear", "manage/policies/bridge/clear", new { controller = "Management", action = "ClearBridge" });
        app.MapControllerRoute("manage-apply", "manage/apply", new { controller = "Management", action = "Apply" });
        app.MapControllerRoute("manage-apply-start", "manage/apply/start", new { controller = "Management", action = "StartApply" });
        app.MapControllerRoute("manage-apply-confirm", "manage/apply/confirm", new { controller = "Management", action = "ConfirmApply" });
        app.MapControllerRoute("manage-apply-rollback", "manage/apply/rollback", new { controller = "Management", action = "RollbackApply" });
        app.MapControllerRoute("manage-audit", "manage/audit", new { controller = "Management", action = "Audit" });
        app.MapControllerRoute("manage-objects-save", "manage/objects/save", new { controller = "Management", action = "SaveObject" });
        app.MapControllerRoute("manage-objects", "manage/objects", new { controller = "Management", action = "Objects" });
        app.MapControllerRoute("manage-sources-import", "manage/sources/import", new { controller = "Management", action = "ImportSource" });
        app.MapControllerRoute("manage-sources-stage", "manage/sources/stage", new { controller = "Management", action = "ImportStagedSource" });
        app.MapControllerRoute("manage-sources-download", "manage/sources/download", new { controller = "Management", action = "DownloadSource" });
        app.MapControllerRoute("manage-sources-review", "manage/sources/review", new { controller = "Management", action = "SourceReview" });
        app.MapControllerRoute("manage-sources", "manage/sources", new { controller = "Management", action = "Sources" });
        app.MapControllerRoute("manage-settings", "manage/settings", new { controller = "Management", action = "Settings" });
        app.MapControllerRoute("manage-settings-save", "manage/settings/save", new { controller = "Management", action = "SaveSettings" });
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

    private static async Task<IResult> QueryApplyStatusAsync(
        HttpContext context,
        ApplyWorkflowService workflow)
    {
        if (!ControllerAuthorization.TryResolveActor(context.User, out _, out _))
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }

        var rawHostId = context.Request.Query["hostId"].SingleOrDefault();
        if (!Guid.TryParseExact(rawHostId, "D", out var hostId) || hostId == Guid.Empty)
        {
            return Results.BadRequest(new { error = "apply.invalidHostId" });
        }

        var result = await workflow.QueryHostStatusAsync(hostId, context.RequestAborted).ConfigureAwait(false);
        if (!result.HostFound || result.Host is null || result.Reply is null)
        {
            return Results.NotFound(new { error = "host.notFound" });
        }

        return Results.Json(BuildApplyPayload(result.Host, result.Reply));
    }

    private static async Task<IResult> StartApplyApiAsync(
        HttpContext context,
        ApplyWorkflowService workflow,
        IAntiforgery antiforgery)
    {
        var validated = await ValidateAdminMutationAsync(context, antiforgery).ConfigureAwait(false);
        if (validated.Failure is { } fail)
        {
            return fail;
        }

        var fields = await ReadSubmissionFieldsAsync(context, "hostId", "revision", "confirmationTimeoutSeconds").ConfigureAwait(false);
        if (fields is null ||
            !TryParseNonEmptyGuid(fields.GetValueOrDefault("hostId"), out var hostId) ||
            !ulong.TryParse(fields.GetValueOrDefault("revision"), NumberStyles.None, CultureInfo.InvariantCulture, out var revision) ||
            revision == 0)
        {
            return Results.BadRequest(new { error = "apply.invalidInput" });
        }

        var timeoutSeconds = ApplyWorkflowService.DefaultConfirmationTimeoutSeconds;
        var rawTimeout = fields.GetValueOrDefault("confirmationTimeoutSeconds");
        if (!string.IsNullOrEmpty(rawTimeout))
        {
            if (!int.TryParse(rawTimeout, NumberStyles.None, CultureInfo.InvariantCulture, out timeoutSeconds) ||
                timeoutSeconds is < ApplyWorkflowService.MinimumConfirmationTimeoutSeconds or > ApplyWorkflowService.MaximumConfirmationTimeoutSeconds)
            {
                return Results.BadRequest(new { error = "apply.invalidTimeout" });
            }
        }

        var result = await workflow.StartApplyAsync(
            hostId,
            revision,
            timeoutSeconds,
            validated.ActorId,
            validated.ActorRole,
            context.RequestAborted).ConfigureAwait(false);

        if (!result.HostFound)
        {
            return Results.NotFound(new { error = "host.notFound" });
        }

        if (!result.RevisionFound || result.Host is null || result.Reply is null)
        {
            return Results.NotFound(new { error = "policy.notFound" });
        }

        return Results.Json(BuildApplyPayload(result.Host, result.Reply), statusCode: MapMutationStatusCode(result.Reply.Outcome));
    }

    private static async Task<IResult> ConfirmApplyApiAsync(
        HttpContext context,
        ApplyWorkflowService workflow,
        IAntiforgery antiforgery) =>
        await ExecuteOperationApiAsync(context, workflow, antiforgery, isConfirm: true).ConfigureAwait(false);

    private static async Task<IResult> RollbackApplyApiAsync(
        HttpContext context,
        ApplyWorkflowService workflow,
        IAntiforgery antiforgery) =>
        await ExecuteOperationApiAsync(context, workflow, antiforgery, isConfirm: false).ConfigureAwait(false);

    private static async Task<IResult> ExecuteOperationApiAsync(
        HttpContext context,
        ApplyWorkflowService workflow,
        IAntiforgery antiforgery,
        bool isConfirm)
    {
        var validated = await ValidateAdminMutationAsync(context, antiforgery).ConfigureAwait(false);
        if (validated.Failure is { } fail)
        {
            return fail;
        }

        var fields = await ReadSubmissionFieldsAsync(context, "hostId", "operationId", "watchdogId", "targetRevision").ConfigureAwait(false);
        if (fields is null ||
            !TryParseNonEmptyGuid(fields.GetValueOrDefault("hostId"), out var hostId) ||
            !TryParseNonEmptyGuid(fields.GetValueOrDefault("operationId"), out var operationId) ||
            !TryParseNonEmptyGuid(fields.GetValueOrDefault("watchdogId"), out var watchdogId))
        {
            return Results.BadRequest(new { error = "apply.invalidInput" });
        }

        ulong? targetRevision = null;
        var rawRev = fields.GetValueOrDefault("targetRevision");
        if (!string.IsNullOrEmpty(rawRev))
        {
            if (!ulong.TryParse(rawRev, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedRev) || parsedRev == 0)
            {
                return Results.BadRequest(new { error = "apply.invalidRevision" });
            }

            targetRevision = parsedRev;
        }

        var result = isConfirm
            ? await workflow.ConfirmApplyAsync(hostId, operationId, watchdogId, targetRevision, validated.ActorId, validated.ActorRole, context.RequestAborted).ConfigureAwait(false)
            : await workflow.RollbackApplyAsync(hostId, operationId, watchdogId, validated.ActorId, validated.ActorRole, context.RequestAborted).ConfigureAwait(false);

        if (!result.HostFound || result.Host is null || result.Reply is null)
        {
            return Results.NotFound(new { error = "host.notFound" });
        }

        return Results.Json(BuildApplyPayload(result.Host, result.Reply), statusCode: MapMutationStatusCode(result.Reply.Outcome));
    }

    private static async Task<(IResult? Failure, string ActorId, string ActorRole)> ValidateAdminMutationAsync(
        HttpContext context,
        IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context).ConfigureAwait(false);
        }
        catch (AntiforgeryValidationException)
        {
            return (Results.BadRequest(), "", "");
        }

        if (!ControllerAuthorization.TryResolveActor(context.User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return (Results.StatusCode(StatusCodes.Status403Forbidden), "", "");
        }

        return (null, actorId, role);
    }

    private static async Task<Dictionary<string, string?>?> ReadSubmissionFieldsAsync(HttpContext context, params string[] names)
    {
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);
        var contentType = context.Request.ContentType?.Split(';')[0].Trim();
        if (string.Equals(contentType, "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
            foreach (var name in names)
            {
                result[name] = form[name].SingleOrDefault();
            }

            return result;
        }

        if (string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var doc = await JsonDocument.ParseAsync(context.Request.Body, new JsonDocumentOptions { MaxDepth = 8 }, context.RequestAborted).ConfigureAwait(false);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }

                foreach (var name in names)
                {
                    if (!root.TryGetProperty(name, out var el) || el.ValueKind == JsonValueKind.Null)
                    {
                        result[name] = null;
                    }
                    else if (el.ValueKind == JsonValueKind.String)
                    {
                        result[name] = el.GetString();
                    }
                    else if (el.ValueKind == JsonValueKind.Number)
                    {
                        result[name] = el.GetRawText();
                    }
                    else
                    {
                        return null;
                    }
                }

                return result;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        return null;
    }

    internal static int MapMutationStatusCode(AgentControlOutcome outcome) => outcome switch
    {
        AgentControlOutcome.AppliedPendingConfirmation or AgentControlOutcome.Confirmed or AgentControlOutcome.RolledBack or AgentControlOutcome.Matched => StatusCodes.Status200OK,
        AgentControlOutcome.Rejected or AgentControlOutcome.InvalidRequest => StatusCodes.Status400BadRequest,
        AgentControlOutcome.Busy or AgentControlOutcome.Drift or AgentControlOutcome.Unbound => StatusCodes.Status409Conflict,
        AgentControlOutcome.Unavailable or AgentControlOutcome.Denied => StatusCodes.Status503ServiceUnavailable,
        _ => StatusCodes.Status500InternalServerError,
    };

    private static object BuildApplyPayload(ManagedHostRecord host, AgentControlReply reply) => new
    {
        hostId = host.Id,
        hostName = host.Name,
        lastKnownRevision = host.LastKnownRevision.ToString(CultureInfo.InvariantCulture),
        outcome = FormatOutcome(reply.Outcome),
        revision = reply.Revision?.ToString(CultureInfo.InvariantCulture),
        operationId = reply.OperationId?.ToString("D"),
        watchdogId = reply.WatchdogId?.ToString("D"),
        activePhase = reply.ActivePhase is { } p ? FormatPhase(p) : null,
        remainingSeconds = reply.RemainingSeconds,
        candidateDigest = reply.CandidateDigest,
        errorCode = reply.ErrorCode,
    };

    private static bool TryParseNonEmptyGuid(string? value, out Guid guid)
    {
        guid = Guid.Empty;
        return Guid.TryParseExact(value, "D", out guid) && guid != Guid.Empty;
    }

    internal static string FormatOutcome(AgentControlOutcome outcome) => outcome switch
    {
        AgentControlOutcome.Matched => "matched",
        AgentControlOutcome.Drift => "drift",
        AgentControlOutcome.Unbound => "unbound",
        AgentControlOutcome.AppliedPendingConfirmation => "appliedPendingConfirmation",
        AgentControlOutcome.Confirmed => "confirmed",
        AgentControlOutcome.RolledBack => "rolledBack",
        AgentControlOutcome.Rejected => "rejected",
        AgentControlOutcome.Busy => "busy",
        AgentControlOutcome.Unavailable => "unavailable",
        AgentControlOutcome.Denied => "denied",
        AgentControlOutcome.InvalidRequest => "invalidRequest",
        _ => "unavailable",
    };

    internal static string FormatPhase(ApplyPhase phase) => phase switch
    {
        ApplyPhase.Prepared => "prepared",
        ApplyPhase.RollbackArmed => "rollbackArmed",
        ApplyPhase.AwaitingConfirmation => "awaitingConfirmation",
        ApplyPhase.Confirmed => "confirmed",
        ApplyPhase.RollbackRequired => "rollbackRequired",
        ApplyPhase.RolledBack => "rolledBack",
        ApplyPhase.RecoveryRequired => "recoveryRequired",
        _ => "recoveryRequired",
    };

    private static string? ReadOptionalString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;
}
