using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

/// <summary>RBAC-gated fleet dashboard, policy authoring, compatibility/diff preview, confirmed apply, and audit viewer.</summary>
[SupportedOSPlatform("linux")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class ManagementController(ControllerStateStore store, ApplyWorkflowService? applyWorkflow = null) : Controller
{
    /// <summary>Renders the host fleet dashboard with recent audit entries (read-only for Auditors).</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public IActionResult Index()
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role))
        {
            return Forbid();
        }

        return View(BuildDashboardModel(actorId, role, null));
    }

    /// <summary>Registers a managed host endpoint from the dashboard (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public IActionResult AddHost(
        string? name,
        string? transportKind,
        string? endpoint,
        string? expectedServerUserId,
        string? socketGroupId,
        string? pinnedServerThumbprint)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var kind = transportKind switch
        {
            "unix" => (AgentTransportKind?)AgentTransportKind.Unix,
            "tls" => AgentTransportKind.Tls,
            _ => null,
        };

        uint? uid = null;
        if (!string.IsNullOrWhiteSpace(expectedServerUserId))
        {
            if (!uint.TryParse(expectedServerUserId, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedUid))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return View("Index", BuildDashboardModel(actorId, role, "Invalid expected server UID."));
            }

            uid = parsedUid;
        }

        uint? gid = null;
        if (!string.IsNullOrWhiteSpace(socketGroupId))
        {
            if (!uint.TryParse(socketGroupId, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedGid))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return View("Index", BuildDashboardModel(actorId, role, "Invalid socket group ID."));
            }

            gid = parsedGid;
        }

        if (kind is null || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(endpoint))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Index", BuildDashboardModel(actorId, role, "Missing required host registration fields."));
        }

        ManagedHostRecord host;
        try
        {
            var pin = string.IsNullOrWhiteSpace(pinnedServerThumbprint) ? null : pinnedServerThumbprint.Trim();
            host = new ManagedHostRecord(Guid.NewGuid(), name.Trim(), kind.Value, endpoint.Trim(), uid, gid, pin);
        }
        catch (ArgumentException)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Index", BuildDashboardModel(actorId, role, "Host specification violated transport constraints."));
        }

        try
        {
            store.RegisterHost(host, actorId, role);
            return LocalRedirect("~/manage");
        }
        catch (ControllerStateException ex) when (ex.Code == "host.duplicate")
        {
            Response.StatusCode = StatusCodes.Status409Conflict;
            return View("Index", BuildDashboardModel(actorId, role, "A host with that name already exists."));
        }
    }

    /// <summary>Deletes a registered host endpoint (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public IActionResult DeleteHost(string? id)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        if (!Guid.TryParseExact(id, "D", out var hostId) || hostId == Guid.Empty)
        {
            return BadRequest();
        }

        _ = store.DeleteHost(hostId, actorId, role);
        return LocalRedirect("~/manage");
    }

    /// <summary>Displays the typed policy bundle editor, compatibility report, and candidate diff preview.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public IActionResult Policies(ulong? revision = null, ulong? compareTo = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role))
        {
            return Forbid();
        }

        var revisions = store.ListPolicyRevisions();
        var selected = revision is > 0
            ? revisions.FirstOrDefault(r => r.Revision == revision.Value)
            : revisions.FirstOrDefault();

        var baseline = compareTo is > 0
            ? compareTo.Value
            : (selected is not null && selected.Revision > 1 ? selected.Revision - 1 : (ulong?)null);

        var draftJson = selected?.PolicyJson ?? PolicyAuthoringService.DefaultStarterBundleJson;
        var report = PolicyAuthoringService.EvaluateDraft(draftJson, store, baseline);

        return View(BuildPolicyModel(
            role,
            draftJson,
            selected?.Summary,
            selected?.Revision,
            baseline,
            revisions,
            report));
    }

    /// <summary>Validates, checks capabilities, compiles, and diffs a policy draft without mutating state.</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Reader), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public IActionResult PreviewPolicy(string? bundleJson, string? summary, ulong? compareToRevision)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role))
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var report = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
        if (!report.IsValid)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
        }

        var revisions = store.ListPolicyRevisions();
        return View("Policies", BuildPolicyModel(
            role,
            raw,
            summary,
            null,
            compareToRevision,
            revisions,
            report));
    }

    /// <summary>Validates, compiles, and persists a new monotonic policy revision (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public IActionResult SavePolicy(string? bundleJson, string? summary, ulong? compareToRevision)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var cleanSummary = string.IsNullOrWhiteSpace(summary) ? null : summary.Trim();
        var revisions = store.ListPolicyRevisions();
        var report = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);

        if (!report.IsValid || report.CanonicalJson is null || report.CandidateDigest is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Policies", BuildPolicyModel(
                role,
                raw,
                cleanSummary,
                null,
                compareToRevision,
                revisions,
                report));
        }

        if (cleanSummary is not null && (cleanSummary.Length > 256 || cleanSummary.Any(char.IsControl)))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            var errReport = report with { IsValid = false, Diagnostics = [new("summary.bounds", "summary")] };
            return View("Policies", BuildPolicyModel(role, raw, cleanSummary, null, compareToRevision, revisions, errReport));
        }

        var saved = store.SavePolicyRevision(report.CanonicalJson, report.CandidateDigest, actorId, role, cleanSummary);
        return LocalRedirect($"~/manage/policies?revision={saved.Revision.ToString(CultureInfo.InvariantCulture)}");
    }

    /// <summary>Displays live agent control state, countdown timer, and two-phase confirmed-apply controls.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public async Task<IActionResult> Apply(string? hostId = null, ulong? revision = null, string? notice = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role))
        {
            return Forbid();
        }

        Guid? parsedHostId = null;
        if (!string.IsNullOrWhiteSpace(hostId))
        {
            if (!Guid.TryParseExact(hostId, "D", out var h) || h == Guid.Empty)
            {
                return BadRequest();
            }

            parsedHostId = h;
        }

        var noticeMessage = notice switch
        {
            "appliedPendingConfirmation" => "Candidate applied with watchdog armed; confirm before timeout or agent will roll back automatically.",
            "confirmed" => "Candidate confirmed as current baseline revision.",
            "rolledBack" => "Explicit rollback completed and verified.",
            _ => null,
        };

        var model = await BuildApplyModelAsync(actorId, role, parsedHostId, revision, noticeMessage, null, HttpContext.RequestAborted);
        return View(model);
    }

    /// <summary>Prepares, arms watchdog, and applies a saved policy revision onto a registered host (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public async Task<IActionResult> StartApply(string? hostId, ulong? revision, int? confirmationTimeoutSeconds)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var workflow = applyWorkflow ?? throw new InvalidOperationException("Apply workflow service is not registered.");
        if (!Guid.TryParseExact(hostId, "D", out var parsedHostId) || parsedHostId == Guid.Empty ||
            revision is null or 0)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Apply", await BuildApplyModelAsync(actorId, role, null, revision, null, "Select both a managed host and a saved policy revision.", HttpContext.RequestAborted));
        }

        var timeout = confirmationTimeoutSeconds ?? ApplyWorkflowService.DefaultConfirmationTimeoutSeconds;
        if (timeout is < ApplyWorkflowService.MinimumConfirmationTimeoutSeconds or > ApplyWorkflowService.MaximumConfirmationTimeoutSeconds)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Apply", await BuildApplyModelAsync(actorId, role, parsedHostId, revision, null, "Confirmation timeout must be between 1 and 3600 seconds.", HttpContext.RequestAborted));
        }

        var result = await workflow.StartApplyAsync(parsedHostId, revision.Value, timeout, actorId, role, HttpContext.RequestAborted);
        if (!result.HostFound)
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            return View("Apply", await BuildApplyModelAsync(actorId, role, null, revision, null, "Selected managed host was not found.", HttpContext.RequestAborted));
        }

        if (!result.RevisionFound || result.Reply is null)
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            return View("Apply", await BuildApplyModelAsync(actorId, role, parsedHostId, null, null, "Selected policy revision was not found.", HttpContext.RequestAborted));
        }

        if (result.Reply.Outcome == AgentControlOutcome.AppliedPendingConfirmation)
        {
            return LocalRedirect($"~/manage/apply?hostId={parsedHostId:D}&revision={revision.Value.ToString(CultureInfo.InvariantCulture)}&notice=appliedPendingConfirmation");
        }

        Response.StatusCode = ControllerStateHost.MapMutationStatusCode(result.Reply.Outcome);
        var reason = string.IsNullOrEmpty(result.Reply.ErrorCode)
            ? ControllerStateHost.FormatOutcome(result.Reply.Outcome)
            : $"{ControllerStateHost.FormatOutcome(result.Reply.Outcome)} ({result.Reply.ErrorCode})";
        return View("Apply", await BuildApplyModelAsync(actorId, role, parsedHostId, revision, null, $"Apply start failed: {reason}.", HttpContext.RequestAborted, result.Reply));
    }

    /// <summary>Confirms an awaiting-confirmation candidate before the watchdog expires (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public async Task<IActionResult> ConfirmApply(string? hostId, string? operationId, string? watchdogId, ulong? targetRevision) =>
        await ExecuteApplyOperationAsync(hostId, operationId, watchdogId, targetRevision, isConfirm: true);

    /// <summary>Immediately rolls back an active unconfirmed candidate before watchdog expiry (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public async Task<IActionResult> RollbackApply(string? hostId, string? operationId, string? watchdogId, ulong? targetRevision) =>
        await ExecuteApplyOperationAsync(hostId, operationId, watchdogId, targetRevision, isConfirm: false);

    private async Task<IActionResult> ExecuteApplyOperationAsync(
        string? hostId,
        string? operationId,
        string? watchdogId,
        ulong? targetRevision,
        bool isConfirm)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var workflow = applyWorkflow ?? throw new InvalidOperationException("Apply workflow service is not registered.");
        if (!Guid.TryParseExact(hostId, "D", out var parsedHostId) || parsedHostId == Guid.Empty ||
            !Guid.TryParseExact(operationId, "D", out var parsedOpId) || parsedOpId == Guid.Empty ||
            !Guid.TryParseExact(watchdogId, "D", out var parsedWdId) || parsedWdId == Guid.Empty)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Apply", await BuildApplyModelAsync(actorId, role, null, targetRevision, null, "Operation or watchdog identifier is invalid.", HttpContext.RequestAborted));
        }

        var result = isConfirm
            ? await workflow.ConfirmApplyAsync(parsedHostId, parsedOpId, parsedWdId, targetRevision, actorId, role, HttpContext.RequestAborted)
            : await workflow.RollbackApplyAsync(parsedHostId, parsedOpId, parsedWdId, actorId, role, HttpContext.RequestAborted);

        if (!result.HostFound || result.Reply is null)
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            return View("Apply", await BuildApplyModelAsync(actorId, role, null, targetRevision, null, "Selected managed host was not found.", HttpContext.RequestAborted));
        }

        var expectedOutcome = isConfirm ? AgentControlOutcome.Confirmed : AgentControlOutcome.RolledBack;
        if (result.Reply.Outcome == expectedOutcome)
        {
            var token = isConfirm ? "confirmed" : "rolledBack";
            var revQuery = targetRevision is > 0 ? $"&revision={targetRevision.Value.ToString(CultureInfo.InvariantCulture)}" : "";
            return LocalRedirect($"~/manage/apply?hostId={parsedHostId:D}{revQuery}&notice={token}");
        }

        Response.StatusCode = ControllerStateHost.MapMutationStatusCode(result.Reply.Outcome);
        var reason = string.IsNullOrEmpty(result.Reply.ErrorCode)
            ? ControllerStateHost.FormatOutcome(result.Reply.Outcome)
            : $"{ControllerStateHost.FormatOutcome(result.Reply.Outcome)} ({result.Reply.ErrorCode})";
        var label = isConfirm ? "Confirm" : "Rollback";
        return View("Apply", await BuildApplyModelAsync(actorId, role, parsedHostId, targetRevision, null, $"{label} failed: {reason}.", HttpContext.RequestAborted, result.Reply));
    }

    /// <summary>Displays append-only audit log and immutable policy revision history (read-only for Auditors).</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public IActionResult Audit()
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role))
        {
            return Forbid();
        }

        var model = new AuditHistoryViewModel
        {
            ActorId = actorId,
            ActorRole = role,
            Entries = store.ListAuditEntries(),
            Revisions = store.ListPolicyRevisions(),
        };
        return View(model);
    }

    private FleetDashboardViewModel BuildDashboardModel(string actorId, string role, string? error)
    {
        var revisions = store.ListPolicyRevisions(1);
        return new FleetDashboardViewModel
        {
            ActorId = actorId,
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            Hosts = store.ListHosts(),
            LatestRevision = revisions.FirstOrDefault(),
            RecentAudit = store.ListAuditEntries(20),
            ErrorMessage = error,
        };
    }

    private static PolicyEditorViewModel BuildPolicyModel(
        string role,
        string bundleJson,
        string? summary,
        ulong? selectedRevision,
        ulong? compareToRevision,
        IReadOnlyList<PolicyRevisionRecord> revisions,
        PolicyEvaluationReport report) =>
        new()
        {
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            BundleJson = bundleJson,
            Summary = summary,
            SelectedRevision = selectedRevision,
            CompareToRevision = compareToRevision,
            Revisions = revisions,
            Compatibility = report.Compatibility,
            CandidateText = report.CandidateText,
            CandidateDigest = report.CandidateDigest,
            UnifiedDiff = report.UnifiedDiff,
            Diagnostics = report.Diagnostics,
        };

    private async Task<ConfirmedApplyViewModel> BuildApplyModelAsync(
        string actorId,
        string role,
        Guid? requestedHostId,
        ulong? requestedRevision,
        string? statusMessage,
        string? errorMessage,
        CancellationToken cancellationToken,
        AgentControlReply? overrideReply = null)
    {
        var hosts = store.ListHosts();
        var revisions = store.ListPolicyRevisions();
        var selectedHost = requestedHostId is { } targetId
            ? hosts.FirstOrDefault(h => h.Id == targetId)
            : hosts.FirstOrDefault();

        var selectedRevision = requestedRevision is > 0
            ? revisions.FirstOrDefault(r => r.Revision == requestedRevision.Value)?.Revision
            : revisions.FirstOrDefault()?.Revision;

        var liveReply = overrideReply;
        if (liveReply is null && selectedHost is not null && applyWorkflow is not null)
        {
            var statusResult = await applyWorkflow.QueryHostStatusAsync(selectedHost.Id, cancellationToken);
            if (statusResult.Host is not null)
            {
                selectedHost = statusResult.Host;
            }

            liveReply = statusResult.Reply;
        }

        return new ConfirmedApplyViewModel
        {
            ActorId = actorId,
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            Hosts = hosts,
            Revisions = revisions,
            SelectedHost = selectedHost,
            SelectedRevision = selectedRevision,
            LiveReply = liveReply,
            RecentAudit = store.ListAuditEntries(20),
            StatusMessage = statusMessage,
            ErrorMessage = errorMessage,
        };
    }
}
