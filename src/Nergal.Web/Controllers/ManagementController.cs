using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

/// <summary>RBAC-gated fleet dashboard, policy authoring, compatibility/diff preview, and audit viewer.</summary>
[SupportedOSPlatform("linux")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class ManagementController(ControllerStateStore store) : Controller
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
}
