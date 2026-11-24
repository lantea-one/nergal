using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

/// <summary>RBAC-gated fleet dashboard, policy authoring, compatibility/diff preview, confirmed apply, system settings, and audit viewer.</summary>
[SupportedOSPlatform("linux")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed partial class ManagementController(ControllerStateStore store, ApplyWorkflowService? applyWorkflow = null, NativePolicySourceCatalog? nativeSources = null) : Controller
{
    /// <summary>Populates live branding settings for the shared layout before action execution.</summary>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        try
        {
            ViewData["Branding"] = store.ReadSystemSettings().Branding;
        }
        catch (ControllerStateException)
        {
            ViewData["Branding"] = SystemSettingsSnapshot.Default.Branding;
        }

        ViewData["ShowNativeSources"] = true;
        base.OnActionExecuting(context);
    }

    /// <summary>Renders the overview and host fleet dashboard with live host health and recent audit entries (read-only for Auditors).</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public async Task<IActionResult> Index()
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role))
        {
            return Forbid();
        }

        return View(await BuildDashboardModelAsync(actorId, role, null, HttpContext.RequestAborted));
    }

    /// <summary>Registers a managed host endpoint from the dashboard (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(8192)]
    public async Task<IActionResult> AddHost(
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
                return View("Index", await BuildDashboardModelAsync(actorId, role, "Invalid expected server UID.", HttpContext.RequestAborted));
            }

            uid = parsedUid;
        }

        uint? gid = null;
        if (!string.IsNullOrWhiteSpace(socketGroupId))
        {
            if (!uint.TryParse(socketGroupId, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedGid))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return View("Index", await BuildDashboardModelAsync(actorId, role, "Invalid socket group ID.", HttpContext.RequestAborted));
            }

            gid = parsedGid;
        }

        if (kind is null || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(endpoint))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return View("Index", await BuildDashboardModelAsync(actorId, role, "Missing required host registration fields.", HttpContext.RequestAborted));
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
            return View("Index", await BuildDashboardModelAsync(actorId, role, "Host specification violated transport constraints.", HttpContext.RequestAborted));
        }

        try
        {
            store.RegisterHost(host, actorId, role);
            return LocalRedirect("~/manage");
        }
        catch (ControllerStateException ex) when (ex.Code == "host.duplicate")
        {
            Response.StatusCode = StatusCodes.Status409Conflict;
            return View("Index", await BuildDashboardModelAsync(actorId, role, "A host with that name already exists.", HttpContext.RequestAborted));
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
    [RequestSizeLimit(524288)]
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
    [RequestSizeLimit(524288)]
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

    /// <summary>Appends a validated filter rule to the draft policy bundle via the structured visual rule builder (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult AddFilterRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        string? chain,
        string? family,
        string? protocol,
        string? verdict,
        string? sources,
        string? destinations,
        string? destinationPorts,
        string? icmpType,
        string? inputInterface,
        string? outputInterface,
        string? connectionStates,
        bool matchOriginalDestinationDnat = false,
        int? rateLimitPackets = null,
        string? rateLimitUnit = null,
        int? rateLimitBurst = null,
        int? rateLimitTimeout = null,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        var revisions = store.ListPolicyRevisions();
        var input = new VisualFilterRuleInput(
            chain, family, protocol, verdict, sources, destinations, destinationPorts,
            icmpType, inputInterface, outputInterface, connectionStates,
            matchOriginalDestinationDnat, rateLimitPackets, rateLimitUnit, rateLimitBurst, rateLimitTimeout, description);

        if (!PolicyAuthoringService.TryAppendFilterRule(raw, input, out var updatedJson, out var diagnostics) || updatedJson is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            var existing = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
            var failed = existing with { IsValid = false, Diagnostics = diagnostics };
            return View("Policies", BuildPolicyModel(role, raw, summary, null, compareToRevision, revisions, failed));
        }

        var report = PolicyAuthoringService.EvaluateDraft(updatedJson, store, compareToRevision);
        return View("Policies", BuildPolicyModel(role, updatedJson, summary, null, compareToRevision, revisions, report));
    }

    /// <summary>Updates an existing filter rule in place in the draft policy bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult EditFilterRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        int ruleIndex,
        string? chain,
        string? family,
        string? protocol,
        string? verdict,
        string? sources,
        string? destinations,
        string? destinationPorts,
        string? icmpType,
        string? inputInterface,
        string? outputInterface,
        string? connectionStates,
        bool matchOriginalDestinationDnat = false,
        int? rateLimitPackets = null,
        string? rateLimitUnit = null,
        int? rateLimitBurst = null,
        int? rateLimitTimeout = null,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var input = new VisualFilterRuleInput(
            chain, family, protocol, verdict, sources, destinations, destinationPorts,
            icmpType, inputInterface, outputInterface, connectionStates,
            matchOriginalDestinationDnat, rateLimitPackets, rateLimitUnit, rateLimitBurst, rateLimitTimeout, description);

        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateFilterRule(raw, ruleIndex, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Updates filter schema version and per-chain default verdicts in the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult UpdateFilterDefaults(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        int schemaVersion,
        string? inputDefaultVerdict,
        string? forwardDefaultVerdict,
        string? outputDefaultVerdict)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateFilterDefaults(raw, schemaVersion, inputDefaultVerdict, forwardDefaultVerdict, outputDefaultVerdict, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Appends a prerouting DNAT rule to the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult AddDnatRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        string? family,
        string? protocol,
        string? originalDestination,
        string? translatedAddress,
        int? originalPort,
        int? translatedPort,
        string? inputInterface,
        string? source,
        string? description = null,
        string? originalPorts = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        if (!ModelState.IsValid || (Request.HasFormContentType && !ValidRouterForm(Request.Form,
            ["ruleIndex", "family", "protocol", "originalDestination", "translatedAddress", "originalPort", "originalPorts", "translatedPort", "inputInterface", "source", "description"], [])))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.dnatFormInvalid", "rule")]); }
        var input = new VisualDnatRuleInput(family, protocol, originalDestination, translatedAddress, originalPort, translatedPort, inputInterface, source, description, originalPorts);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryAppendDnatRule(raw, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Updates an existing prerouting DNAT rule in place in the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult EditDnatRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        int ruleIndex,
        string? family,
        string? protocol,
        string? originalDestination,
        string? translatedAddress,
        int? originalPort,
        int? translatedPort,
        string? inputInterface,
        string? source,
        string? description = null,
        string? originalPorts = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        if (!ModelState.IsValid || (Request.HasFormContentType && !ValidRouterForm(Request.Form,
            ["ruleIndex", "family", "protocol", "originalDestination", "translatedAddress", "originalPort", "originalPorts", "translatedPort", "inputInterface", "source", "description"], [])))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.dnatFormInvalid", "rule")]); }
        var input = new VisualDnatRuleInput(family, protocol, originalDestination, translatedAddress, originalPort, translatedPort, inputInterface, source, description, originalPorts);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateDnatRule(raw, ruleIndex, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Removes a prerouting DNAT rule by index from the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult RemoveDnatRule(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryRemoveDnatRule(raw, ruleIndex, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Appends an explicit postrouting SNAT rule to the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult AddSnatRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        string? family,
        string? source,
        string? translatedAddress,
        string? destination,
        string? outputInterface,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        var input = new VisualSnatRuleInput(family, source, translatedAddress, destination, outputInterface, description);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryAppendSnatRule(raw, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Updates an existing postrouting SNAT rule in place in the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult EditSnatRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        int ruleIndex,
        string? family,
        string? source,
        string? translatedAddress,
        string? destination,
        string? outputInterface,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var input = new VisualSnatRuleInput(family, source, translatedAddress, destination, outputInterface, description);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateSnatRule(raw, ruleIndex, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Removes an explicit postrouting SNAT rule by index from the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult RemoveSnatRule(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryRemoveSnatRule(raw, ruleIndex, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Clears the optional NAT table section from the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult ClearNat(string? bundleJson, string? summary, ulong? compareToRevision)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryClearNat(raw, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Enables or updates the L2 bridge default verdict in the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult UpdateBridgeDefaults(string? bundleJson, string? summary, ulong? compareToRevision, string? defaultVerdict)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateBridgeDefaults(raw, defaultVerdict, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Appends an L2 bridge forward rule to the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult AddBridgeRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        string? etherType,
        string? verdict,
        string? inputInterface,
        string? outputInterface,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = string.IsNullOrWhiteSpace(bundleJson) ? PolicyAuthoringService.DefaultStarterBundleJson : bundleJson;
        var input = new VisualBridgeRuleInput(etherType, verdict, inputInterface, outputInterface, description);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryAppendBridgeRule(raw, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Updates an existing L2 bridge forward rule in place in the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult EditBridgeRule(
        string? bundleJson,
        string? summary,
        ulong? compareToRevision,
        int ruleIndex,
        string? etherType,
        string? verdict,
        string? inputInterface,
        string? outputInterface,
        string? description = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var input = new VisualBridgeRuleInput(etherType, verdict, inputInterface, outputInterface, description);
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryUpdateBridgeRule(raw, ruleIndex, input, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Removes an L2 bridge forward rule by index from the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult RemoveBridgeRule(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryRemoveBridgeRule(raw, ruleIndex, out var updated, out var diags),
            updated,
            diags);
    }

    /// <summary>Clears the optional L2 bridge table section from the draft bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult ClearBridge(string? bundleJson, string? summary, ulong? compareToRevision)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        return ApplyDraftMutation(
            role,
            raw,
            summary,
            compareToRevision,
            PolicyAuthoringService.TryClearBridge(raw, out var updated, out var diags),
            updated,
            diags);
    }

    private IActionResult ApplyDraftMutation(
        string role,
        string raw,
        string? summary,
        ulong? compareToRevision,
        bool succeeded,
        string? updatedJson,
        IReadOnlyList<Nergal.Nftables.PolicyDiagnostic> diagnostics)
    {
        var revisions = store.ListPolicyRevisions();
        if (!succeeded || updatedJson is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            var existing = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
            var failed = existing with { IsValid = false, Diagnostics = diagnostics };
            return View("Policies", BuildPolicyModel(role, raw, summary, null, compareToRevision, revisions, failed));
        }

        var report = PolicyAuthoringService.EvaluateDraft(updatedJson, store, compareToRevision);
        return View("Policies", BuildPolicyModel(role, updatedJson, summary, null, compareToRevision, revisions, report));
    }

    /// <summary>Removes a filter rule by index from the draft policy bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult RemoveFilterRule(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var revisions = store.ListPolicyRevisions();
        if (!PolicyAuthoringService.TryRemoveFilterRule(raw, ruleIndex, out var updatedJson, out var diagnostics) || updatedJson is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            var existing = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
            var failed = existing with { IsValid = false, Diagnostics = diagnostics };
            return View("Policies", BuildPolicyModel(role, raw, summary, null, compareToRevision, revisions, failed));
        }

        var report = PolicyAuthoringService.EvaluateDraft(updatedJson, store, compareToRevision);
        return View("Policies", BuildPolicyModel(role, updatedJson, summary, null, compareToRevision, revisions, report));
    }

    /// <summary>Moves a filter rule up or down in the draft policy bundle (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(524288)]
    public IActionResult MoveFilterRule(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex, int direction)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var raw = bundleJson ?? "";
        var revisions = store.ListPolicyRevisions();
        if (!PolicyAuthoringService.TryMoveFilterRule(raw, ruleIndex, direction, out var updatedJson, out var diagnostics) || updatedJson is null)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            var existing = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
            var failed = existing with { IsValid = false, Diagnostics = diagnostics };
            return View("Policies", BuildPolicyModel(role, raw, summary, null, compareToRevision, revisions, failed));
        }

        var report = PolicyAuthoringService.EvaluateDraft(updatedJson, store, compareToRevision);
        return View("Policies", BuildPolicyModel(role, updatedJson, summary, null, compareToRevision, revisions, report));
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

    /// <summary>Displays system settings covering branding, authentication providers, database backend, and firewall defaults.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public IActionResult Settings(string? notice = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role))
        {
            return Forbid();
        }

        var settings = store.ReadSystemSettings();
        var model = new SystemSettingsViewModel
        {
            ActorId = actorId,
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            Settings = settings,
            StatusMessage = notice == "saved" ? "System settings saved and recorded in the append-only audit log." : null,
            ValidationErrors = [],
        };
        return View(model);
    }

    /// <summary>Validates and persists system settings with append-only audit logging (Administrator only).</summary>
    [HttpPost, Authorize(Policy = ControllerAuthorizationPolicies.Administrator), ValidateAntiForgeryToken]
    [RequestSizeLimit(16384)]
    public IActionResult SaveSettings(
        string? applicationName,
        string? instanceSubtitle,
        string? accentColor,
        string? defaultTheme,
        string? loginBanner,
        bool localAuthEnabled,
        int sessionIdleTimeoutMinutes,
        int lockoutMaxFailedAttempts,
        int lockoutDurationMinutes,
        int minimumPasswordLength,
        bool oidcEnabled,
        string? oidcAuthorityUrl,
        string? oidcClientId,
        string? oidcScopes,
        string? oidcRedirectUri,
        string? oidcGroupsClaim,
        string? oidcAdministratorGroups,
        string? oidcAuditorGroups,
        int oidcMaxAuthAgeSeconds,
        bool ldapEnabled,
        string? ldapServerUri,
        bool ldapUseStartTls,
        string? ldapBaseDn,
        string? ldapBindDn,
        string? ldapUserSearchFilter,
        string? ldapGroupMembershipAttribute,
        string? ldapAdministratorGroupDn,
        string? ldapAuditorGroupDn,
        string? databaseProvider,
        string? databaseHost,
        int? databasePort,
        string? databaseName,
        string? databaseUsername,
        string? databaseTlsMode,
        int defaultConfirmationTimeoutSeconds,
        int defaultFilterSchemaVersion,
        string? defaultInputVerdict,
        string? defaultForwardVerdict,
        string? defaultOutputVerdict,
        bool requireChangeSummary)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out var actorId, out var role) ||
            role != NergalRoles.Administrator)
        {
            return Forbid();
        }

        var candidate = new SystemSettingsSnapshot(
            new BrandingSettings(
                (applicationName ?? "").Trim(),
                (instanceSubtitle ?? "").Trim(),
                (accentColor ?? "blue").Trim().ToLowerInvariant(),
                (defaultTheme ?? "system").Trim().ToLowerInvariant(),
                string.IsNullOrWhiteSpace(loginBanner) ? null : loginBanner.Trim()),
            new LocalAuthSettings(
                localAuthEnabled,
                sessionIdleTimeoutMinutes,
                lockoutMaxFailedAttempts,
                lockoutDurationMinutes,
                minimumPasswordLength),
            new OidcAuthSettings(
                oidcEnabled,
                string.IsNullOrWhiteSpace(oidcAuthorityUrl) ? null : oidcAuthorityUrl.Trim(),
                string.IsNullOrWhiteSpace(oidcClientId) ? null : oidcClientId.Trim(),
                string.IsNullOrWhiteSpace(oidcScopes) ? "openid profile email groups" : oidcScopes.Trim(),
                string.IsNullOrWhiteSpace(oidcRedirectUri) ? null : oidcRedirectUri.Trim(),
                string.IsNullOrWhiteSpace(oidcGroupsClaim) ? "groups" : oidcGroupsClaim.Trim(),
                string.IsNullOrWhiteSpace(oidcAdministratorGroups) ? null : oidcAdministratorGroups.Trim(),
                string.IsNullOrWhiteSpace(oidcAuditorGroups) ? null : oidcAuditorGroups.Trim(),
                oidcMaxAuthAgeSeconds == 0 ? 3600 : oidcMaxAuthAgeSeconds),
            new LdapAuthSettings(
                ldapEnabled,
                string.IsNullOrWhiteSpace(ldapServerUri) ? null : ldapServerUri.Trim(),
                ldapUseStartTls,
                string.IsNullOrWhiteSpace(ldapBaseDn) ? null : ldapBaseDn.Trim(),
                string.IsNullOrWhiteSpace(ldapBindDn) ? null : ldapBindDn.Trim(),
                string.IsNullOrWhiteSpace(ldapUserSearchFilter) ? "(uid={0})" : ldapUserSearchFilter.Trim(),
                string.IsNullOrWhiteSpace(ldapGroupMembershipAttribute) ? "memberOf" : ldapGroupMembershipAttribute.Trim(),
                string.IsNullOrWhiteSpace(ldapAdministratorGroupDn) ? null : ldapAdministratorGroupDn.Trim(),
                string.IsNullOrWhiteSpace(ldapAuditorGroupDn) ? null : ldapAuditorGroupDn.Trim()),
            new DatabaseBackendSettings(
                (databaseProvider ?? "sqlite").Trim().ToLowerInvariant(),
                string.IsNullOrWhiteSpace(databaseHost) ? null : databaseHost.Trim(),
                databasePort,
                string.IsNullOrWhiteSpace(databaseName) ? null : databaseName.Trim(),
                string.IsNullOrWhiteSpace(databaseUsername) ? null : databaseUsername.Trim(),
                string.IsNullOrWhiteSpace(databaseTlsMode) ? "require" : databaseTlsMode.Trim().ToLowerInvariant()),
            new FirewallDefaultsSettings(
                defaultConfirmationTimeoutSeconds,
                defaultFilterSchemaVersion,
                (defaultInputVerdict ?? "drop").Trim().ToLowerInvariant(),
                (defaultForwardVerdict ?? "drop").Trim().ToLowerInvariant(),
                (defaultOutputVerdict ?? "accept").Trim().ToLowerInvariant(),
                requireChangeSummary));

        var errors = SystemSettingsCodec.Validate(candidate);
        if (errors.Count > 0)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            ViewData["Branding"] = store.ReadSystemSettings().Branding;
            return View("Settings", new SystemSettingsViewModel
            {
                ActorId = actorId,
                ActorRole = role,
                CanMutate = true,
                Settings = candidate,
                ErrorMessage = "One or more settings failed validation. Review the highlighted codes below.",
                ValidationErrors = errors,
            });
        }

        store.SaveSystemSettings(candidate, actorId, role);
        return LocalRedirect("~/manage/settings?notice=saved");
    }

    private async Task<FleetDashboardViewModel> BuildDashboardModelAsync(
        string actorId,
        string role,
        string? error,
        CancellationToken cancellationToken)
    {
        var allRevisions = store.ListPolicyRevisions();
        var latest = allRevisions.FirstOrDefault();
        Core.Policy.FirewallPolicyBundle? latestBundle = null;
        if (latest is not null && PolicyAuthoringService.TryDecodeBundle(latest.PolicyJson, out var decoded, out _))
        {
            latestBundle = decoded;
        }

        var hosts = store.ListHosts();
        var healthList = new List<HostHealthSummary>(hosts.Count);
        foreach (var host in hosts)
        {
            if (applyWorkflow is null)
            {
                healthList.Add(new HostHealthSummary
                {
                    Host = host,
                    Reachable = false,
                    StateLabel = "unqueried",
                    ReportedRevision = host.LastKnownRevision > 0 ? host.LastKnownRevision : null,
                });
                continue;
            }

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                var status = await applyWorkflow.QueryHostStatusAsync(host.Id, cts.Token);
                var reply = status.Reply;
                if (reply is null || reply.Outcome is AgentControlOutcome.Unavailable or AgentControlOutcome.Rejected or AgentControlOutcome.Denied)
                {
                    healthList.Add(new HostHealthSummary
                    {
                        Host = status.Host ?? host,
                        Reachable = false,
                        StateLabel = "unavailable",
                        ReportedRevision = host.LastKnownRevision > 0 ? host.LastKnownRevision : null,
                        ErrorCode = reply?.ErrorCode ?? "unreachable",
                    });
                }
                else
                {
                    var stateLabel = reply.OperationId.HasValue || reply.Outcome == AgentControlOutcome.AppliedPendingConfirmation
                        ? "pending"
                        : reply.Outcome switch
                        {
                            AgentControlOutcome.Matched or AgentControlOutcome.Confirmed => "matched",
                            AgentControlOutcome.Drift => "drift",
                            AgentControlOutcome.Unbound => "missing",
                            _ => "online",
                        };

                    healthList.Add(new HostHealthSummary
                    {
                        Host = status.Host ?? host,
                        Reachable = true,
                        StateLabel = stateLabel,
                        ReportedRevision = reply.Revision,
                    });
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                healthList.Add(new HostHealthSummary
                {
                    Host = host,
                    Reachable = false,
                    StateLabel = "unavailable",
                    ReportedRevision = host.LastKnownRevision > 0 ? host.LastKnownRevision : null,
                    ErrorCode = "timeout",
                });
            }
        }

        return new FleetDashboardViewModel
        {
            ActorId = actorId,
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            Hosts = hosts,
            HostHealth = healthList,
            LatestRevision = latest,
            LatestBundle = latestBundle,
            TotalRevisions = allRevisions.Count,
            Settings = store.ReadSystemSettings(),
            RecentAudit = store.ListAuditEntries(20),
            ErrorMessage = error,
        };
    }

    private PolicyEditorViewModel BuildPolicyModel(
        string role,
        string bundleJson,
        string? summary,
        ulong? selectedRevision,
        ulong? compareToRevision,
        IReadOnlyList<PolicyRevisionRecord> revisions,
        PolicyEvaluationReport report,
        PolicyObjectBrowseSelection? objectBrowseSelection = null) =>
        new()
        {
            ActorRole = role,
            CanMutate = role == NergalRoles.Administrator,
            LibraryObjects = objectBrowseSelection is not null ? PolicyObjectVersionChoices.Load(store, objectBrowseSelection.ObjectId) : store.ListReusableObjects(),
            ObjectBrowseSelection = objectBrowseSelection,
            BundleJson = bundleJson,
            Summary = summary,
            SelectedRevision = selectedRevision,
            CompareToRevision = compareToRevision,
            Revisions = revisions,
            Bundle = report.Bundle,
            Compatibility = report.Compatibility,
            CandidateText = report.CandidateText,
            CandidateDigest = report.CandidateDigest,
            UnifiedDiff = report.UnifiedDiff,
            IntentDiff = report.IntentDiff,
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
