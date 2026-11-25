using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Configures the owned auxiliary inet draft table or removes it after its rules have been explicitly removed.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetAuxiliaryDefaults(string? bundleJson, string? summary, ulong? compareToRevision, string? operation,
        int? priority, string? inputDefault, string? forwardDefault, string? outputDefault)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "priority", "inputDefault", "forwardDefault", "outputDefault"], []) || (form.ContainsKey("priority") && priority is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("auxiliary.formInvalid", "auxiliaryFilter")]); }
        var valid = PolicyAuthoringService.TrySetAuxiliaryDefaults(raw, operation, priority, inputDefault, forwardDefault, outputDefault, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Authors a complete ordered auxiliary filter rule in a draft without invoking an agent or saving a revision.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetAuxiliaryRule(string? bundleJson, string? summary, ulong? compareToRevision, string? operation, int? ruleIndex,
        string? chain, string? family, string? protocol, string? verdict, string? sources, string? destinations, string? destinationPorts,
        string? icmpType, string? inputInterface, string? outputInterface, string? connectionStates, string? matchOriginalDestinationDnat,
        int? rateLimitPackets, string? rateLimitUnit, int? rateLimitBurst, int? rateLimitTimeout, string? description, string? sourceMacs,
        string? negateSourceMac, string? negateSource, string? negateDestination, string? negateInputInterface, string? negateOutputInterface, string? rateLimitKey, string? refreshEntryTimeout = null)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "ruleIndex", "chain", "family", "protocol", "verdict", "sources", "destinations", "destinationPorts", "icmpType", "inputInterface", "outputInterface", "connectionStates", "matchOriginalDestinationDnat", "rateLimitPackets", "rateLimitUnit", "rateLimitBurst", "rateLimitTimeout", "description", "sourceMacs", "negateSourceMac", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "rateLimitKey", "refreshEntryTimeout"],
            ["matchOriginalDestinationDnat", "negateSourceMac", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "refreshEntryTimeout"]) || (form.ContainsKey("ruleIndex") && ruleIndex is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("auxiliary.formInvalid", "auxiliaryFilter")]); }
        var valid = PolicyAuthoringService.TrySetAuxiliaryRule(raw, operation, ruleIndex,
            new(chain, family, protocol, verdict, sources, destinations, destinationPorts, icmpType, inputInterface, outputInterface, connectionStates,
                matchOriginalDestinationDnat == "true", rateLimitPackets, rateLimitUnit, rateLimitBurst, rateLimitTimeout, description),
            new(sourceMacs, negateSourceMac == "true", negateSource == "true", negateDestination == "true", negateInputInterface == "true", negateOutputInterface == "true", rateLimitKey, refreshEntryTimeout is null ? null : refreshEntryTimeout == "true"), out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
}
