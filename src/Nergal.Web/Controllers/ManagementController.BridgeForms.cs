using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Configures bridge hook priority/defaults or removes an explicitly empty draft table.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetBridgeSettings(string? bundleJson, string? summary, ulong? compareToRevision, string? operation, int? priority, string? verdict)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? ""; var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "priority", "verdict"], []) || (form.ContainsKey("priority") && priority is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("bridge.settingsFormInvalid", "bridge")]); }
        var valid = PolicyAuthoringService.TrySetBridgeSettings(raw, operation, priority, verdict, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Creates or removes a local declared regular chain; the complete compiler rejects missing targets and cycles.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetBridgeChain(string? bundleJson, string? summary, ulong? compareToRevision, string? operation, string? name)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? ""; var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "name"], []))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("bridge.chainFormInvalid", "bridge.subChains")]); }
        var valid = PolicyAuthoringService.TrySetBridgeChain(raw, operation, name, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Authors a complete ordered bridge rule in the base or one declared regular chain, retaining enabled state.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetExtendedBridgeRule(string? bundleJson, string? summary, ulong? compareToRevision, string? operation, string? chain, int? ruleIndex,
        string? etherType, string? action, string? inputInterface, string? outputInterface, string? bridgeName, string? sourceMac, string? destinationMac,
        string? negateSourceMac, string? negateDestinationMac, string? family, string? source, string? destination, string? protocol,
        string? destinationPorts, string? jumpTarget, string? description)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? ""; var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "chain", "ruleIndex", "etherType", "action", "inputInterface", "outputInterface", "bridgeName", "sourceMac", "destinationMac", "negateSourceMac", "negateDestinationMac", "family", "source", "destination", "protocol", "destinationPorts", "jumpTarget", "description"],
            ["negateSourceMac", "negateDestinationMac"]) || (form.ContainsKey("ruleIndex") && ruleIndex is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("bridge.ruleFormInvalid", "bridge")]); }
        var valid = PolicyAuthoringService.TrySetExtendedBridgeRule(raw, operation, string.IsNullOrEmpty(chain) ? null : chain, ruleIndex,
            new(etherType, action, inputInterface, outputInterface, bridgeName, sourceMac, destinationMac, negateSourceMac == "true", negateDestinationMac == "true",
                family, source, destination, protocol, destinationPorts, jumpTarget, description), out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
}
