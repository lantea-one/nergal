using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Adds, edits, removes or reorders a raw prerouting rule in the submitted draft only.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetRawRule(string? bundleJson, string? summary, ulong? compareToRevision, int? ruleIndex, string? operation,
        string? family, string? verdict, string? protocol, string? source, string? negateSource, string? inputInterface,
        string? negateInputInterface, int? sourcePort, int? destinationPort, string? matchFibUnreachable, string? description)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["ruleIndex", "operation", "family", "verdict", "protocol", "source", "negateSource", "inputInterface", "negateInputInterface", "sourcePort", "destinationPort", "matchFibUnreachable", "description"],
            ["negateSource", "negateInputInterface", "matchFibUnreachable"]) || (form.ContainsKey("ruleIndex") && ruleIndex is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rpfilter.formInvalid", "rule")]); }
        var valid = PolicyAuthoringService.TrySetRawRule(raw, ruleIndex, operation ?? "",
            new(family, verdict, protocol, source, negateSource == "true", inputInterface, negateInputInterface == "true", sourcePort, destinationPort,
                matchFibUnreachable == "true", description), out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Configures the raw chain default without replacing its ordered rules.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetRawDefault(string? bundleJson, string? summary, ulong? compareToRevision, string? verdict)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["verdict"], []))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rpfilter.formInvalid", "rule")]); }
        var valid = PolicyAuthoringService.TrySetRawDefault(raw, verdict, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Sets or explicitly removes the forward SYN MSS clamp in a draft, preserving its retained enabled state.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetMss(string? bundleJson, string? summary, ulong? compareToRevision, string? operation, int? size)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["operation", "size"], []) || (form.ContainsKey("size") && size is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("mss.formInvalid", "filter")]); }
        var valid = PolicyAuthoringService.TrySetMss(raw, operation, size, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Changes only DNAT negation flags; existing translation, matchers, position and enabled state are retained.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetDnatConditions(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex,
        string? negateSource, string? negateDestination, string? negateInputInterface)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["ruleIndex", "negateSource", "negateDestination", "negateInputInterface"],
            ["negateSource", "negateDestination", "negateInputInterface"]) || !form.ContainsKey("ruleIndex"))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("dnat.conditionsFormInvalid", "rule")]); }
        var valid = PolicyAuthoringService.TrySetDnatConditions(raw, ruleIndex, negateSource == "true", negateDestination == "true", negateInputInterface == "true", out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
    /// <summary>Moves one NAT rule by one position in a draft without altering rule contents or enabled state.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> MoveNatRule(string? bundleJson, string? summary, ulong? compareToRevision, string? kind, int ruleIndex, int direction)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["kind", "ruleIndex", "direction"], []) || !form.ContainsKey("ruleIndex") || !form.ContainsKey("direction"))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("nat.moveFormInvalid", "nat")]); }
        var valid = PolicyAuthoringService.TryMoveNatRule(raw, kind, ruleIndex, direction, out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
}
