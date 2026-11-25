using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Updates explicit filter conditions in an unsaved draft; no revision or privileged operation occurs.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> EditFilterConditions(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex,
        string? sourceMacs, string? negateSourceMac, string? negateSource, string? negateDestination,
        string? negateInputInterface, string? negateOutputInterface, string? rateLimitKey, string? refreshEntryTimeout = null)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["ruleIndex", "sourceMacs", "negateSourceMac", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "rateLimitKey", "refreshEntryTimeout"],
            ["negateSourceMac", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "refreshEntryTimeout"]) || !form.ContainsKey("ruleIndex"))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.conditionsFormInvalid", "rule")]); }
        var valid = PolicyAuthoringService.TryUpdateFilterConditions(raw, ruleIndex,
            new(sourceMacs, negateSourceMac == "true", negateSource == "true", negateDestination == "true", negateInputInterface == "true", negateOutputInterface == "true", rateLimitKey, refreshEntryTimeout is null ? null : refreshEntryTimeout == "true"), out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    /// <summary>Adds or updates a complete postrouting draft rule, retaining its existing enabled state and order.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetPostrouting(string? bundleJson, string? summary, ulong? compareToRevision, int? ruleIndex,
        string? family, string? action, string? source, string? destination, string? translatedAddress, string? inputInterface,
        string? outputInterface, string? protocol, string? destinationPorts, string? negateSource, string? negateDestination,
        string? negateInputInterface, string? negateOutputInterface, string? description)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ValidRouterForm(form, ["ruleIndex", "family", "action", "source", "destination", "translatedAddress", "inputInterface", "outputInterface", "protocol", "destinationPorts", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "description"],
            ["negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface"]) || (form.ContainsKey("ruleIndex") && ruleIndex is null))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.postroutingFormInvalid", "rule")]); }
        var valid = PolicyAuthoringService.TrySetPostrouting(raw, ruleIndex,
            new(family, action, source, destination, translatedAddress, inputInterface, outputInterface, protocol, destinationPorts,
                negateSource == "true", negateDestination == "true", negateInputInterface == "true", negateOutputInterface == "true", description), out var updated, out var errors);
        return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }

    // Reject duplicate/unknown fields and malformed checkboxes rather than accepting binder defaults that broaden policy.
    private bool ValidRouterForm(IFormCollection form, string[] fields, string[] checkboxes) =>
        ModelState.IsValid && form.Files.Count == 0 && form.All(kv => kv.Value.Count == 1) &&
        form.Keys.All(k => k is "bundleJson" or "summary" or "compareToRevision" or "__RequestVerificationToken" || fields.Contains(k, StringComparer.Ordinal)) &&
        checkboxes.All(k => !form.ContainsKey(k) || form[k] == "true");
}
