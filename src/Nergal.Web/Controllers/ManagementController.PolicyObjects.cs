using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Policy;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Browses a list history without altering intent, or explicitly replaces/removes a supported draft matcher reference; never saves a revision or applies a firewall.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetPolicyObject(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex, string? slot, string? selection, string? operation, string? scope = null, string? chain = null)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var raw = bundleJson ?? "";
        IReadOnlyList<PolicyDiagnostic> errors = [];
        PolicyObjectReference? reference = null;
        if (!ModelState.IsValid || form.Files.Count != 0 || form.Any(kv => kv.Value.Count != 1) ||
            form.Keys.Any(k => k is not ("bundleJson" or "summary" or "compareToRevision" or "ruleIndex" or "slot" or "selection" or "operation" or "scope" or "chain" or "__RequestVerificationToken")) ||
            !form.ContainsKey("ruleIndex") || operation is not ("attach" or "remove" or "history") || (form.ContainsKey("scope") && scope is not ("primary" or "auxiliary" or "postrouting" or "bridge" or "bridgeChain"))) { errors = [new("object.formInvalid", "object")]; }
        else if (operation is "attach" or "history")
        {
            var parts = (selection ?? "").Split('/');
            if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "D", out var id) || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var version))
            { errors = [new("object.selectionInvalid", "selection")]; }
            else if (store.ReadReusableObject(id, version) is not { } selected) { errors = [new("object.referenceNotFound", "selection")]; }
            else { reference = new(selected.Id, selected.Version, selected.Content); }
        }
        if (errors.Count != 0) { return ObjectDraftFailure(raw, summary, compareToRevision, errors); }
        if (operation == "history")
        {
            // Browse only changes the bounded selector choices, never the supplied rule, slot or canonical draft.
            var report = PolicyAuthoringService.EvaluateDraft(raw, store, compareToRevision);
            if (!report.IsValid) { return ObjectDraftFailure(raw, summary, compareToRevision, report.Diagnostics); }
            if (!HistoryTargetExists(report.Bundle!, ruleIndex, slot, form.ContainsKey("scope") ? scope! : "primary", form.ContainsKey("chain") ? chain ?? "" : null))
            { return ObjectDraftFailure(raw, summary, compareToRevision, [new("object.matcherInvalid", "object")]); }
            return View("Policies", BuildPolicyModel(NergalRoles.Administrator, raw, summary, null, compareToRevision, store.ListPolicyRevisions(), report, new(form.ContainsKey("scope") ? scope! : "primary", ruleIndex, slot ?? "", form.ContainsKey("chain") ? chain : null, reference!.Id, reference.Version)));
        }
        var valid = PolicyObjectAuthoring.TrySet(raw, ruleIndex, slot ?? "", reference, out var updated, out errors, form.ContainsKey("scope") ? scope! : "primary", form.ContainsKey("chain") ? chain ?? "" : null);
        return ApplyDraftMutation(Nergal.Core.Identity.NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
    private static bool HistoryTargetExists(FirewallPolicyBundle bundle, int index, string? slot, string scope, string? chain)
    {
        if (index < 0) { return false; }
        if (scope is "primary" or "auxiliary")
        {
            var rules = scope == "primary" ? bundle.Filter.Rules : bundle.AuxiliaryFilter?.Filter.Rules;
            return chain is null && (slot is "source" or "destination" or "ports") && rules is not null && index < rules.Count && rules[index] is not null;
        }
        if (scope == "postrouting") { return chain is null && (slot is "source" or "destination" or "ports") && bundle.Nat is { } nat && index < nat.SnatRules.Count && nat.SnatRules[index] is not null; }
        if (slot != "ports" || (scope == "bridgeChain" ? string.IsNullOrEmpty(chain) : chain is not null)) { return false; }
        var bridgeRules = scope == "bridge" ? bundle.Bridge?.Rules : bundle.Bridge?.SubChains.FirstOrDefault(c => c.Name == chain)?.Rules;
        return bridgeRules is not null && index < bridgeRules.Count && bridgeRules[index] is not null;
    }

    private IActionResult ObjectDraftFailure(string raw, string? summary, ulong? baseline, IReadOnlyList<PolicyDiagnostic> errors)
    {
        var report = PolicyAuthoringService.EvaluateDraft(raw, store, baseline);
        Response.StatusCode = 400;
        return View("Policies", BuildPolicyModel(Nergal.Core.Identity.NergalRoles.Administrator, raw, summary, null, baseline, store.ListPolicyRevisions(), report with { IsValid = false, Diagnostics = errors }));
    }
}
