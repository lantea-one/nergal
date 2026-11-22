using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Policy;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Explicitly replaces or removes a primary filter matcher reference in an unsaved draft; no revision/apply occurs.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetPolicyObject(string? bundleJson, string? summary, ulong? compareToRevision, int ruleIndex, string? slot, string? selection, string? operation)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        var raw = bundleJson ?? "";
        IReadOnlyList<PolicyDiagnostic> errors = [];
        PolicyObjectReference? reference = null;
        if (!ModelState.IsValid || form.Files.Count != 0 || form.Any(kv => kv.Value.Count != 1) ||
            form.Keys.Any(k => k is not ("bundleJson" or "summary" or "compareToRevision" or "ruleIndex" or "slot" or "selection" or "operation" or "__RequestVerificationToken")) ||
            !form.ContainsKey("ruleIndex") || operation is not ("attach" or "remove")) { errors = [new("object.formInvalid", "object")]; }
        else if (operation == "attach")
        {
            var parts = (selection ?? "").Split('/');
            if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "D", out var id) || !int.TryParse(parts[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var version))
            { errors = [new("object.selectionInvalid", "selection")]; }
            else if (store.ReadReusableObject(id, version) is not { } selected) { errors = [new("object.referenceNotFound", "selection")]; }
            else { reference = new(selected.Id, selected.Version, selected.Content); }
        }
        if (errors.Count != 0) { return ObjectDraftFailure(raw, summary, compareToRevision, errors); }
        var valid = PolicyObjectAuthoring.TrySet(raw, ruleIndex, slot ?? "", reference, out var updated, out errors);
        return ApplyDraftMutation(Nergal.Core.Identity.NergalRoles.Administrator, raw, summary, compareToRevision, valid, updated, errors);
    }
    private IActionResult ObjectDraftFailure(string raw, string? summary, ulong? baseline, IReadOnlyList<PolicyDiagnostic> errors)
    {
        var report = PolicyAuthoringService.EvaluateDraft(raw, store, baseline);
        Response.StatusCode = 400;
        return View("Policies", BuildPolicyModel(Nergal.Core.Identity.NergalRoles.Administrator, raw, summary, null, baseline, store.ListPolicyRevisions(), report with { IsValid = false, Diagnostics = errors }));
    }
}
