using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Changes one rule's enabled state in the submitted draft only, preserving all other intent.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(524288)]
    public async Task<IActionResult> SetRuleState(string? bundleJson, string? summary, ulong? compareToRevision, string? scope, int ruleIndex, string? chain, string? enabled)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var raw = bundleJson ?? "";
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ModelState.IsValid || form.Files.Count != 0 || form.Any(kv => kv.Value.Count != 1) ||
            form.Keys.Any(k => k is not ("bundleJson" or "summary" or "compareToRevision" or "scope" or "ruleIndex" or "chain" or "enabled" or "__RequestVerificationToken")) ||
            !form.ContainsKey("ruleIndex") || !Enum.TryParse<PolicyRuleScope>(scope, out var parsedScope) || !Enum.IsDefined(parsedScope) || parsedScope.ToString() != scope || enabled is not (null or "true"))
        { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.stateFormInvalid", "rule")]); }
        if (!PolicyAuthoringService.TryDecodeBundle(raw, out var bundle, out var errors) || bundle is null)
        { return ObjectDraftFailure(raw, summary, compareToRevision, errors); }
        try
        {
            var next = PolicyRuleStates.SetEnabled(bundle, parsedScope, ruleIndex, string.IsNullOrEmpty(chain) ? null : chain, enabled == "true");
            var compiled = NftPolicyBundleCompiler.Compile(next);
            return ApplyDraftMutation(NergalRoles.Administrator, raw, summary, compareToRevision, compiled.IsSuccess,
                compiled.IsSuccess ? PolicyAuthoringService.EncodeBundle(next) : null, compiled.Diagnostics);
        }
        catch (ArgumentException) { return ObjectDraftFailure(raw, summary, compareToRevision, [new("rule.stateLocationInvalid", "rule")]); }
    }
}
