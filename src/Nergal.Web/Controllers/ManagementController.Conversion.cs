using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Identity;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Refreshes guided choices or persists a complete source-bound review; never creates a revision or applies a firewall.</summary>
    [HttpPost("/manage/sources/conversion/review"), ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(131_072), RequestFormLimits(ValueCountLimit = 2048)]
    public IActionResult ReviewNativeConversion([Bind(Prefix = "Conversion")] NativeConversionForm form, string? operation)
    {
        if (!SourceAdministrator(out var actor)) { return Forbid(); }
        var source = store.ReadNativeSource(form.SourceId); if (source is null) { return NotFound(); }
        if (!ModelState.IsValid || operation is not ("refresh" or "review") || Request.HasFormContentType && (Request.Form.Files.Count != 0 || Request.Form.Any(kv =>
            !kv.Key.EndsWith(".Sources", StringComparison.Ordinal) && kv.Value.Count != 1 ||
            (kv.Key == "Conversion.RestrictGlobalOperations" || kv.Key.EndsWith(".EmptyWildcard", StringComparison.Ordinal)) && kv.Value != "true") || Request.Form.Keys.Any(key =>
            key is not ("operation" or "__RequestVerificationToken" or "Conversion.SourceId" or "Conversion.RestrictGlobalOperations") &&
            !Regex.IsMatch(key, @"^Conversion\.(Tables\[[0-9]{1,2}\]\.(Family|Name|Role)|Includes\[[0-9]{1,2}\]\.(SourceId|Path|Sources|EmptyWildcard))$", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking))))
        { return ConversionFailure(form, "Check the source, table roles and ordered include selections."); }
        var workflow = new NativeConversionWorkflow(store);
        try
        {
            if (operation == "refresh")
            { return View("Sources", new NativeSourcesPageModel(store.ListNativeSources(), source, nativeSources?.Sources ?? [], Conversion: workflow.Page(form.SourceId, input: form))); }
            var plan = workflow.Review(form, actor);
            return RedirectToAction(nameof(Sources), new { sourceId = form.SourceId, planId = plan.Id });
        }
        catch (ArgumentException) { return ConversionFailure(form, "The conversion choices exceed the supported bounds or contain an invalid value."); }
        catch (ControllerStateException error) when (error.Code is "conversion.sourceMissing" or "conversion.capacityExceeded")
        { return ConversionFailure(form, "A selected source is unavailable or conversion-plan storage is full. No plan was saved."); }
    }

    /// <summary>Recomputes one immutable plan and atomically saves one linked revision/list history; never dispatches an apply.</summary>
    [HttpPost("/manage/sources/conversion/commit"), ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(8192)]
    public IActionResult CommitNativeConversion(Guid planId, string? digest)
    {
        if (!SourceAdministrator(out var actor)) { return Forbid(); }
        var plan = store.ReadNativeConversionPlan(planId); if (plan is null) { return NotFound(); }
        if (!ModelState.IsValid || digest is null || Request.HasFormContentType && (Request.Form.Files.Count != 0 || Request.Form.Any(kv => kv.Value.Count != 1) || Request.Form.Keys.Any(k => k is not ("planId" or "digest" or "__RequestVerificationToken"))))
        { return BadRequest(); }
        try
        {
            var revision = new NativeConversionWorkflow(store).Commit(planId, digest, actor);
            return RedirectToAction(nameof(Policies), new { revision = revision.Revision });
        }
        catch (Exception error) when (error is ArgumentException || error is ControllerStateException state && state.Code.StartsWith("conversion.", StringComparison.Ordinal))
        {
            Response.StatusCode = StatusCodes.Status409Conflict;
            var source = store.ReadNativeSource(plan.Content.RootSourceId)!;
            return View("Sources", new NativeSourcesPageModel(store.ListNativeSources(), source, nativeSources?.Sources ?? [], Conversion:
                new NativeConversionWorkflow(store).Page(source.Summary.Id, planId, error: "This plan is blocked, already committed, or no longer matches current conversion logic. Review a new plan; no duplicate revision was created.")));
        }
    }

    /// <summary>Downloads one immutable value-free mapping/gap report, without private source text or an executable candidate.</summary>
    [HttpGet("/manage/sources/conversion/plan/{planId:guid}/report"), Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult DownloadNativeConversionPlan(Guid planId)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var plan = store.ReadNativeConversionPlan(planId);
        return plan is null ? NotFound() : File(Encoding.UTF8.GetBytes(plan.Content.ReportJson), "application/json", "native-conversion-plan.json");
    }

    private IActionResult ConversionFailure(NativeConversionForm form, string error)
    {
        Response.StatusCode = StatusCodes.Status400BadRequest;
        var source = store.ReadNativeSource(form.SourceId);
        NativeConversionPage? page = null;
        if (source is not null)
        {
            try { page = new NativeConversionWorkflow(store).Page(form.SourceId, input: form, error: error); }
            catch (Exception failure) when (failure is ArgumentException or ControllerStateException) { page = new NativeConversionWorkflow(store).Page(form.SourceId, error: error); }
        }
        return View("Sources", new NativeSourcesPageModel(store.ListNativeSources(), source, nativeSources?.Sources ?? [], error, page));
    }
}
