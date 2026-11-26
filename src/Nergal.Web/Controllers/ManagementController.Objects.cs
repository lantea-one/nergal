using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Displays typed library contents and immutable version history to authorized readers.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Reader)]
    public IActionResult Objects(Guid? objectId = null, int? version = null, string? q = null, int? compareToVersion = null)
    {
        if (!ControllerAuthorization.TryResolveActor(User, out _, out var role)) { return Forbid(); }
        if (!ModelState.IsValid || q?.Length > 120 || version is < 1 or > 64 || compareToVersion is < 1 or > 64 || ((version.HasValue || compareToVersion.HasValue) && !objectId.HasValue) ||
            Request.Query.Any(kv => kv.Value.Count != 1)) { return BadRequest(); }
        var selected = objectId.HasValue ? store.ReadReusableObject(objectId.Value, version) : null;
        if (objectId.HasValue && selected is null) { return NotFound(); }
        var baseline = compareToVersion.HasValue ? store.ReadReusableObject(objectId!.Value, compareToVersion.Value) : null;
        if (compareToVersion.HasValue && baseline is null) { return NotFound(); }
        var model = ObjectModel(selected, role == NergalRoles.Administrator, q);
        return View(baseline is null ? model : model with { Comparison = ObjectVersionComparison.Create(baseline, selected!) });
    }

    /// <summary>Appends a validated library version with audit and stale-edit protection; never changes a policy.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(24_576), RequestFormLimits(ValueLengthLimit = 8192, ValueCountLimit = 8)]
    public async Task<IActionResult> SaveObject(Guid? id, int expectedVersion, string? name, string? kind, string? description, string? entries)
    {
        if (!SourceAdministrator(out var actor)) { return Forbid(); }
        var input = new ObjectLibraryInput(id, expectedVersion, name ?? "", kind ?? "", description ?? "", entries ?? "");
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (!ModelState.IsValid || form.Files.Count != 0 || form.Keys.Any(k => k is not ("id" or "expectedVersion" or "name" or "kind" or "description" or "entries" or "__RequestVerificationToken")) ||
            form.Any(kv => kv.Value.Count != 1) || new[] { "expectedVersion", "name", "kind", "description", "entries" }.Any(k => !form.ContainsKey(k)))
        { return ObjectFailure(input, L["Submit each field once. Check the list name, type, description and entries."].Value); }
        try
        {
            var type = kind switch { "ipv4" => ReusableObjectKind.Ipv4, "ipv6" => ReusableObjectKind.Ipv6, "port" => ReusableObjectKind.Port, _ => throw new ArgumentException("object.kindInvalid") };
            var lines = (entries ?? "").Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').Select(e => e.Trim()).Where(e => e.Length > 0);
            var content = new ReusableObjectContent(name ?? "", type, description ?? "", lines);
            var saved = store.SaveReusableObject(id, expectedVersion, content, actor, NergalRoles.Administrator);
            return RedirectToAction(nameof(Objects), new { objectId = saved.Id });
        }
        catch (ArgumentException ex) { return ObjectFailure(input, ObjectError(ex.Message.Split([' ', '\r', '\n'])[0])); }
        catch (ControllerStateException ex) when (ex.Code is "object.staleVersion" or "object.duplicateName" or "object.identityImmutable" or "object.notFound" or "object.capacityExceeded" or "object.versionCapacityExceeded")
        { return ObjectFailure(input, ObjectError(ex.Code), ex.Code == "object.staleVersion" ? 409 : 400); }
    }

    private ObjectLibraryPageModel ObjectModel(ReusableObjectVersion? selected, bool canMutate, string? query = null, ObjectLibraryInput? input = null, string? error = null)
    {
        var objects = store.ListReusableObjects();
        if (!string.IsNullOrWhiteSpace(query)) { objects = objects.Where(o => o.Content.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || o.Content.Description.Contains(query, StringComparison.OrdinalIgnoreCase)).ToArray(); }
        return new(objects, selected is null ? [] : store.ListReusableObjectVersions(selected.Id), selected, canMutate, query, input, error, selected is null ? [] : store.ListPolicyObjectUsage(selected.Id));
    }
    private IActionResult ObjectFailure(ObjectLibraryInput input, string error, int status = 400)
    {
        Response.StatusCode = status;
        return View("Objects", ObjectModel(input.Id.HasValue ? store.ReadReusableObject(input.Id.Value) : null, true, input: input, error: error));
    }
    private string ObjectError(string code) => code switch
    {
        "object.nameInvalid" => L["Use a name of 1–64 lowercase letters, digits or underscores, starting with a letter."].Value,
        "object.kindInvalid" => L["Choose IPv4 addresses, IPv6 addresses or transport ports."].Value,
        "object.descriptionInvalid" => L["Use a plain-text description of at most 500 characters."].Value,
        "object.entryCountInvalid" => L["Enter 1–64 entries, one per line."].Value,
        "object.duplicateEntry" => L["Remove duplicate entries. An address and its /32 or /128 prefix identify the same entry."].Value,
        "object.portInvalid" => L["Enter individual numeric ports from 1 to 65535. Port ranges are not supported."].Value,
        "object.familyMismatch" => L["Every address must match the selected IPv4 or IPv6 type."].Value,
        "object.addressInvalid" or "object.prefixInvalid" or "object.entryInvalid" => L["Use numeric addresses or CIDRs with zero host bits. Names, ranges, scoped and mapped addresses are not supported."].Value,
        "object.staleVersion" => L["Another edit was saved first. Your input is retained; open the current version in another tab and compare before editing again."].Value,
        "object.duplicateName" => L["That name already exists. Choose a different identifier or edit the existing list."].Value,
        "object.identityImmutable" => L["An existing list's name and type cannot change. Create a separate list instead."].Value,
        "object.notFound" => L["The selected list or expected version is invalid. Open the library and select the list again."].Value,
        "object.capacityExceeded" => L["The library has reached its limit of 128 lists. No list or audit entry was added."].Value,
        "object.versionCapacityExceeded" => L["This list has reached its limit of 64 immutable versions. No change was saved."].Value,
        _ => L["Check the list name, type, description and entries. No change was saved."].Value
    };
}
