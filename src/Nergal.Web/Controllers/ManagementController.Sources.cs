using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Lists immutable database sources and optionally inspects one selected snapshot.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult Sources(Guid? sourceId = null)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var selected = sourceId.HasValue ? store.ReadNativeSource(sourceId.Value) : null;
        if (sourceId.HasValue && selected is null) { return NotFound(); }
        return View(new NativeSourcesPageModel(store.ListNativeSources(), selected, nativeSources?.Sources ?? []));
    }

    /// <summary>Accepts bounded UTF-8 source bytes as an audited database snapshot; no conversion or execution occurs.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    [RequestSizeLimit(600_000), RequestFormLimits(MultipartBodyLengthLimit = 600_000, MemoryBufferThreshold = 600_000)]
    public async Task<IActionResult> ImportSource(string? name, IFormFile? sourceFile)
    {
        if (!SourceAdministrator(out var actor)) { return Forbid(); }
        if (!ModelState.IsValid) { return SourceFailure("Check the display name and configuration file."); }
        var form = await Request.ReadFormAsync(HttpContext.RequestAborted);
        if (form.Files.Count != 1 || form.Files[0].Name != "sourceFile" || form["name"].Count != 1 ||
            form.Keys.Any(k => k is not ("name" or "__RequestVerificationToken")))
        { return SourceFailure("Submit one display name and one configuration file."); }
        if (sourceFile is null || sourceFile.Length is 0 or > NativeSourceContent.MaximumBytes) { return SourceFailure("Choose a UTF-8 configuration file between 1 byte and 512 KiB."); }
        try
        {
            await using var input = sourceFile.OpenReadStream();
            using var output = new MemoryStream(); var buffer = new byte[8192]; int read;
            while ((read = await input.ReadAsync(buffer, HttpContext.RequestAborted)) > 0)
            {
                if (output.Length + read > NativeSourceContent.MaximumBytes) { return SourceFailure("The configuration exceeds 512 KiB."); }
                output.Write(buffer, 0, read);
            }
            var text = new UTF8Encoding(false, true).GetString(output.ToArray());
            return SaveSource(new(name ?? "", text), actor);
        }
        catch (DecoderFallbackException) { return SourceFailure("The file must contain valid UTF-8 text."); }
        catch (ArgumentException) { return SourceFailure("Use a display name of 1–120 characters without paths or control characters, and a nonempty UTF-8 file."); }
    }

    /// <summary>Copies an explicitly selected, immutable operator staging snapshot into audited database history.</summary>
    [HttpPost, ValidateAntiForgeryToken, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult ImportStagedSource(string? name, string? digest)
    {
        if (!SourceAdministrator(out var actor)) { return Forbid(); }
        var staged = nativeSources?.Sources.FirstOrDefault(s => s.Name == name && s.Digest == digest);
        if (staged is null) { return NotFound(); }
        try { return SaveSource(new(staged.Name, staged.Text), actor); }
        catch (ArgumentException) { return SourceFailure("The staged source has an invalid name, encoding or size."); }
    }

    /// <summary>Downloads exact original UTF-8 bytes from an immutable database snapshot, without executing or regenerating them.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult DownloadSource(Guid sourceId)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var snapshot = store.ReadNativeSource(sourceId);
        return snapshot is null ? NotFound() : File(new UTF8Encoding(false, true).GetBytes(snapshot.Content.Text), "application/octet-stream", "nftables.conf");
    }

    /// <summary>Downloads a deterministic review bound to a selected immutable database source.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult SourceReview(Guid sourceId)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        var snapshot = store.ReadNativeSource(sourceId);
        if (snapshot is null) { return NotFound(); }
        var source = new NativePolicySource(snapshot.Content.Name, snapshot.Content.Text, snapshot.Content.Digest);
        var report = new NativeSourceMigrationReport(source.Name, source.Digest, source.Review, source.Analysis.Structure.Summary, source.Analysis.RuleParsing);
        return File(JsonSerializer.SerializeToUtf8Bytes(report, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        }), "application/json", "migration-review-" + source.Digest[..12] + ".json");
    }

    private bool SourceAdministrator(out string actor) => ControllerAuthorization.TryResolveActor(User, out actor, out var role) && role == NergalRoles.Administrator;
    private IActionResult SaveSource(NativeSourceContent content, string actor)
    {
        try
        {
            var summary = store.ImportNativeSource(content, actor, NergalRoles.Administrator);
            return RedirectToAction(nameof(Sources), new { sourceId = summary.Id });
        }
        catch (ControllerStateException ex) when (ex.Code == "source.capacityExceeded") { return SourceFailure("Source storage is full (128 snapshots or 32 MiB). No source or audit record was added."); }
    }
    private IActionResult SourceFailure(string error)
    {
        Response.StatusCode = StatusCodes.Status400BadRequest;
        return View("Sources", new NativeSourcesPageModel(store.ListNativeSources(), null, nativeSources?.Sources ?? [], error));
    }
}
