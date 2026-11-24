using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Nergal.Core.Identity;

namespace Nergal.Web.Controllers;

public sealed partial class ManagementController
{
    /// <summary>Downloads the exact create-only native projection of one verified saved revision, without applying it.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult ExportNativePolicy(ulong? revision) => ExportSavedPolicy(revision, native: true);

    /// <summary>Downloads canonical complete saved intent, including dormant rules and immutable reference snapshots.</summary>
    [HttpGet, Authorize(Policy = ControllerAuthorizationPolicies.Administrator)]
    public IActionResult ExportPolicyIntent(ulong? revision) => ExportSavedPolicy(revision, native: false);

    private IActionResult ExportSavedPolicy(ulong? revision, bool native)
    {
        if (!SourceAdministrator(out _)) { return Forbid(); }
        if (!ModelState.IsValid || revision is null or 0 or > long.MaxValue) { return BadRequest(); }
        var saved = store.GetPolicyRevision(revision.Value);
        if (saved is null) { return NotFound(); }
        var export = PolicyRevisionExport.Create(saved);
        if (export is null)
        {
            return Conflict(new { code = "export.revisionInvalid" });
        }

        var number = saved.Revision.ToString(CultureInfo.InvariantCulture);
        return File(new UTF8Encoding(false, true).GetBytes(native ? export.NativeText : export.PolicyJson),
            native ? "application/octet-stream" : "application/json",
            "nergal-revision-" + number + (native ? "-nftables.conf" : "-policy.json"));
    }
}
