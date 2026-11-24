using System.Runtime.Versioning;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Deployment;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Nftables;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Downloads bind complete saved intent to exact native bytes, never drafts, mutable lists or host state.</summary>
[SupportedOSPlatform("linux")]
public sealed class PolicyRevisionExportTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());

    /// <summary>All table scopes and both list projections survive; native output excludes dormant intent only.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Export_PreservesCompleteIntentAndExactMultiTableProjection(bool native)
    {
        var reference = new PolicyObjectReference(Guid.Parse("00000000-0000-0000-0000-000000000051"), 3,
            new("web_services", ReusableObjectKind.Port, "Pinned services", ["443", "8443"]), native);
        var filter = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: reference),
             new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: reference, Enabled: false, Description: "Dormant IPv6 services")]);
        var bundle = new FirewallPolicyBundle(1, filter,
            new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("198.51.100.1/32"), "192.0.2.10", OriginalPortObject: reference)],
                [new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1")]),
            new(1, FilterVerdict.Drop, [new(BridgeEtherType.IPv4, FilterVerdict.Accept, Family: IpFamily.IPv4, Protocol: FilterProtocol.Tcp, DestinationPortObject: reference)]),
            new(-5, filter));
        var json = PolicyBundleJsonCodec.EncodeBundle(bundle);
        var compiled = NftPolicyBundleCompiler.Compile(bundle);
        Assert.True(compiled.IsSuccess, string.Join(',', compiled.Diagnostics));
        var saved = new PolicyRevisionRecord(7, json, compiled.Digest!.Value, Actor, DateTimeOffset.UnixEpoch);

        var export = Assert.IsType<PolicyRevisionExport>(PolicyRevisionExport.Create(saved));
        Assert.Equal(export, PolicyRevisionExport.Create(saved with { CreatedAtUtc = DateTimeOffset.UnixEpoch.AddDays(1), Summary = "Different metadata" }));
        Assert.Equal(json, export.PolicyJson);
        Assert.Equal(compiled.Candidate, export.NativeText);
        Assert.Equal(saved.CandidateDigest, CandidateDigest.FromText(export.NativeText).Value);
        foreach (var table in new[] { "inet nergal_filter", "inet nergal_aux", "inet nergal_nat", "bridge nergal_bridge" })
        { Assert.Contains("create table " + table, export.NativeText); }
        Assert.Equal(native, export.NativeText.Contains("@nergal_obj_", StringComparison.Ordinal));
        Assert.DoesNotContain("Dormant IPv6", export.NativeText);
        var restored = PolicyBundleJsonCodec.DecodeBundle(export.PolicyJson).Value!;
        Assert.False(restored.Filter.Rules[1]!.Enabled);
        Assert.Equal("Dormant IPv6 services", restored.Filter.Rules[1]!.Description);
        Assert.Equal(reference, restored.Filter.Rules[1]!.DestinationPortObject);
        var revisedDormantIntent = PolicyRevisionExport.Create(saved with
        {
            PolicyJson = json.Replace("Dormant IPv6 services", "Retained maintenance services", StringComparison.Ordinal)
        });
        Assert.NotNull(revisedDormantIntent);
        Assert.Equal(export.NativeText, revisedDormantIntent.NativeText);
        Assert.NotEqual(export.PolicyJson, revisedDormantIntent.PolicyJson);
    }

    /// <summary>Unknown intent, semantic failures and saved artifact mismatches cannot yield either partial export.</summary>
    [Theory]
    [InlineData("{", false)]
    [InlineData("{\"schemaVersion\":1,\"unknown\":true}", false)]
    [InlineData("{\"schemaVersion\":1,\"filter\":{\"schemaVersion\":2,\"inputDefaultVerdict\":\"drop\",\"rules\":[{\"family\":\"ipv4\",\"protocol\":\"any\",\"verdict\":\"accept\",\"destinationPort\":443}]}}", false)]
    [InlineData(null, true)]
    public void Export_RejectsInvalidOrMismatchedSavedRevision(string? json, bool wrongDigest)
    {
        json ??= PolicyAuthoringService.DefaultStarterBundleJson;
        var revision = new PolicyRevisionRecord(1, json, wrongDigest ? new string('0', 64) : new string('a', 64), Actor, DateTimeOffset.UnixEpoch);
        Assert.Null(PolicyRevisionExport.Create(revision));
    }

    /// <summary>Only administrators can select saved revisions; exports are immutable and read-only across newer saves.</summary>
    [Fact]
    public void Downloads_SelectVerifiedDatabaseRevisionAndDenyInvalidRequests()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path));
            var report = PolicyAuthoringService.EvaluateDraft(PolicyAuthoringService.DefaultStarterBundleJson);
            var saved = store.SavePolicyRevision(report.CanonicalJson!, report.CandidateDigest!, Actor, NergalRoles.Administrator);
            var invalid = store.SavePolicyRevision("{}", report.CandidateDigest!, Actor, NergalRoles.Administrator);
            var mismatch = store.SavePolicyRevision(report.CanonicalJson!, new string('0', 64), Actor, NergalRoles.Administrator);
            var admin = Controller(store, NergalRoles.Administrator);
            var native = Assert.IsType<FileContentResult>(admin.ExportNativePolicy(saved.Revision));
            var intent = Assert.IsType<FileContentResult>(admin.ExportPolicyIntent(saved.Revision));
            Assert.Equal(report.CandidateText, Encoding.UTF8.GetString(native.FileContents));
            Assert.Equal(report.CanonicalJson, Encoding.UTF8.GetString(intent.FileContents));
            Assert.Equal("nergal-revision-1-nftables.conf", native.FileDownloadName);
            Assert.Equal("nergal-revision-1-policy.json", intent.FileDownloadName);
            Assert.Equal("application/octet-stream", native.ContentType);
            Assert.Equal("application/json", intent.ContentType);
            Assert.Equal(native.FileContents, Assert.IsType<FileContentResult>(admin.ExportNativePolicy(1)).FileContents);
            Assert.Equal(3, store.ListPolicyRevisions().Count);
            Assert.Equal(3, store.ListAuditEntries().Count);
            foreach (var revision in new ulong?[] { null, 0, ulong.MaxValue })
            {
                Assert.IsType<BadRequestResult>(admin.ExportNativePolicy(revision));
                Assert.IsType<BadRequestResult>(admin.ExportPolicyIntent(revision));
            }
            Assert.IsType<NotFoundResult>(admin.ExportNativePolicy(100));
            Assert.IsType<NotFoundResult>(admin.ExportPolicyIntent(100));
            foreach (var revision in new[] { invalid.Revision, mismatch.Revision })
            {
                Assert.IsType<ConflictObjectResult>(admin.ExportNativePolicy(revision));
                Assert.IsType<ConflictObjectResult>(admin.ExportPolicyIntent(revision));
            }
            admin.ModelState.AddModelError("revision", "Invalid revision.");
            Assert.IsType<BadRequestResult>(admin.ExportNativePolicy(1));
            foreach (var role in new string?[] { null, NergalRoles.Auditor })
            {
                var denied = Controller(store, role);
                Assert.IsType<ForbidResult>(denied.ExportNativePolicy(1));
                Assert.IsType<ForbidResult>(denied.ExportPolicyIntent(1));
            }
        }
        finally { Directory.Delete(path, true); }
    }

    private static ManagementController Controller(ControllerStateStore store, string? role) => new(store)
    {
        ControllerContext = new()
        {
            HttpContext = new DefaultHttpContext
            {
                User = role is null ? new() : new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim(ClaimTypes.Role, role), new Claim(ControllerActorIdentity.ActorClaimType, Actor)], "fixture"))
            }
        }
    };
}
