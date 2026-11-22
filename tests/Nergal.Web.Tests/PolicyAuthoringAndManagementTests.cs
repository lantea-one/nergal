using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core;
using Nergal.Core.Identity;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Verifies typed bundle parsing, capability validation, unified candidate diffing, and RBAC-gated MVC actions.</summary>
[SupportedOSPlatform("linux")]
public sealed class PolicyAuthoringAndManagementTests
{
    private const string RichBundleJson = """
        {
          "schemaVersion": 1,
          "filter": {
            "schemaVersion": 2,
            "inputDefaultVerdict": "drop",
            "forwardDefaultVerdict": "drop",
            "outputDefaultVerdict": "accept",
            "rules": [
              {
                "family": "ipv4",
                "protocol": "tcp",
                "verdict": "accept",
                "chain": "forward",
                "inputInterface": "wan0",
                "outputInterface": "lan0",
                "destinationPort": 443,
                "connectionStates": ["new", "established"],
                "rateLimit": {
                  "packetsPerWindow": 20,
                  "windowUnit": "second",
                  "burst": 5,
                  "entryTimeoutSeconds": 60
                },
                "matchOriginalDestinationDnat": true
              }
            ]
          },
          "nat": {
            "schemaVersion": 1,
            "dnatRules": [
              {
                "family": "ipv4",
                "protocol": "tcp",
                "originalDestination": "198.51.100.2/32",
                "translatedAddress": "192.0.2.50",
                "originalPort": 443,
                "translatedPort": 8443
              }
            ],
            "snatRules": [
              {
                "family": "ipv4",
                "source": "192.0.2.0/24",
                "translatedAddress": "198.51.100.2",
                "outputInterface": "wan0"
              }
            ]
          },
          "bridge": {
            "schemaVersion": 1,
            "defaultVerdict": "drop",
            "rules": [
              {
                "etherType": "arp",
                "verdict": "accept",
                "inputInterface": "veth0"
              }
            ]
          }
        }
        """;

    /// <summary>Multi-table bundles round-trip deterministically and compile into unified candidate text and SHA-256 digests.</summary>
    [Fact]
    public void Authoring_EvaluatesMultiTableBundleAndComputesUnifiedDiff()
    {
        var report1 = PolicyAuthoringService.EvaluateDraft(PolicyAuthoringService.DefaultStarterBundleJson);
        Assert.True(report1.IsValid);
        Assert.NotNull(report1.CandidateText);
        Assert.NotNull(report1.CandidateDigest);
        Assert.True(report1.Compatibility!.IsCompatible);
        Assert.Contains("create table inet nergal_filter", report1.CandidateText);

        var report2 = PolicyAuthoringService.EvaluateDraft(RichBundleJson);
        Assert.True(report2.IsValid);
        Assert.Contains("create table inet nergal_nat", report2.CandidateText);
        Assert.Contains("create table bridge nergal_bridge", report2.CandidateText);

        var reevaluated = PolicyAuthoringService.EvaluateDraft(report2.CanonicalJson!);
        Assert.Equal(report2.CandidateDigest, reevaluated.CandidateDigest);

        var diff = PolicyAuthoringService.ComputeUnifiedDiff(report1.CandidateText!, report2.CandidateText!, "rev1", "rev2");
        Assert.Contains("--- rev1", diff);
        Assert.Contains("+++ rev2", diff);
        Assert.Contains("+ create table inet nergal_nat", diff);
        Assert.Contains("+ create table bridge nergal_bridge", diff);
    }

    /// <summary>Capability evaluator rejects bundles requiring unsupported features on constrained backends.</summary>
    [Fact]
    public void Authoring_RejectsUnsupportedBackendCapabilitiesFailClosed()
    {
        var limited = new BackendCapabilities("limited-nft", [FirewallFeature.DualStackFiltering, FirewallFeature.ForeignTablePreservation]);
        var report = PolicyAuthoringService.EvaluateDraft(RichBundleJson, targetCapabilities: limited);

        Assert.False(report.IsValid);
        Assert.NotNull(report.Compatibility);
        Assert.False(report.Compatibility!.IsCompatible);
        Assert.Null(report.CandidateText);
        Assert.Contains(report.Diagnostics, d => d.Code == "backend.unsupportedFeature");
    }

    /// <summary>Duplicate keys, invalid JSON, unknown properties, and semantic policy errors fail closed without partial candidates.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("{\"schemaVersion\":1,\"filter\":{\"schemaVersion\":1,\"inputDefaultVerdict\":\"drop\",\"rules\":[]},\"extra\":1}")]
    [InlineData("{\"schemaVersion\":1,\"schemaVersion\":1,\"filter\":{\"schemaVersion\":1,\"inputDefaultVerdict\":\"drop\",\"rules\":[]}}")]
    [InlineData("{\"schemaVersion\":1,\"filter\":{\"schemaVersion\":1,\"inputDefaultVerdict\":\"drop\",\"rules\":[{\"family\":\"ipv4\",\"protocol\":\"any\",\"verdict\":\"accept\",\"chain\":\"forward\"}]}}")]
    public void Authoring_RejectsMalformedOrInvalidBundles(string json)
    {
        var report = PolicyAuthoringService.EvaluateDraft(json);
        Assert.False(report.IsValid);
        Assert.Null(report.CandidateText);
        Assert.Null(report.CandidateDigest);
        Assert.NotEmpty(report.Diagnostics);
    }

    /// <summary>ManagementController enforces RBAC boundaries, validates before persistence, and logs canonical actor attribution.</summary>
    [Fact]
    public void Controller_EnforcesRbacPersistsRevisionsAndRendersDiffs()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var auditorActor = ControllerActorIdentity.FromFederatedAccount("https://idp.example", "auditor");

            var adminController = CreateController(store, adminActor, NergalRoles.Administrator);
            var auditorController = CreateController(store, auditorActor, NergalRoles.Auditor);

            // Both roles can view dashboard and preview diffs.
            var dashView = Assert.IsType<ViewResult>(auditorController.Index());
            var dashModel = Assert.IsType<FleetDashboardViewModel>(dashView.Model);
            Assert.False(dashModel.CanMutate);

            var previewView = Assert.IsType<ViewResult>(auditorController.PreviewPolicy(RichBundleJson, "Preview note", null));
            var previewModel = Assert.IsType<PolicyEditorViewModel>(previewView.Model);
            Assert.NotNull(previewModel.CandidateText);
            Assert.False(previewModel.CanMutate);

            // Auditor cannot persist hosts or policy revisions even if invoked directly.
            Assert.IsType<ForbidResult>(auditorController.AddHost("gw1", "tls", "192.0.2.10:8443", null, null, new string('a', 64)));
            Assert.IsType<ForbidResult>(auditorController.SavePolicy(RichBundleJson, "Denied", null));
            Assert.Empty(store.ListHosts());
            Assert.Empty(store.ListPolicyRevisions());

            // Invalid bundle returns 400 and persists nothing.
            var badSave = Assert.IsType<ViewResult>(adminController.SavePolicy("{invalid", "Bad", null));
            Assert.Equal(StatusCodes.Status400BadRequest, adminController.Response.StatusCode);
            Assert.Empty(store.ListPolicyRevisions());

            // Admin saves two revisions and previews diff between rev 1 and rev 2.
            var redir1 = Assert.IsType<LocalRedirectResult>(adminController.SavePolicy(PolicyAuthoringService.DefaultStarterBundleJson, "Rev 1 baseline", null));
            Assert.Equal("~/manage/policies?revision=1", redir1.Url);

            var redir2 = Assert.IsType<LocalRedirectResult>(adminController.SavePolicy(RichBundleJson, "Rev 2 rich bundle", 1));
            Assert.Equal("~/manage/policies?revision=2", redir2.Url);

            var policiesView = Assert.IsType<ViewResult>(auditorController.Policies(revision: 2, compareTo: 1));
            var editor = Assert.IsType<PolicyEditorViewModel>(policiesView.Model);
            Assert.Equal(2UL, editor.SelectedRevision);
            Assert.Equal(1UL, editor.CompareToRevision);
            Assert.Contains("+ create table inet nergal_nat", editor.UnifiedDiff);

            var hostRedirect = Assert.IsType<LocalRedirectResult>(adminController.AddHost("gw1", "tls", "192.0.2.10:8443", null, null, new string('a', 64)));
            Assert.Equal("~/manage", hostRedirect.Url);
            Assert.Single(store.ListHosts());

            var auditView = Assert.IsType<ViewResult>(auditorController.Audit());
            var auditModel = Assert.IsType<AuditHistoryViewModel>(auditView.Model);
            Assert.Equal(3, auditModel.Entries.Count);
            Assert.Equal("host.register", auditModel.Entries[0].Action);
            Assert.Equal(adminActor, auditModel.Entries[0].ActorId);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static ManagementController CreateController(ControllerStateStore store, string actorId, string role)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Role, role),
            new Claim(ControllerActorIdentity.ActorClaimType, actorId),
        ],
        "test"));
        return new ManagementController(store)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal },
            },
        };
    }

    private static string CreateOwnerOnlyTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "ng-ui-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static void TryDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
