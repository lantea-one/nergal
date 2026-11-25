using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Nergal.ControllerState;
using Nergal.Core;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
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
    public async Task Controller_EnforcesRbacPersistsRevisionsAndRendersDiffs()
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
            var dashView = Assert.IsType<ViewResult>(await auditorController.Index());
            var dashModel = Assert.IsType<FleetDashboardViewModel>(dashView.Model);
            Assert.False(dashModel.CanMutate);
            var hostView = Assert.IsType<ViewResult>(await auditorController.Hosts());
            Assert.False(Assert.IsType<FleetDashboardViewModel>(hostView.Model).CanMutate);
            Assert.IsType<BadRequestResult>(adminController.Policies(section: "unknown"));
            var natView = Assert.IsType<ViewResult>(adminController.Policies(section: "nat"));
            Assert.Equal("nat", Assert.IsType<PolicyEditorViewModel>(natView.Model).InitialSection);

            var previewView = Assert.IsType<ViewResult>(auditorController.PreviewPolicy(RichBundleJson, "Preview note", null));
            var previewModel = Assert.IsType<PolicyEditorViewModel>(previewView.Model);
            Assert.NotNull(previewModel.CandidateText);
            Assert.False(previewModel.CanMutate);

            // Auditor cannot persist hosts or policy revisions even if invoked directly.
            Assert.IsType<ForbidResult>(await auditorController.AddHost("gw1", "tls", "192.0.2.10:8443", null, null, new string('a', 64)));
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

            var hostRedirect = Assert.IsType<LocalRedirectResult>(await adminController.AddHost("gw1", "tls", "192.0.2.10:8443", null, null, new string('a', 64)));
            Assert.Equal("~/manage/hosts", hostRedirect.Url);
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

    /// <summary>Visual rule builder appends inline address/port sets and IPv4 ICMP types, reorders/removes rules, and denies Auditors.</summary>
    [Fact]
    public void VisualRuleBuilder_AppendsInlineSetsReordersAndEnforcesAuditorForbid()
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
            var auditorActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("22222222-2222-2222-2222-222222222222"));

            var adminController = CreateController(store, adminActor, NergalRoles.Administrator);
            var auditorController = CreateController(store, auditorActor, NergalRoles.Auditor);

            // Auditor is denied all visual rule builder mutations.
            Assert.IsType<ForbidResult>(auditorController.AddFilterRule(PolicyAuthoringService.DefaultStarterBundleJson, null, null, "input", "ipv4", "tcp", "accept", "192.0.2.0/24", null, "443", null, null, null, null));
            Assert.IsType<ForbidResult>(auditorController.MoveFilterRule(PolicyAuthoringService.DefaultStarterBundleJson, null, null, 0, 1));
            Assert.IsType<ForbidResult>(auditorController.RemoveFilterRule(PolicyAuthoringService.DefaultStarterBundleJson, null, null, 0));

            // Administrator appends an inline CIDR + port set rule.
            var added1 = Assert.IsType<ViewResult>(adminController.AddFilterRule(
                PolicyAuthoringService.DefaultStarterBundleJson,
                "web-sets",
                null,
                "input",
                "ipv4",
                "tcp",
                "accept",
                "198.51.100.0/24, 192.0.2.0/24",
                null,
                "443, 80",
                null,
                null,
                null,
                "new"));
            var model1 = Assert.IsType<PolicyEditorViewModel>(added1.Model);
            Assert.Empty(model1.Diagnostics);
            Assert.NotNull(model1.Bundle);
            Assert.Equal(2, model1.Bundle!.Filter.Rules.Count);
            Assert.Contains("ip saddr { 192.0.2.0/24, 198.51.100.0/24 }", model1.CandidateText, StringComparison.Ordinal);
            Assert.Contains("tcp dport { 80, 443 }", model1.CandidateText, StringComparison.Ordinal);

            // Append IPv4 ICMP parameter-problem rule.
            var added2 = Assert.IsType<ViewResult>(adminController.AddFilterRule(
                model1.BundleJson,
                "web-sets",
                null,
                "input",
                "ipv4",
                "icmp",
                "accept",
                null,
                null,
                null,
                "parameter-problem",
                null,
                null,
                null));
            var model2 = Assert.IsType<PolicyEditorViewModel>(added2.Model);
            Assert.Empty(model2.Diagnostics);
            Assert.Equal(3, model2.Bundle!.Filter.Rules.Count);
            Assert.Contains("icmp type parameter-problem accept", model2.CandidateText, StringComparison.Ordinal);

            // Move the ICMP rule up by one slot.
            var moved = Assert.IsType<ViewResult>(adminController.MoveFilterRule(model2.BundleJson, "web-sets", null, 2, -1));
            var movedModel = Assert.IsType<PolicyEditorViewModel>(moved.Model);
            Assert.Equal(FilterProtocol.Icmp, movedModel.Bundle!.Filter.Rules[1]!.Protocol);

            // Remove the first rule.
            var removed = Assert.IsType<ViewResult>(adminController.RemoveFilterRule(movedModel.BundleJson, "web-sets", null, 0));
            var removedModel = Assert.IsType<PolicyEditorViewModel>(removed.Model);
            Assert.Equal(2, removedModel.Bundle!.Filter.Rules.Count);

            // Invalid port set (duplicate) returns 400 with structured diagnostic.
            var invalid = Assert.IsType<ViewResult>(adminController.AddFilterRule(
                removedModel.BundleJson,
                "web-sets",
                null,
                "input",
                "ipv4",
                "tcp",
                "accept",
                null,
                null,
                "443, 443",
                null,
                null,
                null,
                null));
            Assert.Equal(StatusCodes.Status400BadRequest, adminController.Response.StatusCode);
            var invalidModel = Assert.IsType<PolicyEditorViewModel>(invalid.Model);
            Assert.Contains(invalidModel.Diagnostics, d => d.Code == "set.duplicate");
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Both accepted and rejected draft posts bound the displayed note without creating a revision or audit entry.</summary>
    [Theory]
    [InlineData("443", StatusCodes.Status200OK)]
    [InlineData("443, 443", StatusCodes.Status400BadRequest)]
    public void VisualRuleBuilder_BoundsDraftNoteWithoutPersisting(string ports, int expectedStatus)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var admin = CreateController(store, actor, NergalRoles.Administrator);
            var retained = "<draft> " + new string('a', 247);
            var submitted = retained + "🔒 extra";

            var result = Assert.IsType<ViewResult>(admin.AddFilterRule(
                PolicyAuthoringService.DefaultStarterBundleJson, submitted, null,
                "input", "ipv4", "tcp", "accept", "192.0.2.0/24", null, ports, null, null, null, null));
            Assert.Equal(expectedStatus, admin.Response.StatusCode);
            Assert.Equal(retained, Assert.IsType<PolicyEditorViewModel>(result.Model).Summary);

            var invalidSave = Assert.IsType<ViewResult>(admin.SavePolicy(PolicyAuthoringService.DefaultStarterBundleJson, submitted, null));
            Assert.Equal(StatusCodes.Status400BadRequest, admin.Response.StatusCode);
            Assert.Contains(Assert.IsType<PolicyEditorViewModel>(invalidSave.Model).Diagnostics, d => d.Code == "summary.bounds");
            Assert.Empty(store.ListPolicyRevisions());
            Assert.Empty(store.ListAuditEntries(20));
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Structured visual forms edit Filter defaults, rate limits, ct status dnat, NAT DNAT/SNAT, and L2 Bridge rules while denying Auditors.</summary>
    [Fact]
    public void VisualBuilder_SupportsFilterDefaultsRateLimitNatBridgeAndDeniesAuditors()
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
            var auditorActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("22222222-2222-2222-2222-222222222222"));

            var admin = CreateController(store, adminActor, NergalRoles.Administrator);
            var auditor = CreateController(store, auditorActor, NergalRoles.Auditor);
            var seed = PolicyAuthoringService.DefaultStarterBundleJson;

            // Auditor denied on every structured builder endpoint.
            Assert.IsType<ForbidResult>(auditor.UpdateFilterDefaults(seed, null, null, 2, "drop", "drop", "accept"));
            Assert.IsType<ForbidResult>(auditor.AddDnatRule(seed, null, null, "ipv4", "tcp", "192.0.2.1/32", "198.51.100.2", 443, 8443, "wan0", null));
            Assert.IsType<ForbidResult>(auditor.RemoveDnatRule(seed, null, null, 0));
            Assert.IsType<ForbidResult>(auditor.AddSnatRule(seed, null, null, "ipv4", "192.0.2.0/24", "198.51.100.1", null, "wan0"));
            Assert.IsType<ForbidResult>(auditor.RemoveSnatRule(seed, null, null, 0));
            Assert.IsType<ForbidResult>(auditor.ClearNat(seed, null, null));
            Assert.IsType<ForbidResult>(auditor.UpdateBridgeDefaults(seed, null, null, "drop"));
            Assert.IsType<ForbidResult>(auditor.AddBridgeRule(seed, null, null, "ipv4", "accept", "br0", null));
            Assert.IsType<ForbidResult>(auditor.RemoveBridgeRule(seed, null, null, 0));
            Assert.IsType<ForbidResult>(auditor.ClearBridge(seed, null, null));

            // 1. Update filter defaults.
            var m1 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.UpdateFilterDefaults(seed, "full-ui", null, 2, "drop", "drop", "drop")).Model);
            Assert.Empty(m1.Diagnostics);
            Assert.Equal(FilterVerdict.Drop, m1.Bundle!.Filter.OutputDefaultVerdict);

            // 2. Add filter rule with ct status dnat + per-source rate limit.
            var m2 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddFilterRule(m1.BundleJson, "full-ui", null, "forward", "ipv4", "tcp", "accept",
                    null, "198.51.100.2/32", "8443", null, "wan0", "lan0", "new, established",
                    matchOriginalDestinationDnat: true, rateLimitPackets: 25, rateLimitUnit: "second", rateLimitBurst: 10, rateLimitTimeout: 120)).Model);
            Assert.Empty(m2.Diagnostics);
            Assert.Contains("ct status dnat", m2.CandidateText, StringComparison.Ordinal);
            Assert.Contains("limit rate 25/second burst 10 packets", m2.CandidateText, StringComparison.Ordinal);

            // 3. Add DNAT & SNAT rules, then remove DNAT, then clear NAT.
            var m3 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddDnatRule(m2.BundleJson, "full-ui", null, "ipv4", "tcp", "192.0.2.1/32", "198.51.100.2", 443, 8443, "wan0", null)).Model);
            Assert.Empty(m3.Diagnostics);
            Assert.Single(m3.Bundle!.Nat!.DnatRules);

            var m4 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddSnatRule(m3.BundleJson, "full-ui", null, "ipv4", "198.51.100.0/24", "192.0.2.1", null, "wan0")).Model);
            Assert.Empty(m4.Diagnostics);
            Assert.Single(m4.Bundle!.Nat!.SnatRules);
            Assert.Contains("create table inet nergal_nat", m4.CandidateText, StringComparison.Ordinal);

            var m5 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.RemoveDnatRule(m4.BundleJson, "full-ui", null, 0)).Model);
            Assert.Empty(m5.Bundle!.Nat!.DnatRules);
            Assert.Single(m5.Bundle.Nat.SnatRules);

            var m6 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.ClearNat(m5.BundleJson, "full-ui", null)).Model);
            Assert.Null(m6.Bundle!.Nat);

            // 4. Enable bridge, add bridge rule, remove bridge rule, clear bridge.
            var m7 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.UpdateBridgeDefaults(m6.BundleJson, "full-ui", null, "drop")).Model);
            Assert.NotNull(m7.Bundle!.Bridge);
            Assert.Equal(FilterVerdict.Drop, m7.Bundle.Bridge!.DefaultVerdict);

            var m8 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddBridgeRule(m7.BundleJson, "full-ui", null, "arp", "accept", "br0", null)).Model);
            Assert.Single(m8.Bundle!.Bridge!.Rules);
            Assert.Contains("create table bridge nergal_bridge", m8.CandidateText, StringComparison.Ordinal);

            var m9 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.RemoveBridgeRule(m8.BundleJson, "full-ui", null, 0)).Model);
            Assert.Empty(m9.Bundle!.Bridge!.Rules);

            var m10 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.ClearBridge(m9.BundleJson, "full-ui", null)).Model);
            Assert.Null(m10.Bundle!.Bridge);
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
