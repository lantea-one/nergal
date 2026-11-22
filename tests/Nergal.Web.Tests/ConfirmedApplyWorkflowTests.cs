using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Controller;
using Nergal.Core.Deployment;
using Nergal.Core.Identity;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Verifies two-phase confirmed-apply workflow transitions, scope guards, key permission checks, RBAC, and audit persistence.</summary>
[SupportedOSPlatform("linux")]
public sealed class ConfirmedApplyWorkflowTests
{
    private const string SampleDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string FilterOnlyBundleJson = """
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
                "chain": "input",
                "destinationPort": 443
              }
            ]
          }
        }
        """;

    private const string MultiTableBundleJson = """
        {
          "schemaVersion": 1,
          "filter": {
            "schemaVersion": 1,
            "inputDefaultVerdict": "drop",
            "rules": []
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
            "snatRules": []
          }
        }
        """;

    /// <summary>PrepareApply -> Confirm promotes host LastKnownRevision and records start/confirm audit trail.</summary>
    [Fact]
    public async Task Workflow_StartThenConfirmUpdatesRevisionAndAppendsAuditEntries()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminId = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var host = new ManagedHostRecord(
                Guid.Parse("bbbbbbbb-0000-0000-0000-000000000001"),
                "gw-primary",
                AgentTransportKind.Unix,
                "/run/nergal/control.sock",
                expectedServerUserId: 0);
            store.RegisterHost(host, adminId, NergalRoles.Administrator);

            var eval = PolicyAuthoringService.EvaluateDraft(FilterOnlyBundleJson);
            Assert.True(eval.IsValid);
            var rev = store.SavePolicyRevision(eval.CanonicalJson!, eval.CandidateDigest!, adminId, NergalRoles.Administrator, "Allow HTTPS");

            var dispatcher = new RecordingDispatcher((_, req) => req.Command switch
            {
                AgentControlCommand.Status => new AgentControlReply(AgentControlOutcome.Matched, revision: 2),
                AgentControlCommand.PrepareApply => new AgentControlReply(
                    AgentControlOutcome.AppliedPendingConfirmation,
                    revision: 1,
                    operationId: req.OperationId,
                    watchdogId: req.WatchdogId,
                    activePhase: ApplyPhase.AwaitingConfirmation,
                    remainingSeconds: req.ConfirmationTimeoutSeconds,
                    candidateDigest: eval.CandidateDigest),
                AgentControlCommand.Confirm => new AgentControlReply(
                    AgentControlOutcome.Confirmed,
                    revision: 2,
                    operationId: req.OperationId,
                    watchdogId: req.WatchdogId,
                    activePhase: ApplyPhase.Confirmed,
                    candidateDigest: eval.CandidateDigest),
                _ => throw new InvalidOperationException("Unexpected command"),
            });

            var workflow = new ApplyWorkflowService(store, dispatcher);
            var controller = CreateController(store, workflow, adminId, NergalRoles.Administrator);

            var startResult = Assert.IsType<LocalRedirectResult>(await controller.StartApply(host.Id.ToString("D"), rev.Revision, 25));
            Assert.Equal($"~/manage/apply?hostId={host.Id:D}&revision=1&notice=appliedPendingConfirmation", startResult.Url);

            var prepCall = Assert.Single(dispatcher.Sent);
            Assert.Equal(AgentControlCommand.PrepareApply, prepCall.Request.Command);
            Assert.Equal(25, prepCall.Request.ConfirmationTimeoutSeconds);
            Assert.NotNull(prepCall.Request.Policy);

            var opId = prepCall.Request.OperationId!.Value;
            var wdId = prepCall.Request.WatchdogId!.Value;

            var confirmResult = Assert.IsType<LocalRedirectResult>(
                await controller.ConfirmApply(host.Id.ToString("D"), opId.ToString("D"), wdId.ToString("D"), rev.Revision));
            Assert.Equal($"~/manage/apply?hostId={host.Id:D}&revision=1&notice=confirmed", confirmResult.Url);

            // Re-reading host status verifies updated LastKnownRevision persisted cleanly.
            var refreshedHost = store.GetHost(host.Id);
            Assert.NotNull(refreshedHost);
            Assert.Equal(2UL, refreshedHost!.LastKnownRevision);

            var entries = store.ListAuditEntries();
            Assert.Equal("apply.confirm", entries[0].Action);
            Assert.Equal("confirmed", entries[0].Outcome);
            Assert.Equal(2UL, entries[0].Revision);
            Assert.Equal("apply.start", entries[1].Action);
            Assert.Equal("pending_confirmation", entries[1].Outcome);
            Assert.Equal(1UL, entries[1].Revision);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Immediate rollback resets operation cleanly and records apply.rollback in audit_log.</summary>
    [Fact]
    public async Task Workflow_RollbackRecordsAuditAndPreservesBaseline()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminId = ControllerActorIdentity.FromFederatedAccount("https://idp.example", "admin-1");
            var host = new ManagedHostRecord(
                Guid.Parse("bbbbbbbb-0000-0000-0000-000000000002"),
                "gw-tls",
                AgentTransportKind.Tls,
                "192.0.2.10:8443",
                pinnedServerThumbprint: SampleDigest);
            store.RegisterHost(host, adminId, NergalRoles.Administrator);

            var eval = PolicyAuthoringService.EvaluateDraft(FilterOnlyBundleJson);
            var rev = store.SavePolicyRevision(eval.CanonicalJson!, eval.CandidateDigest!, adminId, NergalRoles.Administrator);

            var dispatcher = new RecordingDispatcher((_, req) => req.Command switch
            {
                AgentControlCommand.PrepareApply => new AgentControlReply(
                    AgentControlOutcome.AppliedPendingConfirmation,
                    revision: 3,
                    operationId: req.OperationId,
                    watchdogId: req.WatchdogId,
                    activePhase: ApplyPhase.AwaitingConfirmation,
                    remainingSeconds: 15),
                AgentControlCommand.Rollback => new AgentControlReply(
                    AgentControlOutcome.RolledBack,
                    revision: 3,
                    operationId: req.OperationId,
                    watchdogId: req.WatchdogId,
                    activePhase: ApplyPhase.RolledBack),
                _ => new AgentControlReply(AgentControlOutcome.Matched, revision: 3),
            });

            var workflow = new ApplyWorkflowService(store, dispatcher);
            var controller = CreateController(store, workflow, adminId, NergalRoles.Administrator);

            _ = Assert.IsType<LocalRedirectResult>(await controller.StartApply(host.Id.ToString("D"), rev.Revision, 15));
            var opId = dispatcher.Sent[0].Request.OperationId!.Value;
            var wdId = dispatcher.Sent[0].Request.WatchdogId!.Value;

            var rbResult = Assert.IsType<LocalRedirectResult>(
                await controller.RollbackApply(host.Id.ToString("D"), opId.ToString("D"), wdId.ToString("D"), null));
            Assert.Equal($"~/manage/apply?hostId={host.Id:D}&notice=rolledBack", rbResult.Url);

            Assert.Equal(3UL, store.GetHost(host.Id)!.LastKnownRevision);
            Assert.Equal("apply.rollback", store.ListAuditEntries()[0].Action);
            Assert.Equal("rolled_back", store.ListAuditEntries()[0].Outcome);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Multi-table bundles containing NAT/bridge sections dispatch over the control channel while Auditor mutation attempts fail closed with 403.</summary>
    [Fact]
    public async Task Workflow_DispatchesMultiTableBundleAndEnforcesAuditorRbac()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminId = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var auditorId = ControllerActorIdentity.FromLocalAccount(Guid.Parse("22222222-2222-2222-2222-222222222222"));

            var host = new ManagedHostRecord(
                Guid.Parse("bbbbbbbb-0000-0000-0000-000000000003"),
                "gw-scope",
                AgentTransportKind.Unix,
                "/run/nergal/control.sock",
                expectedServerUserId: 0);
            store.RegisterHost(host, adminId, NergalRoles.Administrator);

            var eval = PolicyAuthoringService.EvaluateDraft(MultiTableBundleJson);
            Assert.True(eval.IsValid);
            var rev = store.SavePolicyRevision(eval.CanonicalJson!, eval.CandidateDigest!, adminId, NergalRoles.Administrator);

            var dispatcher = new RecordingDispatcher((_, req) => req.Command switch
            {
                AgentControlCommand.Status => new AgentControlReply(AgentControlOutcome.Matched, revision: 1),
                AgentControlCommand.PrepareApply => new AgentControlReply(
                    AgentControlOutcome.AppliedPendingConfirmation,
                    revision: 1,
                    operationId: req.OperationId,
                    watchdogId: req.WatchdogId ?? Guid.NewGuid(),
                    activePhase: ApplyPhase.AwaitingConfirmation,
                    remainingSeconds: req.ConfirmationTimeoutSeconds),
                _ => new AgentControlReply(AgentControlOutcome.Unavailable, errorCode: "unexpected"),
            });
            var workflow = new ApplyWorkflowService(store, dispatcher);

            var auditorController = CreateController(store, workflow, auditorId, NergalRoles.Auditor);
            var readView = Assert.IsType<ViewResult>(await auditorController.Apply());
            var readModel = Assert.IsType<ConfirmedApplyViewModel>(readView.Model);
            Assert.False(readModel.CanMutate);

            var dummyId = Guid.NewGuid().ToString("D");
            Assert.IsType<ForbidResult>(await auditorController.StartApply(host.Id.ToString("D"), rev.Revision, 10));
            Assert.IsType<ForbidResult>(await auditorController.ConfirmApply(host.Id.ToString("D"), dummyId, dummyId, rev.Revision));
            Assert.IsType<ForbidResult>(await auditorController.RollbackApply(host.Id.ToString("D"), dummyId, dummyId, null));
            Assert.Single(dispatcher.Sent); // Only the Apply() read status query dispatched.

            var adminController = CreateController(store, workflow, adminId, NergalRoles.Administrator);
            var redirect = Assert.IsType<LocalRedirectResult>(await adminController.StartApply(host.Id.ToString("D"), rev.Revision, 10));
            Assert.Contains("notice=appliedPendingConfirmation", redirect.Url, StringComparison.Ordinal);
            Assert.Equal(2, dispatcher.Sent.Count);
            var prepareRequest = dispatcher.Sent[1].Request;
            Assert.Equal(AgentControlCommand.PrepareApply, prepareRequest.Command);
            Assert.NotNull(prepareRequest.Bundle);
            Assert.NotNull(prepareRequest.Bundle!.Nat);

            var latestAudit = store.ListAuditEntries()[0];
            Assert.Equal("apply.start", latestAudit.Action);
            Assert.Equal("pending_confirmation", latestAudit.Outcome);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Client mTLS key validation enforces 0600 permissions, and missing keys/unreachable endpoints fail closed as Unavailable.</summary>
    [Fact]
    public async Task Dispatcher_ValidatesClientKeyPermissionsAndDegradesFailClosed()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var certPath = Path.Combine(dir, "client.crt");
            var keyPath = Path.Combine(dir, "client.key");
            CreateSelfSignedClientCert(certPath, keyPath);

            // Half-configured client mTLS fails closed.
            var halfConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["TlsClientCertificatePath"] = certPath })
                .Build();
            Assert.Equal("tls.clientConfigInvalid", Assert.Throws<InvalidOperationException>(() =>
                ControllerTlsClientConfig.FromConfiguration(halfConfig)).Message);

            // Unsafe 0644 private key permissions must be rejected.
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            var unsafeConfig = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["TlsClientCertificatePath"] = certPath,
                    ["TlsClientKeyPath"] = keyPath,
                })
                .Build();
            Assert.Equal("tls.keyPermissions", Assert.Throws<InvalidOperationException>(() =>
                ControllerTlsClientConfig.FromConfiguration(unsafeConfig)).Message);

            // Missing client cert when dispatching TLS returns Unavailable without throwing raw secrets.
            var emptyDispatcher = new DefaultAgentControlDispatcher(new ControllerTlsClientConfig(null, null));
            var tlsHost = new ManagedHostRecord(
                Guid.NewGuid(),
                "unreachable-tls",
                AgentTransportKind.Tls,
                "127.0.0.1:1",
                pinnedServerThumbprint: SampleDigest);
            var missingCertReply = await emptyDispatcher.SendAsync(tlsHost, new AgentControlRequest(AgentControlCommand.Status), TestContext.Current.CancellationToken);
            Assert.Equal(AgentControlOutcome.Unavailable, missingCertReply.Outcome);
            Assert.Equal("tls.clientCertMissing", missingCertReply.ErrorCode);

            // Valid 0600 key passes startup validation, and unreachable endpoints degrade to transport error codes.
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var loaded = ControllerTlsClientConfig.FromConfiguration(unsafeConfig);
            Assert.True(loaded.HasClientCertificate);

            var dispatcher = new DefaultAgentControlDispatcher(loaded);
            var tlsUnreachable = await dispatcher.SendAsync(tlsHost, new AgentControlRequest(AgentControlCommand.Status), TestContext.Current.CancellationToken);
            Assert.Equal(AgentControlOutcome.Unavailable, tlsUnreachable.Outcome);
            Assert.Equal("transport.tlsUnavailable", tlsUnreachable.ErrorCode);

            var unixHost = new ManagedHostRecord(
                Guid.NewGuid(),
                "unreachable-unix",
                AgentTransportKind.Unix,
                Path.Combine(dir, "missing.sock"),
                expectedServerUserId: 0);
            var unixUnreachable = await dispatcher.SendAsync(unixHost, new AgentControlRequest(AgentControlCommand.Status), TestContext.Current.CancellationToken);
            Assert.Equal(AgentControlOutcome.Unavailable, unixUnreachable.Outcome);
            Assert.Equal("transport.localUnavailable", unixUnreachable.ErrorCode);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>Preview-only tables must be rejected before any privileged dispatch and recorded in the audit.</summary>
    [Fact]
    public async Task Workflow_DeniesExtendedScopeWithoutCallingAgent()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new(dir));
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());
            var host = new ManagedHostRecord(Guid.NewGuid(), "synthetic", AgentTransportKind.Unix, "/run/nergal/synthetic.sock", expectedServerUserId: 0);
            store.RegisterHost(host, actor, NergalRoles.Administrator);
            var bundle = new Nergal.Core.Policy.FirewallPolicyBundle(1,
                new(1, Nergal.Core.Policy.FilterVerdict.Drop, []), auxiliaryFilter: new(-5,
                    new(2, Nergal.Core.Policy.FilterVerdict.Accept, Nergal.Core.Policy.FilterVerdict.Accept, Nergal.Core.Policy.FilterVerdict.Accept, [])));
            var report = PolicyAuthoringService.EvaluateDraft(Nergal.Core.Policy.PolicyBundleJsonCodec.EncodeBundle(bundle));
            Assert.True(report.IsValid);
            var revision = store.SavePolicyRevision(report.CanonicalJson!, report.CandidateDigest!, actor, NergalRoles.Administrator, "Synthetic preview");
            var dispatcher = new RecordingDispatcher((_, _) => throw new InvalidOperationException("Must not contact agent"));
            var workflow = new ApplyWorkflowService(store, dispatcher);
            var result = await workflow.StartApplyAsync(host.Id, revision.Revision, 30, actor, NergalRoles.Administrator, TestContext.Current.CancellationToken);
            Assert.Equal("policy.previewOnlyScope", result.Reply!.ErrorCode);
            Assert.Empty(dispatcher.Sent);
            Assert.Contains(store.ListAuditEntries(), e => e.Action == "apply.start" && e.Outcome == "rejected" && e.DetailCode == "policy.previewOnlyScope");
        }
        finally { TryDelete(dir); }
    }

    private sealed class RecordingDispatcher(Func<ManagedHostRecord, AgentControlRequest, AgentControlReply> handler) : IAgentControlDispatcher
    {
        public List<(ManagedHostRecord Host, AgentControlRequest Request)> Sent { get; } = [];

        public Task<AgentControlReply> SendAsync(
            ManagedHostRecord host,
            AgentControlRequest request,
            CancellationToken cancellationToken = default)
        {
            Sent.Add((host, request));
            return Task.FromResult(handler(host, request));
        }
    }

    private static ManagementController CreateController(
        ControllerStateStore store,
        ApplyWorkflowService workflow,
        string actorId,
        string role)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Role, role),
            new Claim(ControllerActorIdentity.ActorClaimType, actorId),
        ],
        "test"));
        return new ManagementController(store, workflow)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal },
            },
        };
    }

    private static void CreateSelfSignedClientCert(string certPath, string keyPath)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=nergal-test-client", ecdsa, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllText(certPath, cert.ExportCertificatePem());
        File.WriteAllText(keyPath, ecdsa.ExportPkcs8PrivateKeyPem());
    }

    private static string CreateOwnerOnlyTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "ng-apply-" + Guid.NewGuid().ToString("N")[..12]);
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
