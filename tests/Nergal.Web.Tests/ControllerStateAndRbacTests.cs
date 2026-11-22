using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies controller SQLite persistence, append-only audit triggers, and Administrator/Auditor RBAC policies.</summary>
[SupportedOSPlatform("linux")]
public sealed class ControllerStateAndRbacTests
{
    private const string SampleDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>Hosts, monotonic policy revisions, and audit entries persist durably; direct SQL tampering is blocked by triggers.</summary>
    [Fact]
    public void Store_EnforcesFileModesMonotonicRevisionsAndAppendOnlyAuditTriggers()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        var adminId = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
        var oidcActor = ControllerActorIdentity.FromFederatedAccount("https://idp.example", "auditor-1");
        var clock = new FixedClock(new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero));

        try
        {
            var options = new ControllerStateOptions(dir);
            var store = ControllerStateStore.Initialize(options, clock);

            // Repeat initialization must fail closed.
            Assert.Equal("controller.exists", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Initialize(options)).Code);

            var unixHost = new ManagedHostRecord(
                Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"),
                "local-agent",
                AgentTransportKind.Unix,
                "/run/nergal/control.sock",
                expectedServerUserId: 100,
                socketGroupId: 200);

            var tlsHost = new ManagedHostRecord(
                Guid.Parse("aaaaaaaa-0000-0000-0000-000000000002"),
                "edge-gw.example",
                AgentTransportKind.Tls,
                "192.0.2.10:8443",
                pinnedServerThumbprint: SampleDigest);

            store.RegisterHost(unixHost, adminId, NergalRoles.Administrator);
            store.RegisterHost(tlsHost, adminId, NergalRoles.Administrator);

            // Duplicate host ID/name fails closed; Auditors cannot register hosts or save revisions.
            Assert.Equal("host.duplicate", Assert.Throws<ControllerStateException>(() => store.RegisterHost(unixHost, adminId, NergalRoles.Administrator)).Code);
            Assert.Equal("rbac.denied", Assert.Throws<ControllerStateException>(() =>
                store.RegisterHost(
                    new ManagedHostRecord(Guid.NewGuid(), "blocked", AgentTransportKind.Tls, "192.0.2.11:8443", pinnedServerThumbprint: SampleDigest),
                    oidcActor,
                    NergalRoles.Auditor)).Code);

            var hosts = store.ListHosts();
            Assert.Equal(2, hosts.Count);
            Assert.Equal(unixHost.Id, store.GetHost(unixHost.Id)?.Id);

            store.UpdateHostLastRevision(tlsHost.Id, 4);
            Assert.Equal(4UL, store.GetHost(tlsHost.Id)?.LastKnownRevision);

            var rev1 = store.SavePolicyRevision("{\"schemaVersion\":1}", SampleDigest, adminId, NergalRoles.Administrator, "Initial baseline");
            var rev2 = store.SavePolicyRevision("{\"schemaVersion\":2}", SampleDigest, adminId, NergalRoles.Administrator, "Stateful update");
            Assert.Equal(1UL, rev1.Revision);
            Assert.Equal(2UL, rev2.Revision);
            Assert.Equal(2, store.ListPolicyRevisions().Count);
            Assert.Equal("Initial baseline", store.GetPolicyRevision(1)?.Summary);

            Assert.Equal("rbac.denied", Assert.Throws<ControllerStateException>(() =>
                store.SavePolicyRevision("{}", SampleDigest, oidcActor, NergalRoles.Auditor)).Code);

            _ = store.AppendAudit(oidcActor, NergalRoles.Auditor, "audit.view", "controller", null, "succeeded");
            var entries = store.ListAuditEntries();
            Assert.Equal(5, entries.Count);
            Assert.Equal("audit.view", entries[0].Action);
            Assert.Equal(oidcActor, entries[0].ActorId);
            Assert.Equal(NergalRoles.Auditor, entries[0].ActorRole);

            // Reopening succeeds and validates triggers/schema.
            var reopened = ControllerStateStore.Open(options, clock);
            Assert.Equal(5, reopened.ListAuditEntries().Count);

            // Direct SQLite UPDATE/DELETE against audit_log fails via triggers.
            var dbPath = Path.Combine(dir, "controller.db");
            using (var raw = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Pooling = false }.ToString()))
            {
                raw.Open();
                using var updateCmd = raw.CreateCommand();
                updateCmd.CommandText = "UPDATE audit_log SET outcome = 'forged' WHERE sequence = 1";
                var updEx = Assert.Throws<SqliteException>(() => updateCmd.ExecuteNonQuery());
                Assert.Contains("append-only", updEx.Message, StringComparison.OrdinalIgnoreCase);

                using var deleteCmd = raw.CreateCommand();
                deleteCmd.CommandText = "DELETE FROM audit_log WHERE sequence = 1";
                var delEx = Assert.Throws<SqliteException>(() => deleteCmd.ExecuteNonQuery());
                Assert.Contains("append-only", delEx.Message, StringComparison.OrdinalIgnoreCase);
            }

            Assert.True(store.DeleteHost(unixHost.Id, adminId, NergalRoles.Administrator));
            Assert.False(store.DeleteHost(unixHost.Id, adminId, NergalRoles.Administrator));
            Assert.Null(store.GetHost(unixHost.Id));

            // Unsafe directory permissions must fail closed.
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead);
            Assert.Equal("path.permissions", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(options)).Code);
        }
        finally
        {
            TryRestoreAndDelete(dir);
        }
    }

    /// <summary>Dropped audit immutability triggers fail schema validation cleanly rather than silently repairing.</summary>
    [Fact]
    public void Store_RejectsTamperedAuditTriggers()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var options = new ControllerStateOptions(dir);
            _ = ControllerStateStore.Initialize(options);
            var dbPath = Path.Combine(dir, "controller.db");
            using (var raw = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Pooling = false }.ToString()))
            {
                raw.Open();
                using var dropCmd = raw.CreateCommand();
                dropCmd.CommandText = "DROP TRIGGER audit_no_delete;";
                dropCmd.ExecuteNonQuery();
            }

            Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(options)).Code);
        }
        finally
        {
            TryRestoreAndDelete(dir);
        }
    }

    /// <summary>ManagedHostRecord rejects empty/mismatched transport fields fail-closed.</summary>
    [Fact]
    public void HostRecord_EnforcesTransportSpecificInvariants()
    {
        var id = Guid.NewGuid();
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(Guid.Empty, "h1", AgentTransportKind.Tls, "192.0.2.1:8443", pinnedServerThumbprint: SampleDigest));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "bad host name", AgentTransportKind.Tls, "192.0.2.1:8443", pinnedServerThumbprint: SampleDigest));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Unix, "relative.sock", expectedServerUserId: 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Unix, "/run/agent.sock", expectedServerUserId: null));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Unix, "/run/agent.sock", expectedServerUserId: 1, pinnedServerThumbprint: SampleDigest));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Tls, "badendpoint", pinnedServerThumbprint: SampleDigest));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Tls, "192.0.2.1:8443", expectedServerUserId: 1, pinnedServerThumbprint: SampleDigest));
        Assert.Throws<ArgumentException>(() => new ManagedHostRecord(id, "h1", AgentTransportKind.Tls, "192.0.2.1:8443", pinnedServerThumbprint: "short"));
    }

    /// <summary>Authorization policies allow Administrators to mutate, restrict Auditors to read-only, and reject unrecognized roles.</summary>
    [Fact]
    public async Task RbacPolicies_RestrictMutatingPolicyToAdministrator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication();
        ControllerAuthorization.Configure(services, federated: true);
        using var provider = services.BuildServiceProvider();
        var auth = provider.GetRequiredService<IAuthorizationService>();

        var admin = MakePrincipal(ControllerActorIdentity.FromLocalAccount(Guid.NewGuid()), NergalRoles.Administrator, FederatedLogin.Session);
        var auditor = MakePrincipal(ControllerActorIdentity.FromFederatedAccount("https://idp.example", "aud-1"), NergalRoles.Auditor, FederatedLogin.Session);
        var unknown = MakePrincipal(ControllerActorIdentity.FromFederatedAccount("https://idp.example", "other-1"), "nergal:unknown", FederatedLogin.Session);

        Assert.True((await auth.AuthorizeAsync(admin, null, ControllerAuthorizationPolicies.Administrator)).Succeeded);
        Assert.True((await auth.AuthorizeAsync(admin, null, ControllerAuthorizationPolicies.Reader)).Succeeded);
        Assert.False((await auth.AuthorizeAsync(auditor, null, ControllerAuthorizationPolicies.Administrator)).Succeeded);
        Assert.True((await auth.AuthorizeAsync(auditor, null, ControllerAuthorizationPolicies.Reader)).Succeeded);
        Assert.False((await auth.AuthorizeAsync(unknown, null, ControllerAuthorizationPolicies.Administrator)).Succeeded);
        Assert.False((await auth.AuthorizeAsync(unknown, null, ControllerAuthorizationPolicies.Reader)).Succeeded);
    }

    /// <summary>Audit read endpoint exposes canonical actor attribution and forbids malformed/unattributed principals.</summary>
    [Fact]
    public async Task AuditEndpoint_RejectsMalformedActorIdentity()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var ctx = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Role, NergalRoles.Auditor)], "test")),
            };
            using var provider = new ServiceCollection().AddLogging().BuildServiceProvider();
            ctx.RequestServices = provider;
            await ControllerStateHost.ListAudit(ctx, store).ExecuteAsync(ctx);
            Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
        }
        finally
        {
            TryRestoreAndDelete(dir);
        }
    }

    /// <summary>Local account provisioning supports explicit Auditor role assignment and claims generation.</summary>
    [Fact]
    public async Task LocalAccount_AuditorRoleFlowsToIssuedClaims()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var options = new LocalAccountOptions(dir);
            await LocalAccountDatabase.InitializeAsync(options);
            using var services = new ServiceCollection()
                .AddLogging()
                .AddLocalAdministratorAccounts(options)
                .BuildServiceProvider();
            using var scope = services.CreateScope();
            var accounts = scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>();
            var invalid = await accounts.ProvisionAsync("auditor", "long enough password 123", "invalid-role");
            Assert.False(invalid.Succeeded);

            var ok = await accounts.ProvisionAsync("auditor", "long enough password 123", NergalRoles.Auditor);
            Assert.True(ok.Succeeded);

            var factory = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.IUserClaimsPrincipalFactory<LocalAdministrator>>();
            var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<LocalAdministrator>>();
            var account = await users.FindByNameAsync("auditor");
            Assert.NotNull(account);
            var principal = await factory.CreateAsync(account!);
            Assert.True(ControllerAuthorization.TryResolveActor(principal, out var actorId, out var role));
            Assert.Equal(NergalRoles.Auditor, role);
            Assert.Equal(ControllerActorIdentity.FromLocalAccount(Guid.Parse(account!.Id)), actorId);
        }
        finally
        {
            TryRestoreAndDelete(dir);
        }
    }

    private static ClaimsPrincipal MakePrincipal(string actorId, string role, string authType) =>
        new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Role, role),
            new Claim(ControllerActorIdentity.ActorClaimType, actorId),
        ],
        authType));

    private static string CreateOwnerOnlyTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "ng-cs-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static void TryRestoreAndDelete(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
