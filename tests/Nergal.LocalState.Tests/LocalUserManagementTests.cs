using System.Runtime.Versioning;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.LocalState.Tests;

/// <summary>Real protected SQLite and Identity checks for authority, last-administrator races, audit atomicity and profile isolation.</summary>
[SupportedOSPlatform("linux")]
public sealed class LocalUserManagementTests
{
    private const string Password = "synthetic user fixture password 0001";

    /// <summary>A missing role is corrupt state, never an implicit Administrator grant.</summary>
    [Fact]
    public async Task MissingRole_FailsClosedWithoutGrantingBootstrapAuthority()
    {
        await using var f = await Fixture.Create();
        f.Sql("DELETE FROM AspNetUserClaims");
        Assert.Equal("account.unsupportedState", (await Assert.ThrowsAsync<AccountStoreException>(() =>
            f.Run(a => a.VerifyAsync("fixture-admin", Password)))).Code);
        Assert.Equal(1, f.Count("AspNetUsers"));
        Assert.Equal(1, f.Count("IdentityAudit"));
    }

    /// <summary>Profiles cannot mint authority; Auditor metadata is isolated and stale submissions preserve durable state.</summary>
    [Fact]
    public async Task Profiles_ArePersonalVersionedMetadata_NotAuthority()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        Assert.True((await f.Run(a => a.CreateUserAsync(admin, "fixture-auditor", Password, NergalRoles.Auditor))).Succeeded);
        var auditor = await f.SignIn("fixture-auditor");
        var count = f.Count("IdentityAudit");
        var profile = await f.Run(a => a.ReadProfileAsync(auditor));
        Assert.Equal(0, profile.Version);
        Assert.Equal(count, f.Count("IdentityAudit"));
        Assert.True((await f.Run(a => a.SaveProfileAsync(auditor, 0, new ProfileMetadata("Administrator \U0001f981")))).Succeeded);
        var saved = await f.Run(a => a.ReadProfileAsync(auditor));
        Assert.Equal("Administrator \U0001f981", saved.DisplayName);
        Assert.Equal(NergalRoles.Auditor, saved.Role);
        Assert.Equal(TimeSpan.Zero, saved.UpdatedUtc!.Value.Offset);
        Assert.Equal(["profile.stale"], (await f.Run(a => a.SaveProfileAsync(auditor, 0, new ProfileMetadata("lost edit")))).ErrorCodes);
        await Denied(() => f.Run(a => a.ListUsersAsync(auditor)));
        await Denied(() => f.Run(a => a.CreateUserAsync(auditor, "escalation", Password, NergalRoles.Administrator)));
        Assert.Empty((await f.Run(a => a.ReadProfileAsync(admin))).DisplayName);
        Assert.Equal(saved, await f.Run(a => a.ReadProfileAsync(auditor)));
        Assert.Equal(count + 1, f.Count("IdentityAudit"));
        Assert.Equal(["profile.metadata"], (await f.Run(a => a.SaveProfileAsync(auditor, saved.Version, new ProfileMetadata("hidden\ncontrol")))).ErrorCodes);
    }

    /// <summary>Independent signed issuer/subject identities never merge profiles based on an identical name or email.</summary>
    [Fact]
    public async Task FederatedProfiles_KeepExactIssuerSubjectBoundary()
    {
        await using var f = await Fixture.Create();
        var first = External("https://issuer-one.example", "subject");
        var second = External("https://issuer-two.example", "subject");
        Assert.True((await f.Run(a => a.SaveProfileAsync(first, 0, new ProfileMetadata("Shared display name")))).Succeeded);
        Assert.Empty((await f.Run(a => a.ReadProfileAsync(second))).DisplayName);
        Assert.Null((await f.Run(a => a.ReadProfileAsync(first))).LocalAccountId);
        Assert.Equal(["account.externalCredential"], (await f.Run(a => a.ChangeOwnPasswordAsync(first, 1, Password, Password))).ErrorCodes);
    }

    /// <summary>Concurrent self-demotions serialize; the second cannot remove the last enabled local Administrator.</summary>
    [Fact]
    public async Task LastAdministrator_ConcurrentDemotionsLeaveOneEnabledAdministrator()
    {
        await using var f = await Fixture.Create();
        var first = await f.SignIn("fixture-admin");
        Assert.True((await f.Run(a => a.CreateUserAsync(first, "fixture-second", Password, NergalRoles.Administrator))).Succeeded);
        var second = await f.SignIn("fixture-second");
        var all = await f.Run(a => a.ListUsersAsync(first));
        var principals = new[] { first, second };
        var results = await Task.WhenAll(principals.Select(p => Task.Run(() => f.Run(a => a.UpdateUserAsync(p,
            Guid.Parse(p.FindFirstValue(ClaimTypes.NameIdentifier)!), 1, NergalRoles.Auditor, true)))));
        Assert.Single(results, r => r.Succeeded);
        Assert.Equal(["account.lastAdministrator"], Assert.Single(results, r => !r.Succeeded).ErrorCodes);
        var remaining = principals[Array.FindIndex(results, r => !r.Succeeded)];
        var after = await f.Run(a => a.ListUsersAsync(remaining));
        var last = Assert.Single(after, u => u.Enabled && u.Role == NergalRoles.Administrator);
        Assert.Equal(["account.lastAdministrator"], (await f.Run(a => a.UpdateUserAsync(remaining, last.Id, last.Version,
            NergalRoles.Administrator, false))).ErrorCodes);
        Assert.Equal(2, all.Count);
    }

    /// <summary>A demoted or disabled actor's old principal cannot create accounts, even if an earlier request passed web authorization.</summary>
    [Fact]
    public async Task AccessChanges_RevokeOldAuthorityAndDenyDisabledLogin()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        Assert.True((await f.Run(a => a.CreateUserAsync(admin, "fixture-second", Password, NergalRoles.Administrator))).Succeeded);
        var second = await f.SignIn("fixture-second");
        var target = Assert.Single(await f.Run(a => a.ListUsersAsync(admin)), u => u.UserName == "fixture-second");
        Assert.True((await f.Run(a => a.UpdateUserAsync(admin, target.Id, 1, NergalRoles.Auditor, true))).Succeeded);
        await Denied(() => f.Run(a => a.CreateUserAsync(second, "forbidden", Password, NergalRoles.Administrator)));
        Assert.Equal(["account.stale"], (await f.Run(a => a.UpdateUserAsync(admin, target.Id, 1, NergalRoles.Administrator, true))).ErrorCodes);
        var fresh = await f.SignIn("fixture-second");
        Assert.Equal(NergalRoles.Auditor, fresh.FindFirstValue(ClaimTypes.Role));
        Assert.True((await f.Run(a => a.UpdateUserAsync(admin, target.Id, 2, NergalRoles.Auditor, false))).Succeeded);
        Assert.False((await f.Run(a => a.VerifyAsync("fixture-second", Password))).Succeeded);
        await Denied(() => f.Run(a => a.ReadProfileAsync(fresh)));
        Assert.True((await f.Run(a => a.UpdateUserAsync(admin, target.Id, 3, NergalRoles.Auditor, true))).Succeeded);
        Assert.True((await f.Run(a => a.VerifyAsync("fixture-second", Password))).Succeeded);
    }

    /// <summary>A failed audit insert rolls back stamp/state; audit events cannot be updated or deleted.</summary>
    [Fact]
    public async Task RevocationAndAudit_AreAtomicAndAppendOnly()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        Assert.True((await f.Run(a => a.CreateUserAsync(admin, "fixture-auditor", Password, NergalRoles.Auditor))).Succeeded);
        var auditor = await f.SignIn("fixture-auditor");
        var target = Assert.Single(await f.Run(a => a.ListUsersAsync(admin)), u => u.UserName == "fixture-auditor");
        var count = f.Count("IdentityAudit");
        f.Sql("CREATE TRIGGER fixture_audit_denial BEFORE INSERT ON IdentityAudit WHEN NEW.Action='account.sessionsRevoked' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END");
        Assert.Equal("account.databaseError", (await Assert.ThrowsAsync<AccountStoreException>(() =>
            f.Run(a => a.RevokeUserAsync(admin, target.Id, 1)))).Code);
        Assert.Equal(count, f.Count("IdentityAudit"));
        Assert.NotNull(await f.Run(a => a.ReadProfileAsync(auditor)));
        f.Sql("DROP TRIGGER fixture_audit_denial");
        Assert.True((await f.Run(a => a.RevokeUserAsync(admin, target.Id, 1))).Succeeded);
        await Denied(() => f.Run(a => a.ReadProfileAsync(auditor)));
        Assert.Throws<SqliteException>(() => f.Sql("DELETE FROM IdentityAudit"));
        Assert.Throws<SqliteException>(() => f.Sql("UPDATE IdentityAudit SET Action='rewritten'"));
        Assert.Equal(count + 1, f.Count("IdentityAudit"));
        f.Sql("DROP TRIGGER identity_audit_no_delete");
        Assert.Equal("account.schemaOrIntegrity", (await Assert.ThrowsAsync<AccountStoreException>(() =>
            f.Run(a => a.ReadIdentityAuditAsync(admin)))).Code);
    }

    /// <summary>Bad current passwords persist failure accounting; a correct password change invalidates every old principal.</summary>
    [Fact]
    public async Task OwnPassword_VerifiesCurrentCredentialAndRevokesExistingSessions()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        Assert.Equal(["account.credentialsDenied"], (await f.Run(a => a.ChangeOwnPasswordAsync(admin, 1, "synthetic wrong current password", Password))).ErrorCodes);
        Assert.Equal(1L, f.Scalar("SELECT AccessFailedCount FROM AspNetUsers"));
        const string replacement = "synthetic replacement password 0002";
        Assert.True((await f.Run(a => a.ChangeOwnPasswordAsync(admin, 1, Password, replacement))).Succeeded);
        await Denied(() => f.Run(a => a.ReadProfileAsync(admin)));
        Assert.False((await f.Run(a => a.VerifyAsync("fixture-admin", Password))).Succeeded);
        Assert.True((await f.Run(a => a.VerifyAsync("fixture-admin", replacement))).Succeeded);
        Assert.Equal(2L, f.Scalar("SELECT Version FROM LocalAccountState"));
    }

    /// <summary>Observed defaults stay separate from local overrides, and old mapping versions become immediately ineligible.</summary>
    [Fact]
    public async Task ProviderDefaults_AreExactIdentityVersionBoundAndPreserveLocalOverrides()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var mapping = new OidcProfileMapping("https://issuer-one.example", 0, true, "name", "given_name", "family_name", "email", null);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping))).Succeeded);
        var actor = External(mapping.Issuer, "subject");
        using var claims = JsonDocument.Parse("""{"iss":"https://issuer-one.example","sub":"subject","name":"Provider","given_name":"Given","family_name":"Family","email":"person@example.test"}""");
        Assert.True((await f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, claims.RootElement))).Succeeded);
        var read = await f.Run(a => a.ReadProfileAsync(actor));
        Assert.Equal(new ProfileMetadata("Provider", "Given", "Family", "person@example.test"), read.Effective);
        Assert.Empty(read.DisplayName);
        Assert.Equal(1, read.Provider!.MappingVersion);
        Assert.Equal(TimeSpan.Zero, read.Provider.ObservedUtc.Offset);
        Assert.True((await f.Run(a => a.SaveProfileAsync(actor, 0, new ProfileMetadata("Local", FamilyName: "Local family")))).Succeeded);
        var local = await f.Run(a => a.ReadProfileAsync(actor));
        Assert.Equal(new ProfileMetadata("Local", "Given", "Local family", "person@example.test"), local.Effective);
        Assert.Null((await f.Run(a => a.ReadProfileAsync(External(mapping.Issuer, "other-subject")))).Provider);
        Assert.Null((await f.Run(a => a.ReadProfileAsync(External("https://issuer-two.example", "subject")))).Provider);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping with { Version = 1, DisplayNameClaim = "nickname" }))).Succeeded);
        var retired = await f.Run(a => a.ReadProfileAsync(actor));
        Assert.Null(retired.Provider);
        Assert.Equal("Local", retired.Effective.DisplayName);
        Assert.Empty(retired.Effective.Email);
        Assert.True((await f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, claims.RootElement))).Succeeded);
        var refreshed = await f.Run(a => a.ReadProfileAsync(actor));
        Assert.Equal(local.Version, refreshed.Version);
        Assert.Equal("Local", refreshed.Effective.DisplayName);
        Assert.Equal(["displayName.missing"], refreshed.Provider!.Diagnostics);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping with { Version = 2, Enabled = false }))).Succeeded);
        Assert.Null((await f.Run(a => a.ReadProfileAsync(actor))).Provider);
        Assert.Equal(1, f.Count("OidcProfileObservation"));
    }

    /// <summary>Current Administrator authority, expected versions and transactional audit protect mapping changes.</summary>
    [Fact]
    public async Task MappingMutations_DenyStaleOrRevokedAuthorityAndRollbackAuditFailure()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var mapping = new OidcProfileMapping("https://issuer.example", 0, true, "name", "", "", "", null);
        await Denied(() => f.Run(a => a.SaveOidcProfileMappingAsync(External(mapping.Issuer, "auditor"), mapping)));
        Assert.Equal(["profile.mappingInvalid"], (await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping with { DisplayNameClaim = "groups" }))).ErrorCodes);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping))).Succeeded);
        Assert.Equal(["profile.mappingStale"], (await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping))).ErrorCodes);
        var events = f.Count("IdentityAudit");
        f.Sql("CREATE TRIGGER fixture_mapping_audit_failure BEFORE INSERT ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
        await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping with { Version = 1, Enabled = false })));
        Assert.True(Assert.Single(await f.Run(a => a.ReadOidcProfileMappingsAsync(admin))).Enabled);
        Assert.Equal(events, f.Count("IdentityAudit"));
        f.Sql("DROP TRIGGER fixture_mapping_audit_failure");
        var account = Assert.Single(await f.Run(a => a.ListUsersAsync(admin)));
        Assert.True((await f.Run(a => a.RevokeUserAsync(admin, account.Id, account.Version))).Succeeded);
        await Denied(() => f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping with { Version = 1 })));
    }

    /// <summary>Metadata cannot cross actor bindings or persist from ambiguous payloads or incomplete schema.</summary>
    [Fact]
    public async Task ProviderRefresh_DeniesLocalActorsIdentityMismatchDuplicatesAndBrokenSchema()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var mapping = new OidcProfileMapping("https://issuer.example", 0, true, "name", "", "", "", null);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin, mapping))).Succeeded);
        using var mismatch = JsonDocument.Parse("""{"iss":"https://issuer.example","sub":"another","name":"wrong"}""");
        var actor = External(mapping.Issuer, "subject");
        Assert.Equal(["profile.providerIdentity"], (await f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, mismatch.RootElement))).ErrorCodes);
        Assert.Equal(["profile.providerIdentity"], (await f.Run(a => a.RefreshVerifiedOidcProfileAsync(admin, mismatch.RootElement))).ErrorCodes);
        using var duplicate = JsonDocument.Parse("""{"iss":"https://issuer.example","sub":"subject","name":"first","name":"second"}""");
        Assert.Equal(["profile.providerClaims"], (await f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, duplicate.RootElement))).ErrorCodes);
        Assert.Equal(0, f.Count("OidcProfileObservation"));
        f.Sql("DROP TABLE OidcProfileObservation");
        Assert.Equal("account.schemaOrIntegrity", (await Assert.ThrowsAsync<AccountStoreException>(() =>
            f.Run(a => a.VerifyAsync("fixture-admin", Password)))).Code);
    }

    /// <summary>A callback from a retired connection cannot refresh profile defaults or append a sign-in audit.</summary>
    [Fact]
    public async Task OidcProfileRefresh_DeniesRetiredConnectionInsideTheStore()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var keys = new EphemeralDataProtectionProvider();
        const string issuer = "https://identity.example.test";
        var connection = new OidcConnectionSettings(true, issuer, "client", "https://firewall.example.test/signin-oidc",
            "groups", ["admins"], []);
        Assert.True((await f.Run(a => a.SaveOidcConnectionAsync(admin, 0, connection, "synthetic-secret", keys))).Succeeded);
        Assert.True((await f.Run(a => a.SaveOidcProfileMappingAsync(admin,
            new OidcProfileMapping(issuer, 0, true, "name", "", "", "", null)))).Succeeded);
        var actor = External(issuer, "subject");
        ((ClaimsIdentity)actor.Identity!).AddClaim(new("nergal.oidc-generation", "1"));
        using var verified = JsonDocument.Parse("""{"iss":"https://identity.example.test","sub":"subject","name":"Stable"}""");
        Assert.True((await f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, verified.RootElement))).Succeeded);
        var disabled = new OidcConnectionSettings(false, issuer, connection.ClientId, connection.CallbackUri,
            connection.GroupClaim, connection.AdministratorGroups, connection.AuditorGroups);
        Assert.True((await f.Run(a => a.SaveOidcConnectionAsync(admin, 1, disabled, "", keys))).Succeeded);
        var events = f.Count("IdentityAudit");
        using var retired = JsonDocument.Parse("""{"iss":"https://identity.example.test","sub":"subject","name":"Retired"}""");
        await Denied(() => f.Run(a => a.RefreshVerifiedOidcProfileAsync(actor, retired.RootElement)));
        Assert.Equal(events, f.Count("IdentityAudit"));
        Assert.Equal("Stable", f.Scalar("SELECT DisplayName FROM OidcProfileObservation"));
    }

    /// <summary>Secret storage is purpose-bound, write-only, versioned, and cannot be replaced by stale or nonlocal actors.</summary>
    [Fact]
    public async Task OidcConnection_EncryptsSecretsAndRequiresCurrentLocalAuthority()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var keys = new EphemeralDataProtectionProvider();
        var settings = new OidcConnectionSettings(true, "https://identity.example.test", "client", "https://firewall.example.test/signin-oidc", "groups", ["admins"], ["auditors"]);
        Assert.Null(await f.Run(a => a.ReadOidcConnectionAsync(admin)));
        Assert.Equal(["provider.secretRequired"], (await f.Run(a => a.SaveOidcConnectionAsync(admin, 0, settings, "", keys))).ErrorCodes);
        const string secret = "synthetic-client-secret-0001";
        Assert.True((await f.Run(a => a.SaveOidcConnectionAsync(admin, 0, settings, secret, keys))).Succeeded);
        var snapshot = (await f.Run(a => a.ReadOidcConnectionAsync(admin)))!;
        Assert.Equal(1, snapshot.Version); Assert.True(snapshot.HasSecret);
        Assert.DoesNotContain(secret, (string)f.Scalar("SELECT ProtectedSecret FROM OidcConnection")!);
        Assert.Equal(secret, (await f.Run(a => a.ReadOidcRuntimeAsync(keys)))!.ClientSecret);
        Assert.Equal("provider.secretUnavailable", (await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.ReadOidcRuntimeAsync(new EphemeralDataProtectionProvider())))).Code);
        Assert.Equal(["provider.stale"], (await f.Run(a => a.SaveOidcConnectionAsync(admin, 0, settings, secret, keys))).ErrorCodes);
        Assert.True((await f.Run(a => a.SaveOidcConnectionAsync(admin, 1, settings, "", keys))).Succeeded);
        Assert.Equal(secret, (await f.Run(a => a.ReadOidcRuntimeAsync(keys)))!.ClientSecret);
        var other = new OidcConnectionSettings(true, "https://other.example.test", "client", settings.CallbackUri, "groups", ["admins"], []);
        Assert.Equal(["provider.secretRequired"], (await f.Run(a => a.SaveOidcConnectionAsync(admin, 2, other, "", keys))).ErrorCodes);
        await Denied(() => f.Run(a => a.ReadOidcConnectionAsync(External(settings.Issuer, "auditor"))));
        var external = External(settings.Issuer, "administrator");
        ((ClaimsIdentity)external.Identity!).RemoveClaim(external.FindFirst(ClaimTypes.Role)!);
        ((ClaimsIdentity)external.Identity!).AddClaim(new(ClaimTypes.Role, NergalRoles.Administrator));
        Assert.Equal(["provider.localAdministratorRequired"], (await f.Run(a => a.SaveOidcConnectionAsync(external, 2, settings, secret, keys))).ErrorCodes);
        var user = Assert.Single(await f.Run(a => a.ListUsersAsync(admin)));
        Assert.True((await f.Run(a => a.RevokeUserAsync(admin, user.Id, user.Version))).Succeeded);
        await Denied(() => f.Run(a => a.SaveOidcConnectionAsync(admin, 2, settings, secret, keys)));
    }

    /// <summary>Audit failure cannot partially replace trust; missing rows or tampered ciphertext never restore bootstrap trust.</summary>
    [Fact]
    public async Task OidcConnection_AuditFailureAndStoredCorruptionFailClosed()
    {
        await using var f = await Fixture.Create();
        var admin = await f.SignIn("fixture-admin");
        var keys = new EphemeralDataProtectionProvider();
        var settings = new OidcConnectionSettings(true, "https://identity.example.test", "client", "https://firewall.example.test/signin-oidc", "groups", ["admins"], []);
        Assert.True((await f.Run(a => a.SaveOidcConnectionAsync(admin, 0, settings, "synthetic-secret", keys))).Succeeded);
        var events = f.Count("IdentityAudit");
        f.Sql("CREATE TRIGGER fixture_connection_audit_failure BEFORE INSERT ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END");
        await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.SaveOidcConnectionAsync(admin, 1, settings, "replacement-secret", keys)));
        Assert.Equal(events, f.Count("IdentityAudit"));
        Assert.Equal(1, (await f.Run(a => a.ReadOidcConnectionAsync(admin)))!.Version);
        Assert.Equal("synthetic-secret", (await f.Run(a => a.ReadOidcRuntimeAsync(keys)))!.ClientSecret);
        f.Sql("DROP TRIGGER fixture_connection_audit_failure");
        f.Sql("UPDATE OidcConnection SET ProtectedSecret='tampered'");
        Assert.Equal("provider.secretUnavailable", (await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.ReadOidcRuntimeAsync(keys)))).Code);
        f.Sql("DELETE FROM OidcConnection");
        Assert.Equal("account.corrupt", (await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.ReadOidcRuntimeAsync(keys)))).Code);
    }

    private static ClaimsPrincipal External(string issuer, string subject) => new(new ClaimsIdentity([
        new("iss", issuer), new("sub", subject), new(ClaimTypes.Name, "same-name"), new(ClaimTypes.Email, "same@example.test"),
        new(ClaimTypes.Role, NergalRoles.Auditor), new(ControllerActorIdentity.ActorClaimType, ControllerActorIdentity.FromFederatedAccount(issuer, subject)),
    ], "nergal.federated-session"));

    private static async Task Denied(Func<Task> operation) => Assert.Equal("account.denied",
        (await Assert.ThrowsAsync<AccountStoreException>(operation)).Code);

    private sealed class Fixture : IAsyncDisposable
    {
        internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "nergal-user-management-" + Guid.NewGuid().ToString("N"));
        internal string Database => Path.Combine(Directory, "accounts.db");
        internal LocalAccountOptions Options { get; }
        private readonly ServiceProvider services;
        private Fixture()
        {
            System.IO.Directory.CreateDirectory(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Options = new(Directory);
            var collection = new ServiceCollection().AddLocalAdministratorAccounts(Options);
            collection.AddDataProtection().UseEphemeralDataProtectionProvider();
            collection.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme);
            services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        }
        internal static async Task<Fixture> Create()
        {
            var f = new Fixture();
            try
            {
                await LocalAccountDatabase.InitializeAsync(f.Options);
                Assert.True((await f.Run(a => a.ProvisionAsync("fixture-admin", Password))).Succeeded);
                return f;
            }
            catch { await f.DisposeAsync(); throw; }
        }
        internal async Task<T> Run<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
        {
            using var scope = services.CreateScope();
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = http;
            return await operation(scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>());
        }
        internal async Task<ClaimsPrincipal> SignIn(string name)
        {
            using var scope = services.CreateScope();
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = http;
            Assert.True(await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().SignInAsync(name, Password));
            var ticket = services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>()
                .Get(IdentityConstants.ApplicationScheme).TicketDataFormat.Unprotect(http.Response.Headers.SetCookie.ToString().Split(';')[0].Split('=', 2)[1]);
            Assert.NotNull(ticket);
            return ticket.Principal;
        }
        internal object? Scalar(string sql)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
            connection.Open(); using var command = connection.CreateCommand(); command.CommandText = sql; return command.ExecuteScalar();
        }
        internal void Sql(string sql) => Scalar(sql);
        internal long Count(string table) => Convert.ToInt64(Scalar("SELECT count(*) FROM " + table));
        public async ValueTask DisposeAsync() { await services.DisposeAsync(); System.IO.Directory.Delete(Directory, true); }
    }
}
