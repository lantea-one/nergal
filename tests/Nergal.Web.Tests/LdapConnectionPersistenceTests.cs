using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Tests protected LDAP settings against a disposable SQLite account store and real Data Protection.</summary>
[SupportedOSPlatform("linux")]
public sealed class LdapConnectionPersistenceTests
{
    private const string LocalPassword = "synthetic local account password";
    private const string InitialSecret = " clé de recherche ";
    private const string ReplacementSecret = "synthetic replacement directory password";
    private static readonly LdapConnectionSettings Settings = new(true, "ldaps://directory.example.test",
        "192.0.2.10", "ou=people,dc=example,dc=test", "cn=reader,dc=example,dc=test", "uid",
        "cn=admins,dc=example,dc=test", "cn=auditors,dc=example,dc=test", new("cn", "givenName", "sn", "mail"));

    /// <summary>Fresh stores preserve the exact bind secret, managed settings and audit across service reconstruction.</summary>
    [Fact]
    public async Task Save_PersistsProtectedStateAndRejectsReplay()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.Equal(8L, fixture.Scalar("PRAGMA user_version"));
        Assert.Null(await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        Assert.Null(await fixture.Run(a => a.ReadLdapRuntimeAsync(0, fixture.Keys)));
        Assert.Equal(["provider.secretRequired"], (await fixture.Save(admin, 0, Settings, "")).ErrorCodes);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        Assert.Equal(["provider.stale"], (await fixture.Save(admin, 0, Settings, ReplacementSecret)).ErrorCodes);
        var saved = await fixture.Run(a => a.ReadLdapConnectionAsync(admin));
        Assert.NotNull(saved);
        Assert.Equal(1L, saved.Version);
        Assert.Equal(Settings, saved.Settings);
        Assert.NotEqual(Guid.Empty, saved.DirectoryId);
        Assert.True(saved.HasSecret);
        Assert.Equal(TimeSpan.Zero, saved.UpdatedUtc.Offset);
        Assert.DoesNotContain(InitialSecret, Assert.IsType<string>(fixture.Scalar("SELECT ProtectedSecret FROM LdapConnection")));
        var audit = Assert.Single(await fixture.Run(a => a.ReadIdentityAuditAsync(admin)),
            entry => entry.Action == "provider.ldapConnectionSaved");
        Assert.Equal("ldap", audit.Target);
        Assert.Equal(admin.FindFirstValue(ControllerActorIdentity.ActorClaimType), audit.ActorId);
        Assert.Equal(NergalRoles.Administrator, audit.ActorRole);

        await fixture.RestartServices();
        Assert.Equal(saved, await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        var runtime = await fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys));
        Assert.NotNull(runtime);
        Assert.Equal(saved, runtime.Snapshot);
        Assert.Equal(Settings.ToDirectorySettings(saved.DirectoryId), runtime.Directory);
        Assert.Equal(Settings.DialIp, runtime.DialAddress.ToString());
        Assert.Equal(InitialSecret, runtime.SearchPassword);
    }

    /// <summary>Two creation attempts with the same generation cannot both commit.</summary>
    [Fact]
    public async Task ConcurrentCreate_CommitsOneGenerationAndOneAudit()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<LocalProvisionResult> Attempt(string secret) => Task.Run(async () =>
        {
            await ready.Task;
            return await fixture.Save(admin, 0, Settings, secret);
        });
        var first = Attempt(InitialSecret);
        var second = Attempt(ReplacementSecret);
        ready.SetResult();
        var results = await Task.WhenAll(first, second);
        Assert.Single(results, result => result.Succeeded);
        var rejected = Assert.Single(results, result => !result.Succeeded);
        Assert.Equal(["provider.stale"], rejected.ErrorCodes);
        Assert.Equal(1L, fixture.Scalar("SELECT count(*) FROM LdapConnection"));
        Assert.Equal(1L, fixture.Scalar("SELECT count(*) FROM IdentityAudit WHERE Action='provider.ldapConnectionSaved'"));
        var runtime = await fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys));
        Assert.Equal(results[0].Succeeded ? InitialSecret : ReplacementSecret, runtime?.SearchPassword);
    }

    /// <summary>Only a current local Administrator may view or change trust, even with a valid external Administrator identity.</summary>
    [Fact]
    public async Task Management_RechecksLocalRoleAndSecurityStamp()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Run(a => a.CreateUserAsync(admin, "fixture-auditor", LocalPassword, NergalRoles.Auditor))).Succeeded);
        var auditor = await fixture.SignIn("fixture-auditor");
        var forgedRole = new ClaimsPrincipal(auditor.Identities.Select(identity => new ClaimsIdentity(
            identity.Claims.Where(claim => claim.Type != ClaimTypes.Role).Append(new(ClaimTypes.Role, NergalRoles.Administrator)),
            identity.AuthenticationType)));
        const string issuer = "https://oidc.example.test";
        var external = new ClaimsPrincipal(new ClaimsIdentity([
            new("iss", issuer), new("sub", "external-admin"), new(ClaimTypes.Role, NergalRoles.Administrator),
            new(ControllerActorIdentity.ActorClaimType, ControllerActorIdentity.FromFederatedAccount(issuer, "external-admin"))
        ], "fixture-oidc"));
        await Denied("account.denied", () => fixture.Run(a => a.ReadLdapConnectionAsync(auditor)));
        await Denied("account.denied", () => fixture.Save(forgedRole, 0, Settings, InitialSecret));
        await Denied("provider.localAdministratorRequired", () => fixture.Run(a => a.ReadLdapConnectionAsync(external)));
        Assert.Equal(["provider.localAdministratorRequired"], (await fixture.Save(external, 0, Settings, InitialSecret)).ErrorCodes);

        var local = Assert.Single(await fixture.Run(a => a.ListUsersAsync(admin)), u => u.UserName == "fixture-admin");
        Assert.True((await fixture.Run(a => a.RevokeUserAsync(admin, local.Id, local.Version))).Succeeded);
        await Denied("account.denied", () => fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        await Denied("account.denied", () => fixture.Save(admin, 0, Settings, InitialSecret));
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM LdapConnection"));
    }

    /// <summary>Non-bind edits retain the exact secret and actor namespace while disabled or stale attempts skip decryption.</summary>
    [Fact]
    public async Task Save_RetainsBindSecretAcrossNonTrustEdits()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Run(a => a.ReadLdapConnectionAsync(admin));
        Assert.NotNull(original);
        var ciphertext = fixture.Scalar("SELECT ProtectedSecret FROM LdapConnection");
        var updated = Settings with { Enabled = false, LoginAttribute = "mail", ProfileMapping = new() };
        Assert.True((await fixture.Save(admin, 1, updated, "")).Succeeded);
        Assert.Equal(["provider.stale"], (await fixture.Save(admin, 1, Settings, ReplacementSecret)).ErrorCodes);
        Assert.Null(await fixture.Run(a => a.ReadLdapRuntimeAsync(2, new EphemeralDataProtectionProvider())));
        Assert.True((await fixture.Save(admin, 2, updated with { Enabled = true }, "")).Succeeded);
        Assert.Null(await fixture.Run(a => a.ReadLdapRuntimeAsync(2, new EphemeralDataProtectionProvider())));
        var runtime = await fixture.Run(a => a.ReadLdapRuntimeAsync(3, fixture.Keys));
        Assert.NotNull(runtime);
        Assert.Equal(original.DirectoryId, runtime.Snapshot.DirectoryId);
        Assert.Equal(InitialSecret, runtime.SearchPassword);
        Assert.Equal(ciphertext, fixture.Scalar("SELECT ProtectedSecret FROM LdapConnection"));
    }

    /// <summary>Each bind-trust edit requires replacement, and only bind-DN rotation preserves the actor namespace.</summary>
    [Theory]
    [InlineData("endpoint")]
    [InlineData("dial")]
    [InlineData("base")]
    [InlineData("bind")]
    public async Task Save_RequiresReplacementForBindTrustChanges(string change)
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Run(a => a.ReadLdapConnectionAsync(admin));
        Assert.NotNull(original);
        var updated = change switch
        {
            "endpoint" => Settings with { ServerUri = Settings.ServerUri + ":636" },
            "dial" => Settings with { DialIp = "2001:db8::10" },
            "base" => Settings with { UserBaseDn = "ou=other,dc=example,dc=test" },
            "bind" => Settings with { SearchBindDn = "cn=reader-new,dc=example,dc=test" },
            _ => throw new ArgumentOutOfRangeException(nameof(change))
        };
        Assert.Equal(["provider.secretRequired"], (await fixture.Save(admin, 1, updated, "")).ErrorCodes);
        Assert.Equal(original, await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        Assert.True((await fixture.Save(admin, 1, updated, ReplacementSecret)).Succeeded);
        var runtime = await fixture.Run(a => a.ReadLdapRuntimeAsync(2, fixture.Keys));
        Assert.NotNull(runtime);
        Assert.Equal(change == "bind", original.DirectoryId == runtime.Snapshot.DirectoryId);
        Assert.Equal(updated, runtime.Snapshot.Settings);
        Assert.Equal(ReplacementSecret, runtime.SearchPassword);
    }

    /// <summary>Only canonical literal dial addresses are accepted, and an IP-literal peer must match the dial address.</summary>
    [Theory]
    [InlineData("ldaps://directory.example.test", "directory.example.test")]
    [InlineData("ldaps://directory.example.test", "192.000.2.10")]
    [InlineData("ldaps://directory.example.test", "2001:DB8:0:0::10")]
    [InlineData("ldaps://directory.example.test", "fe80::10%2")]
    [InlineData("ldaps://192.0.2.11", "192.0.2.10")]
    [InlineData("ldaps://[2001:db8::11]", "2001:db8::10")]
    public async Task Save_RejectsInvalidDialAddress(string uri, string dialIp)
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        var result = await fixture.Save(admin, 0, Settings with { ServerUri = uri, DialIp = dialIp }, InitialSecret);
        Assert.Equal(["provider.invalid"], result.ErrorCodes);
        Assert.Null(await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
    }

    /// <summary>Invalid bind secrets cannot commit even when a valid connection is supplied.</summary>
    [Fact]
    public async Task Save_UsesAdapterPasswordContract()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        foreach (var malformed in new[] { "nul\0secret", new string('x', 2049), new string('\ud800', 1) })
        {
            Assert.Equal(["provider.invalid"], (await fixture.Save(admin, 0, Settings, malformed)).ErrorCodes);
        }
        Assert.True((await fixture.Save(admin, 0, Settings, " ")).Succeeded);
        Assert.Equal(" ", (await fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys)))?.SearchPassword);
    }

    /// <summary>Aborting the SQLite audit insert preserves the prior generation, directory identity and credential.</summary>
    [Fact]
    public async Task Save_AuditFailureRollsBackCreationAndReplacement()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        const string failAudit = """
            CREATE TRIGGER fixture_ldap_audit_failure BEFORE INSERT ON IdentityAudit
            WHEN NEW.Action = 'provider.ldapConnectionSaved' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END
            """;
        fixture.Scalar(failAudit);
        await Denied("account.databaseError", () => fixture.Save(admin, 0, Settings, InitialSecret));
        Assert.Null(await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        fixture.Scalar("DROP TRIGGER fixture_ldap_audit_failure");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Run(a => a.ReadLdapConnectionAsync(admin));
        fixture.Scalar(failAudit);
        await Denied("account.databaseError", () =>
            fixture.Save(admin, 1, Settings with { DialIp = "192.0.2.11" }, ReplacementSecret));
        Assert.Equal(1L, fixture.Scalar("SELECT count(*) FROM IdentityAudit WHERE Action='provider.ldapConnectionSaved'"));
        Assert.Equal(original, await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        Assert.Equal(InitialSecret, (await fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys)))?.SearchPassword);
    }

    /// <summary>Any changed bound field or ciphertext fails decryption for a current adapter attempt.</summary>
    [Theory]
    [InlineData("DirectoryId", "11111111-2222-4333-8444-555555555555")]
    [InlineData("ServerUri", "ldaps://directory.example.test:636")]
    [InlineData("DialIp", "192.0.2.11")]
    [InlineData("UserBaseDn", "ou=other,dc=example,dc=test")]
    [InlineData("SearchBindDn", "cn=other,dc=example,dc=test")]
    [InlineData("ProtectedSecret", "!")]
    public async Task Runtime_DeniesDamagedOrRetargetedCiphertext(string column, string value)
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        fixture.Scalar($"UPDATE LdapConnection SET {column}=$value", value);
        Assert.Equal(1L, (await fixture.Run(a => a.ReadLdapConnectionAsync(admin)))?.Version);
        await Denied("provider.secretUnavailable", () => fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys)));
    }

    /// <summary>Wrong keys cannot unseal the secret and a deleted row cannot return to first-run state.</summary>
    [Fact]
    public async Task Runtime_RejectsWrongKeyAndDeletedRow()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        var oidc = new OidcConnectionSettings(true, "https://oidc.example.test", "fixture-client",
            "https://controller.example.test/signin-oidc", "groups", ["admins"], []);
        Assert.True((await fixture.Run(a => a.SaveOidcConnectionAsync(admin, 0, oidc, "synthetic-oidc-secret", fixture.Keys))).Succeeded);
        Assert.Null(await fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        await Denied("provider.secretUnavailable", () => fixture.Run(a => a.ReadLdapRuntimeAsync(1, new EphemeralDataProtectionProvider())));
        fixture.Scalar("UPDATE LdapConnection SET ProtectedSecret='!'");
        var local = await fixture.Run(async a =>
        {
            await a.RequireProvisionedAsync();
            return await a.VerifyAsync("fixture-admin", LocalPassword);
        });
        Assert.True(local.Succeeded);
        fixture.Scalar("DELETE FROM LdapConnection");
        await Denied("account.corrupt", () => fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys)));
        await Denied("account.corrupt", () => fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        await Denied("account.corrupt", () => fixture.Save(admin, 0, Settings, ReplacementSecret));
    }

    /// <summary>SQLite rejects invalid singleton identities, enabled flags and non-integer or out-of-range generations.</summary>
    [Theory]
    [InlineData("Id=2")]
    [InlineData("Enabled=2")]
    [InlineData("Enabled=0.5")]
    [InlineData("Version=0")]
    [InlineData("Version=1.5")]
    [InlineData("Version=9223372036854775807")]
    public async Task Schema_EnforcesConnectionConstraints(string assignment)
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var error = Assert.Throws<SqliteException>(() => { fixture.Scalar($"UPDATE LdapConnection SET {assignment}"); });
        Assert.Equal(19, error.SqliteErrorCode);
        Assert.Equal(1L, (await fixture.Run(a => a.ReadLdapConnectionAsync(admin)))?.Version);
    }

    /// <summary>Restoring a formerly valid row cannot roll trust back while later committed audit history remains.</summary>
    [Fact]
    public async Task Runtime_DeniesOlderValidRowWithLaterAuditHistory()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn("fixture-admin");
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        fixture.Scalar("CREATE TABLE fixture_old_ldap AS SELECT * FROM LdapConnection");
        Assert.True((await fixture.Save(admin, 1, Settings with { DialIp = "192.0.2.11" }, ReplacementSecret)).Succeeded);
        fixture.Scalar("DELETE FROM LdapConnection; INSERT INTO LdapConnection SELECT * FROM fixture_old_ldap; DROP TABLE fixture_old_ldap");
        Assert.Equal(1L, fixture.Scalar("SELECT Version FROM LdapConnection"));
        Assert.Equal(2L, fixture.Scalar("SELECT count(*) FROM IdentityAudit WHERE Action='provider.ldapConnectionSaved'"));
        await Denied("account.corrupt", () => fixture.Run(a => a.ReadLdapRuntimeAsync(1, fixture.Keys)));
        await Denied("account.corrupt", () => fixture.Run(a => a.ReadLdapRuntimeAsync(2, fixture.Keys)));
        await Denied("account.corrupt", () => fixture.Run(a => a.ReadLdapConnectionAsync(admin)));
        await Denied("account.corrupt", () => fixture.Save(admin, 1, Settings, ReplacementSecret));
    }

    /// <summary>Opening account storage rejects previous versions and missing or damaged LDAP table definitions.</summary>
    [Theory]
    [InlineData("PRAGMA user_version=4")]
    [InlineData("PRAGMA user_version=5")]
    [InlineData("PRAGMA user_version=6")]
    [InlineData("PRAGMA user_version=7")]
    [InlineData("DROP TABLE LdapConnection")]
    [InlineData("ALTER TABLE LdapConnection DROP COLUMN DialIp")]
    [InlineData("ALTER TABLE LdapConnection DROP COLUMN DialIp; ALTER TABLE LdapConnection ADD COLUMN DialIp INTEGER NOT NULL DEFAULT 0")]
    public async Task Schema_RejectsOldOrDamagedShape(string damage)
    {
        await using var fixture = await Fixture.Create();
        fixture.Scalar(damage);
        await Denied("account.schemaOrIntegrity", () => fixture.Run(a => a.VerifyAsync("fixture-admin", LocalPassword)));
    }

    /// <summary>Reopening fails when a rebuilt table retains its columns but drops the required checks.</summary>
    [Fact]
    public async Task Schema_RejectsConnectionTableWithoutConstraints()
    {
        await using var fixture = await Fixture.Create();
        var definition = Assert.IsType<string>(fixture.Scalar(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='LdapConnection'"));
        var firstCheck = definition.IndexOf("CONSTRAINT \"ldap_connection_", StringComparison.Ordinal);
        Assert.True(firstCheck > 0);
        var withoutChecks = definition[..definition.LastIndexOf(',', firstCheck)] + ")";
        fixture.Scalar($"DROP TABLE LdapConnection; {withoutChecks}");

        Assert.Equal(17L, fixture.Scalar("SELECT count(*) FROM pragma_table_info('LdapConnection')"));
        await Denied("account.schemaOrIntegrity", () => fixture.Run(a => a.VerifyAsync("fixture-admin", LocalPassword)));
    }

    private static async Task Denied(string code, Func<Task> operation)
        => Assert.Equal(code, (await Assert.ThrowsAsync<AccountStoreException>(operation)).Code);

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly LocalAccountOptions options = new(Path.Combine(Path.GetTempPath(), "nergal-ldap-store-" + Guid.NewGuid().ToString("N")));
        private ServiceProvider services = null!;
        internal IDataProtectionProvider Keys { get; } = new EphemeralDataProtectionProvider();

        internal static async Task<Fixture> Create()
        {
            var fixture = new Fixture();
            Directory.CreateDirectory(fixture.options.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            fixture.services = fixture.StartServices();
            try
            {
                await LocalAccountDatabase.InitializeAsync(fixture.options);
                Assert.True((await fixture.Run(a => a.ProvisionAsync("fixture-admin", LocalPassword))).Succeeded);
                return fixture;
            }
            catch { await fixture.DisposeAsync(); throw; }
        }

        private ServiceProvider StartServices()
        {
            var collection = new ServiceCollection().AddLocalAdministratorAccounts(options);
            collection.AddDataProtection().UseEphemeralDataProtectionProvider();
            collection.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme);
            return collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        }

        internal async Task RestartServices()
        {
            await services.DisposeAsync();
            services = StartServices();
        }

        internal Task<LocalProvisionResult> Save(ClaimsPrincipal admin, long version, LdapConnectionSettings settings, string secret)
            => Run(a => a.SaveLdapConnectionAsync(admin, version, settings, secret, Keys));

        internal async Task<T> Run<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
        {
            await using var scope = services.CreateAsyncScope();
            return await operation(scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>());
        }

        internal async Task<ClaimsPrincipal> SignIn(string username)
        {
            await using var scope = services.CreateAsyncScope();
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
            accessor.HttpContext = http;
            try
            {
                Assert.True(await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().SignInAsync(username, LocalPassword));
                var cookie = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.ApplicationScheme);
                var ticket = cookie.TicketDataFormat.Unprotect(http.Response.Headers.SetCookie.ToString().Split(';')[0].Split('=', 2)[1]);
                Assert.NotNull(ticket);
                return ticket.Principal;
            }
            finally { accessor.HttpContext = null; }
        }

        internal object? Scalar(string statement, string? value = null)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(options.Directory, "accounts.db"),
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false
            }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            if (value is not null) { command.Parameters.AddWithValue("$value", value); }
            return command.ExecuteScalar();
        }

        public async ValueTask DisposeAsync()
        {
            await services.DisposeAsync();
            Directory.Delete(options.Directory, recursive: true);
        }
    }
}
