using System.Runtime.Versioning;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
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

/// <summary>Exercises SMTP configuration with a private SQLite account database and real Data Protection.</summary>
[SupportedOSPlatform("linux")]
public sealed class EmailDeliveryStoreTests
{
    private const string Administrator = "fixture-admin";
    private const string LocalPassword = "synthetic local account password";
    private const string InitialSecret = " synthetic SMTP clé ";
    private const string ReplacementSecret = "synthetic rotated SMTP password";
    private const string SaveAction = "mfa.emailDeliverySaved";
    private static readonly EmailDeliverySettings Settings =
        new(true, "relay.example.test", 587, "nergal@example.test", "fixture-relay");

    /// <summary>Creation starts at expected version zero and a replay cannot change settings, password or audit.</summary>
    [Fact]
    public async Task Save_RequiresCurrentVersionAndKeepsPasswordWriteOnly()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.Null(await fixture.Read(admin));
        Assert.Null(await fixture.Runtime(0));
        Assert.Equal(["mfa.stale"], (await fixture.Save(admin, 1, Settings, InitialSecret)).ErrorCodes);
        Assert.Equal(["mfa.deliveryPasswordRequired"], (await fixture.Save(admin, 0, Settings, "")).ErrorCodes);
        Assert.Empty(await fixture.Saves(admin));

        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var saved = await fixture.Read(admin);
        Assert.NotNull(saved);
        Assert.Equal(1L, saved.Version);
        Assert.Equal(Settings, saved.Settings);
        Assert.True(saved.HasPassword);
        Assert.Equal(TimeSpan.Zero, saved.UpdatedUtc.Offset);
        var protectedPassword = fixture.StoredPassword();
        Assert.NotEmpty(protectedPassword);
        Assert.Equal(-1, protectedPassword.AsSpan().IndexOf(Encoding.UTF8.GetBytes(InitialSecret)));

        var replay = await fixture.Save(admin, 0, Settings with { FromAddress = "other@example.test" }, ReplacementSecret);
        Assert.Equal(["mfa.stale"], replay.ErrorCodes);
        Assert.Equal(saved, await fixture.Read(admin));
        Assert.Equal(protectedPassword, fixture.StoredPassword());
        var audit = Assert.Single(await fixture.Saves(admin));
        Assert.Equal("smtp", audit.Target);
        Assert.Equal(admin.FindFirstValue(ControllerActorIdentity.ActorClaimType), audit.ActorId);
        Assert.Equal(NergalRoles.Administrator, audit.ActorRole);
        var publicData = JsonSerializer.Serialize(new { saved, audit });
        Assert.DoesNotContain(JsonEncodedText.Encode(InitialSecret.Trim()).ToString(), publicData);
        Assert.DoesNotContain(Convert.ToBase64String(protectedPassword), publicData);

        var runtime = await fixture.Runtime(1);
        Assert.NotNull(runtime);
        Assert.Equal(saved, runtime.Snapshot);
        Assert.Equal(InitialSecret, runtime.Password);
        await Denied("mfa.deliveryUnavailable", () => fixture.Runtime(1, new EphemeralDataProtectionProvider()));
    }

    /// <summary>Relay management requires a current local Administrator, including the persisted role and security stamp.</summary>
    [Fact]
    public async Task Management_RejectsNonLocalAndStaleAuthority()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Read(admin);
        Assert.True((await fixture.Run(a => a.CreateUserAsync(admin, "fixture-auditor", LocalPassword, NergalRoles.Auditor))).Succeeded);
        var auditor = await fixture.SignIn("fixture-auditor");
        var forgedRole = new ClaimsPrincipal(auditor.Identities.Select(identity => new ClaimsIdentity(
            identity.Claims.Where(claim => claim.Type != ClaimTypes.Role).Append(new(ClaimTypes.Role, NergalRoles.Administrator)),
            identity.AuthenticationType)));
        const string issuer = "https://oidc.example.test";
        const string subject = "fixture-federated-admin";
        var federated = new ClaimsPrincipal(new ClaimsIdentity([
            new("iss", issuer), new("sub", subject), new(ClaimTypes.Role, NergalRoles.Administrator),
            new(ControllerActorIdentity.ActorClaimType, ControllerActorIdentity.FromFederatedAccount(issuer, subject))
        ], "fixture-oidc"));

        foreach (var denied in new[] { new ClaimsPrincipal(new ClaimsIdentity()), auditor, forgedRole })
        {
            await Denied("account.denied", () => fixture.Read(denied));
            await Denied("account.denied", () => fixture.Save(denied, 1, Settings, ReplacementSecret));
        }
        await Denied("provider.localAdministratorRequired", () => fixture.Read(federated));
        Assert.Equal(["provider.localAdministratorRequired"], (await fixture.Save(federated, 1, Settings, ReplacementSecret)).ErrorCodes);

        var local = Assert.Single(await fixture.Run(a => a.ListUsersAsync(admin)), user => user.UserName == Administrator);
        Assert.True((await fixture.Run(a => a.RevokeUserAsync(admin, local.Id, local.Version))).Succeeded);
        await Denied("account.denied", () => fixture.Read(admin));
        await Denied("account.denied", () => fixture.Save(admin, 1, Settings, ReplacementSecret));
        var fresh = await fixture.SignIn(Administrator);
        Assert.Equal(original, await fixture.Read(fresh));
        Assert.Equal(InitialSecret, (await fixture.Runtime(1))?.Password);
        Assert.Single(await fixture.Saves(fresh));
    }

    /// <summary>Two callers updating the same generation can commit only one setting change and audit event.</summary>
    [Fact]
    public async Task ConcurrentSave_CommitsOneUpdate()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = Assert.Single(await fixture.Saves(admin));
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<LocalProvisionResult> Attempt(string password) => Task.Run(async () =>
        {
            await ready.Task;
            return await fixture.Save(admin, 1, Settings, password);
        });

        var first = Attempt(InitialSecret);
        var second = Attempt(ReplacementSecret);
        ready.SetResult();
        var results = await Task.WhenAll(first, second);
        Assert.Single(results, result => result.Succeeded);
        Assert.Equal(["mfa.stale"], Assert.Single(results, result => !result.Succeeded).ErrorCodes);
        AssertNextSave(original, await fixture.Saves(admin));
        Assert.Equal(results[0].Succeeded ? InitialSecret : ReplacementSecret, (await fixture.Runtime(2))?.Password);
        Assert.Null(await fixture.Runtime(1));
    }

    /// <summary>Changing any credential destination field requires replacement and invalidates replay of the old ciphertext.</summary>
    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("username")]
    public async Task Save_BindsPasswordToRelayDestination(string field)
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Read(admin);
        var protectedPassword = fixture.StoredPassword();
        var newDestination = field switch
        {
            "host" => Settings with { Host = "backup-relay.example.test" },
            "port" => Settings with { Port = 2525 },
            "username" => Settings with { UserName = "fixture-backup-relay" },
            _ => throw new ArgumentOutOfRangeException(nameof(field))
        };

        Assert.Equal(["mfa.deliveryPasswordRequired"], (await fixture.Save(admin, 1, newDestination, "")).ErrorCodes);
        Assert.Equal(original, await fixture.Read(admin));
        Assert.Equal(protectedPassword, fixture.StoredPassword());
        Assert.Single(await fixture.Saves(admin));

        Assert.True((await fixture.Save(admin, 1, newDestination, ReplacementSecret)).Succeeded);
        var runtime = await fixture.Runtime(2);
        Assert.NotNull(runtime);
        Assert.Equal(newDestination, runtime.Snapshot.Settings);
        Assert.Equal(ReplacementSecret, runtime.Password);

        fixture.Sql("UPDATE EmailDeliveryConnection SET ProtectedPassword = $password", protectedPassword);
        await Denied("mfa.deliveryUnavailable", () => fixture.Runtime(2));
    }

    /// <summary>Disabling delivery preserves the credential, blocks enrollment and denies both current and retired delivery reservations.</summary>
    [Fact]
    public async Task Runtime_DeniesDisabledAndStaleGenerations()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        Assert.True((await fixture.Run(a => a.ReadEmailMfaEnrollmentAsync(admin))).CanStart);
        var protectedPassword = fixture.StoredPassword();
        var disabled = Settings with { Enabled = false, FromAddress = "recovery@example.test" };
        Assert.True((await fixture.Save(admin, 1, disabled, "")).Succeeded);
        Assert.Equal(disabled, (await fixture.Read(admin))?.Settings);
        Assert.Equal(protectedPassword, fixture.StoredPassword());
        Assert.False((await fixture.Run(a => a.ReadEmailMfaEnrollmentAsync(admin))).CanStart);

        var sender = new RecordingSender();
        Assert.Null(await fixture.Run(a => a.BeginEmailMfaEnrollmentAsync(admin, "recipient@example.test", fixture.Keys, sender)));
        Assert.Equal(0, sender.Calls);
        Assert.Null(await fixture.Runtime(1));
        Assert.Null(await fixture.Runtime(2, new EphemeralDataProtectionProvider()));

        Assert.True((await fixture.Save(admin, 2, disabled with { Enabled = true }, "")).Succeeded);
        Assert.Null(await fixture.Runtime(1));
        Assert.Null(await fixture.Runtime(2));
        Assert.Null(await fixture.Runtime(4));
        Assert.Equal(InitialSecret, (await fixture.Runtime(3))?.Password);
        Assert.Equal(protectedPassword, fixture.StoredPassword());
    }

    /// <summary>An older valid configuration cannot regain authority while later append-only saves remain.</summary>
    [Fact]
    public async Task Store_RejectsRestoredRowWithLaterAudit()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        Assert.Equal(InitialSecret, (await fixture.Runtime(1))?.Password);
        var original = Assert.Single(await fixture.Saves(admin));
        fixture.Sql("CREATE TABLE fixture_old_delivery AS SELECT * FROM EmailDeliveryConnection");
        Assert.True((await fixture.Save(admin, 1, Settings with { Host = "backup-relay.example.test" }, ReplacementSecret)).Succeeded);
        var committed = await fixture.Saves(admin);
        AssertNextSave(original, committed);
        Assert.Equal(ReplacementSecret, (await fixture.Runtime(2))?.Password);

        fixture.Sql("""
            BEGIN;
            DELETE FROM EmailDeliveryConnection;
            INSERT INTO EmailDeliveryConnection SELECT * FROM fixture_old_delivery;
            DROP TABLE fixture_old_delivery;
            COMMIT;
            """);
        Assert.Equal(1L, Assert.IsType<long>(fixture.Sql("SELECT Version FROM EmailDeliveryConnection")));
        var deletion = Assert.Throws<SqliteException>(() =>
        {
            fixture.Sql("DELETE FROM IdentityAudit WHERE Action = 'mfa.emailDeliverySaved'");
        });
        Assert.Equal(19, deletion.SqliteErrorCode);
        Assert.Equal(committed, await fixture.Saves(admin));

        await Denied("account.corrupt", () => fixture.Read(admin));
        await Denied("account.corrupt", () => fixture.Runtime(1));
        await Denied("account.corrupt", () => fixture.Runtime(2));
        await Denied("account.corrupt", () => fixture.Save(admin, 1, Settings, ReplacementSecret));
        Assert.Equal(committed, await fixture.Saves(admin));
    }

    /// <summary>A failed audit insert rolls back both initial configuration and later credential rotation.</summary>
    [Fact]
    public async Task Save_RollsBackWhenAuditInsertFails()
    {
        await using var fixture = await Fixture.Create();
        var admin = await fixture.SignIn(Administrator);
        const string failAudit = """
            CREATE TRIGGER fixture_delivery_audit_failure BEFORE INSERT ON IdentityAudit
            WHEN NEW.Action = 'mfa.emailDeliverySaved'
            BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END
            """;
        const string allowAudit = "DROP TRIGGER fixture_delivery_audit_failure";

        fixture.Sql(failAudit);
        await Denied("account.databaseError", () => fixture.Save(admin, 0, Settings, InitialSecret));
        Assert.Null(await fixture.Read(admin));
        Assert.Empty(await fixture.Saves(admin));

        fixture.Sql(allowAudit);
        Assert.True((await fixture.Save(admin, 0, Settings, InitialSecret)).Succeeded);
        var original = await fixture.Read(admin);
        var initialAudit = Assert.Single(await fixture.Saves(admin));
        var protectedPassword = fixture.StoredPassword();
        var newDestination = Settings with { Host = "backup-relay.example.test" };
        fixture.Sql(failAudit);
        await Denied("account.databaseError", () => fixture.Save(admin, 1, newDestination, ReplacementSecret));
        Assert.Equal(original, await fixture.Read(admin));
        Assert.Equal(protectedPassword, fixture.StoredPassword());
        Assert.Equal(InitialSecret, (await fixture.Runtime(1))?.Password);
        Assert.Null(await fixture.Runtime(2));
        Assert.Equal(initialAudit, Assert.Single(await fixture.Saves(admin)));

        fixture.Sql(allowAudit);
        Assert.True((await fixture.Save(admin, 1, newDestination, ReplacementSecret)).Succeeded);
        Assert.Equal(ReplacementSecret, (await fixture.Runtime(2))?.Password);
        AssertNextSave(initialAudit, await fixture.Saves(admin));
    }

    private static void AssertNextSave(IdentityAuditEntry original, IdentityAuditEntry[] history)
        => Assert.Collection(history,
            latest => Assert.True(latest.Sequence > original.Sequence),
            earlier => Assert.Equal(original, earlier));

    private static async Task Denied(string code, Func<Task> operation)
        => Assert.Equal(code, (await Assert.ThrowsAsync<AccountStoreException>(operation)).Code);

    private sealed class RecordingSender : IMfaEmailSender
    {
        internal int Calls { get; private set; }

        public Task SendAsync(EmailMfaDelivery delivery, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.CompletedTask;
        }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly LocalAccountOptions options = new(Path.Combine(Path.GetTempPath(), "nergal-email-store-" + Guid.NewGuid().ToString("N")));
        private ServiceProvider services = null!;
        internal IDataProtectionProvider Keys { get; } = new EphemeralDataProtectionProvider();

        internal static async Task<Fixture> Create()
        {
            var fixture = new Fixture();
            Directory.CreateDirectory(fixture.options.Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                var collection = new ServiceCollection().AddLocalAdministratorAccounts(fixture.options);
                collection.AddDataProtection().UseEphemeralDataProtectionProvider();
                collection.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme);
                fixture.services = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
                await LocalAccountDatabase.InitializeAsync(fixture.options);
                Assert.True((await fixture.Run(a => a.ProvisionAsync(Administrator, LocalPassword))).Succeeded);
                return fixture;
            }
            catch
            {
                await fixture.DisposeAsync();
                throw;
            }
        }

        internal Task<EmailDeliverySnapshot?> Read(ClaimsPrincipal admin)
            => Run(a => a.ReadEmailDeliveryAsync(admin));

        internal Task<EmailDeliveryRuntime?> Runtime(long generation, IDataProtectionProvider? keys = null)
            => Run(a => a.ReadEmailDeliveryRuntimeAsync(generation, keys ?? Keys));

        internal Task<LocalProvisionResult> Save(ClaimsPrincipal admin, long version, EmailDeliverySettings settings, string password)
            => Run(a => a.SaveEmailDeliveryAsync(admin, version, settings, password, Keys));

        internal async Task<IdentityAuditEntry[]> Saves(ClaimsPrincipal admin)
            => (await Run(a => a.ReadIdentityAuditAsync(admin))).Where(entry => entry.Action == SaveAction).ToArray();

        internal byte[] StoredPassword()
            => Assert.IsType<byte[]>(Sql("SELECT ProtectedPassword FROM EmailDeliveryConnection"));

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

        internal object? Sql(string statement, byte[]? password = null)
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
            if (password is not null) { command.Parameters.AddWithValue("$password", password); }
            return command.ExecuteScalar();
        }

        public async ValueTask DisposeAsync()
        {
            if (services is not null) { await services.DisposeAsync(); }
            Directory.Delete(options.Directory, recursive: true);
        }
    }
}
