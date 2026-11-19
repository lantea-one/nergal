using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication;
using Nergal.Identity;

namespace Nergal.LocalState.Tests;

/// <summary>Exercises real Identity hashing, SQLite reservations, lockout and private files with synthetic application accounts only.</summary>
[SupportedOSPlatform("linux")]
public sealed class LocalAdministratorAccountTests
{
    private const string Name = "fixture-admin";
    private const string Password = "synthetic fixture password 0001";
    private const string Incorrect = "synthetic incorrect password 0002";

    /// <summary>Configuration neither creates state nor registers a browser login handler, and conflicting stores are rejected.</summary>
    [Fact]
    public async Task Configuration_IsExplicitAndIssuesNoBrowserSession()
    {
        Assert.Throws<ArgumentException>(() => new LocalAccountOptions("relative"));
        Assert.Throws<ArgumentException>(() => new LocalAccountOptions("/tmp/bad\0path"));
        await using var fixture = await Fixture.Create(initialize: false);
        Assert.False(File.Exists(fixture.Database));
        Assert.Empty(await fixture.Services.GetRequiredService<IAuthenticationSchemeProvider>().GetAllSchemesAsync());
        var services = new ServiceCollection().AddLocalAdministratorAccounts(fixture.Options);
        Assert.Throws<InvalidOperationException>(() => services.AddLocalAdministratorAccounts(fixture.Options));
    }

    /// <summary>Initialization creates no default account; provisioning is explicit, singleton and persistently hashed.</summary>
    [Fact]
    public async Task Provisioning_IsExplicitSingletonAndSurvivesReopen()
    {
        await using var fixture = await Fixture.Create();
        AssertDenied(await fixture.Verify(Name, Password));
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        var signedIn = await fixture.Verify(Name.ToUpperInvariant(), Password);
        Assert.True(signedIn.Succeeded);
        Assert.NotNull(signedIn.AdministratorId);
        Assert.Equal(["account.exists"], (await fixture.Provision("other-fixture", Password)).ErrorCodes);
        Assert.Equal(signedIn.AdministratorId, (await fixture.Verify(Name, Password, reopen: true)).AdministratorId);
        foreach (var file in Directory.EnumerateFiles(fixture.Path))
        {
            Assert.DoesNotContain(Password, Encoding.Latin1.GetString(File.ReadAllBytes(file)));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        }
        // The database itself, not just the provisioning count check, rejects another administrator.
        var denied = Assert.Throws<SqliteException>(() => fixture.Sql("INSERT INTO AspNetUsers (Id,EmailConfirmed,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEnabled,AccessFailedCount) VALUES('second-fixture',0,0,0,1,0)"));
        Assert.Equal(19, denied.SqliteErrorCode);
    }

    /// <summary>Unknown, wrong and locked-out credentials expose the same result, and failure/reset accounting persists.</summary>
    [Fact]
    public async Task Verification_PersistsLockoutAndResetsFailuresAfterSuccess()
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        AssertDenied(await fixture.Verify("absent-fixture", Password));
        for (var attempt = 0; attempt < 2; attempt++) { AssertDenied(await fixture.Verify(Name, Incorrect)); }
        Assert.True((await fixture.Verify(Name, Password)).Succeeded);
        for (var attempt = 0; attempt < 4; attempt++) { AssertDenied(await fixture.Verify(Name, Incorrect)); }
        Assert.True((await fixture.Verify(Name, Password)).Succeeded);
        for (var attempt = 0; attempt < 5; attempt++) { AssertDenied(await fixture.Verify(Name, Incorrect)); }
        AssertDenied(await fixture.Verify(Name, Password, reopen: true));
        AssertDenied(await fixture.Verify(Name, Incorrect));
        // A persisted deadline in the past exercises expiry without a timing sleep.
        fixture.Sql("UPDATE AspNetUsers SET LockoutEnd='2000-01-01 00:00:00+00:00'");
        Assert.True((await fixture.Verify(Name, Password, reopen: true)).Succeeded);
    }

    /// <summary>Concurrent callers cannot lose failed-attempt increments and bypass the singleton account's lockout.</summary>
    [Fact]
    public async Task Verification_ConcurrentFailuresAreSerialized()
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        var failures = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => Task.Run(() => fixture.Verify(Name, Incorrect))));
        Assert.All(failures, AssertDenied);
        AssertDenied(await fixture.Verify(Name, Password));
    }

    /// <summary>Concurrent provisioning cannot create competing initial administrators or overwrite the winning credential.</summary>
    [Fact]
    public async Task Provisioning_ConcurrentBootstrapHasOneWinner()
    {
        await using var fixture = await Fixture.Create();
        var results = await Task.WhenAll(
            Task.Run(() => fixture.Provision("fixture-one", Password)),
            Task.Run(() => fixture.Provision("fixture-two", Incorrect)));
        Assert.Single(results, result => result.Succeeded);
        Assert.Equal(["account.exists"], Assert.Single(results, result => !result.Succeeded).ErrorCodes);
        Assert.Equal(results[0].Succeeded, (await fixture.Verify("fixture-one", Password)).Succeeded);
        Assert.Equal(results[1].Succeeded, (await fixture.Verify("fixture-two", Incorrect)).Succeeded);
    }

    /// <summary>Passwords use explicit Unicode scalar bounds without composition rules or normalization.</summary>
    [Theory]
    [InlineData("too short")]
    [InlineData("")]
    public async Task Provisioning_RejectsWeakBoundsWithoutCreatingAccount(string password)
    {
        await using var fixture = await Fixture.Create();
        Assert.Equal(["password.bounds"], (await fixture.Provision(Name, password)).ErrorCodes);
        Assert.True((await fixture.Provision(Name, new string('a', 15))).Succeeded);
    }

    /// <summary>Malformed Unicode and oversized credentials never enter hashing/storage; a valid non-ASCII password remains exact.</summary>
    [Fact]
    public async Task Provisioning_EnforcesExactUnicodeAndMaximumBounds()
    {
        await using var fixture = await Fixture.Create();
        foreach (var invalid in new[] { new string('a', 129), new string('a', 14) + '\ud800', string.Concat(Enumerable.Repeat("\U0001f512", 14)) })
        {
            Assert.Equal(["password.bounds"], (await fixture.Provision(Name, invalid)).ErrorCodes);
        }
        var unicode = string.Concat(Enumerable.Repeat("\U0001f512", 15));
        Assert.True((await fixture.Provision(Name, unicode)).Succeeded);
        Assert.True((await fixture.Verify(Name, unicode)).Succeeded);
        AssertDenied(await fixture.Verify(Name, new string('a', 5000)));
        AssertDenied(await fixture.Verify(Name, new string('a', 14) + '\ud800'));
    }

    /// <summary>Unicode-equivalent strings are not silently normalized into the same password.</summary>
    [Fact]
    public async Task Verification_PreservesExactPasswordRepresentation()
    {
        await using var fixture = await Fixture.Create();
        const string original = "synthetic \u00e9 fixture password";
        Assert.True((await fixture.Provision(Name, original)).Succeeded);
        Assert.True((await fixture.Verify(Name, original)).Succeeded);
        AssertDenied(await fixture.Verify(Name, original.Normalize(NormalizationForm.FormD)));
    }

    /// <summary>Untrusted identifier text cannot become SQL or a different account, and invalid input is not reflected in diagnostics.</summary>
    [Theory]
    [InlineData("bad name")]
    [InlineData("' OR 1=1 --")]
    [InlineData("")]
    public async Task Provisioning_RejectsUnsupportedUserNames(string name)
    {
        await using var fixture = await Fixture.Create();
        Assert.Equal(["account.userName"], (await fixture.Provision(name, Password)).ErrorCodes);
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        AssertDenied(await fixture.Verify(name, Password));
    }

    /// <summary>Normal operations never create/adopt a missing, unrelated or incomplete account schema.</summary>
    [Fact]
    public async Task Storage_RefusesMissingOrForeignDatabaseWithoutRepair()
    {
        await using var fixture = await Fixture.Create(initialize: false);
        await Reject("account.databaseMissing", () => fixture.Verify(Name, Password));
        Assert.False(File.Exists(fixture.Database));
        using (var file = new FileStream(fixture.Database, new FileStreamOptions
        { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite })) { }
        var before = File.ReadAllBytes(fixture.Database);
        await Reject("account.schemaOrIntegrity", () => fixture.Verify(Name, Password));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
        await Reject("account.exists", () => LocalAccountDatabase.InitializeAsync(fixture.Options));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>Unsafe modes, shared inodes and symlinks are rejected before credential database access.</summary>
    [Fact]
    public async Task Storage_RejectsUnsafeFilesWithoutChangingCredentials()
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        var before = File.ReadAllBytes(fixture.Database);
        File.SetUnixFileMode(fixture.Database, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        await Reject("path.mode", () => fixture.Verify(Name, Password));
        File.SetUnixFileMode(fixture.Database, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var alias = fixture.Database + ".alias";
        Assert.Equal(0, link(fixture.Database, alias));
        await Reject("path.hardLink", () => fixture.Verify(Name, Password));
        File.Delete(alias);
        var saved = fixture.Database + ".saved";
        File.Move(fixture.Database, saved);
        File.CreateSymbolicLink(fixture.Database, saved);
        await Reject("path.symlink", () => fixture.Verify(Name, Password));
        File.Delete(fixture.Database);
        File.Move(saved, fixture.Database);
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
        Assert.True((await fixture.Verify(Name, Password)).Succeeded);
    }

    /// <summary>Unexpected account schema identity/version is never silently migrated, even when the credential itself is valid.</summary>
    [Theory]
    [InlineData("PRAGMA user_version=2")]
    [InlineData("PRAGMA application_id=0x4e52474c")]
    public async Task Storage_RefusesUnknownSchemaIdentityOrVersion(string damage)
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        fixture.Sql(damage);
        var before = File.ReadAllBytes(fixture.Database);
        await Reject("account.schemaOrIntegrity", () => fixture.Verify(Name, Password));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    /// <summary>A malformed stored administrator identifier never becomes a successful credential result.</summary>
    [Theory]
    [InlineData("invalid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    public async Task Verification_RefusesCorruptAdministratorIdentifier(string identifier)
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        fixture.Sql("UPDATE AspNetUsers SET Id=$id", ("$id", identifier));
        await Reject("account.corrupt", () => fixture.Verify(Name, Password));
    }

    /// <summary>Unsupported security state cannot silently disable lockout or turn password verification into a two-factor bypass.</summary>
    [Theory]
    [InlineData("UPDATE AspNetUsers SET LockoutEnabled=0")]
    [InlineData("UPDATE AspNetUsers SET TwoFactorEnabled=1")]
    public async Task Verification_RefusesUnsupportedSecurityState(string damage)
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        fixture.Sql(damage);
        await Reject("account.unsupportedState", () => fixture.Verify(Name, Password));
    }

    /// <summary>Malformed persisted hashes are a stable storage failure, never a leaked framework exception or successful credential result.</summary>
    [Fact]
    public async Task Verification_RejectsMalformedStoredHash()
    {
        await using var fixture = await Fixture.Create();
        Assert.True((await fixture.Provision(Name, Password)).Succeeded);
        fixture.Sql("UPDATE AspNetUsers SET PasswordHash='malformed-not-base64'");
        await Reject("account.corrupt", () => fixture.Verify(Name, Password));
    }

    /// <summary>Cancellation before reservation neither creates an account nor mutates protected state.</summary>
    [Fact]
    public async Task Credentials_PreCanceledRequestsLeaveStoreUnchanged()
    {
        await using var fixture = await Fixture.Create();
        var before = File.ReadAllBytes(fixture.Database);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        using var scope = fixture.Services.CreateScope();
        var accounts = scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accounts.ProvisionAsync(Name, Password, canceled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accounts.VerifyAsync(Name, Password, canceled.Token));
        Assert.Equal(before, File.ReadAllBytes(fixture.Database));
    }

    private static void AssertDenied(LocalCredentialResult result)
    { Assert.False(result.Succeeded); Assert.Null(result.AdministratorId); }
    private static async Task Reject(string code, Func<Task> action)
        => Assert.Equal(code, (await Assert.ThrowsAsync<AccountStoreException>(action)).Code);
    [DllImport("libc", SetLastError = true)]
    private static extern int link(string existing, string newPath);

    private sealed class Fixture : IAsyncDisposable
    {
        internal string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nergal-accounts-" + Guid.NewGuid().ToString("N"));
        internal string Database => System.IO.Path.Combine(Path, "accounts.db");
        internal LocalAccountOptions Options { get; }
        internal ServiceProvider Services { get; }
        private Fixture()
        {
            Directory.CreateDirectory(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Options = new(Path);
            Services = Build();
        }
        private ServiceProvider Build() => new ServiceCollection().AddLocalAdministratorAccounts(Options)
            .BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        internal static async Task<Fixture> Create(bool initialize = true)
        {
            var fixture = new Fixture();
            try { if (initialize) { await LocalAccountDatabase.InitializeAsync(fixture.Options); } return fixture; }
            catch { await fixture.DisposeAsync(); throw; }
        }
        internal async Task<LocalProvisionResult> Provision(string name, string password)
        {
            using var scope = Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().ProvisionAsync(name, password);
        }
        internal async Task<LocalCredentialResult> Verify(string name, string password, bool reopen = false)
        {
            using var fresh = reopen ? Build() : null;
            using var scope = (fresh ?? Services).CreateScope();
            return await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().VerifyAsync(name, password);
        }
        internal void Sql(string text, params (string Name, object Value)[] parameters)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = text;
            foreach (var parameter in parameters) { command.Parameters.AddWithValue(parameter.Name, parameter.Value); }
            command.ExecuteNonQuery();
        }
        public async ValueTask DisposeAsync() { await Services.DisposeAsync(); Directory.Delete(Path, true); }
    }
}
