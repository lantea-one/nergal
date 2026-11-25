using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises the local MFA transaction and protected application cookie against disposable SQLite state.</summary>
[SupportedOSPlatform("linux")]
public sealed class MfaStoreTests
{
    private const string Administrator = "fixture-admin";
    private const string Password = "synthetic local account password";

    /// <summary>Pending setup cannot satisfy policy or gate password sign-in until a current code activates it.</summary>
    [Fact]
    public async Task Enrollment_ActivatesOnlyAfterCurrentCode()
    {
        await using var fixture = await Fixture.Create();
        var (_, admin) = await fixture.SignIn(Administrator);
        var enrollment = await fixture.BeginEnrollment(admin);
        Assert.False(await fixture.Run(accounts => accounts.HasTotpAsync(admin)));
        var seed = DecodeKey(enrollment.ManualKey);
        var ciphertext = Assert.IsType<byte[]>(fixture.Scalar("SELECT ProtectedSeed FROM MfaActorState"));
        Assert.Equal(-1, ciphertext.AsSpan().IndexOf(seed));

        var policy = await fixture.Run(accounts => accounts.ReadMfaPolicyAsync(admin));
        Assert.Equal(MfaRequirement.Optional, policy.Requirement);
        Assert.Equal(["account.lastAdministrator"], (await fixture.SavePolicy(admin, policy.Version, MfaRequirement.Administrators)).ErrorCodes);
        Assert.Equal(policy, await fixture.Run(accounts => accounts.ReadMfaPolicyAsync(admin)));
        var wrongCode = WrongCode(seed, fixture.Clock.GetUtcNow());
        var rejected = await fixture.Run(accounts => accounts.ConfirmTotpEnrollmentAsync(admin, enrollment.Id, wrongCode, fixture.Keys));
        Assert.Equal(["mfa.enrollmentDenied"], rejected.ErrorCodes);
        Assert.False(await fixture.Run(accounts => accounts.HasTotpAsync(admin)));

        fixture.Clock.Now = fixture.Clock.Now.AddSeconds(1);
        var (setupCookie, currentAdmin) = await fixture.SignIn(Administrator);
        await fixture.ConfirmEnrollment(currentAdmin, enrollment, seed);
        Assert.Equal(1L, fixture.AuditCount("mfa.totpEnrolled"));
        Assert.Null(await fixture.Authenticate(setupCookie));
        var enrolled = await fixture.SignInWithFactor(seed);
        Assert.True(await fixture.Run(accounts => accounts.HasTotpAsync(enrolled)));
        Assert.Null(await fixture.Run(accounts => accounts.BeginTotpEnrollmentAsync(enrolled, fixture.Keys)));
    }

    /// <summary>A failed code issues no cookie and an expired proof cannot use a fresh valid code.</summary>
    [Fact]
    public async Task Continuation_BadCodeAndExpiredProofCannotSignIn()
    {
        await using var fixture = await Fixture.Create();
        var seed = await fixture.Enroll(Administrator);
        var challenge = await fixture.BeginChallenge(Administrator);
        var continuation = Assert.IsType<string>(challenge.Continuation);

        Assert.Null(await fixture.Authenticate("__Host-nergal-admin=" + continuation));
        var auditBefore = fixture.AuditCount("local.signedIn");
        Retry(challenge, await fixture.Complete(continuation, WrongCode(seed, fixture.Clock.Now)));

        // Hold an unfailed proof through its deadline so the wrong code cannot account for its rejection.
        var pending = await fixture.BeginChallenge(Administrator);
        fixture.Clock.Now = Assert.IsType<DateTimeOffset>(pending.ExpiresUtc);
        var code = CodeAt(seed, fixture.Clock.GetUtcNow());
        Denied(await fixture.Complete(Assert.IsType<string>(pending.Continuation), code));
        Assert.Equal(auditBefore, fixture.AuditCount("local.signedIn"));

        var replacement = await fixture.BeginChallenge(Administrator);
        var completed = await fixture.Complete(Assert.IsType<string>(replacement.Continuation), code);
        await fixture.RequireAdministratorCookie(completed);
    }

    /// <summary>Replacing the continuation cannot replenish the actor's factor-attempt budget.</summary>
    [Fact]
    public async Task Continuation_ProofAndActorAttemptBudgetsSurviveNewPasswordProof()
    {
        await using var fixture = await Fixture.Create();
        var seed = await fixture.Enroll(Administrator);
        var wrong = WrongCode(seed, fixture.Clock.Now);
        var first = await fixture.BeginChallenge(Administrator);
        var firstToken = Assert.IsType<string>(first.Continuation);
        Retry(first, await fixture.Complete(firstToken, wrong));
        Retry(first, await fixture.Complete(firstToken, wrong));
        Denied(await fixture.Complete(firstToken, wrong));
        Denied(await fixture.Complete(firstToken, CodeAt(seed, fixture.Clock.Now)));

        var second = await fixture.BeginChallenge(Administrator);
        var secondToken = Assert.IsType<string>(second.Continuation);
        Retry(second, await fixture.Complete(secondToken, wrong));
        Denied(await fixture.Complete(secondToken, wrong));
        Denied(await fixture.Begin(Administrator));

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(15);
        await fixture.SignInWithFactor(seed);
    }

    /// <summary>Concurrent completion consumes a proof exactly once and replay remains denied after services reopen.</summary>
    [Fact]
    public async Task Continuation_ConcurrentCompletionAndReplayIssueOneCookie()
    {
        await using var fixture = await Fixture.Create();
        var seed = await fixture.Enroll(Administrator);
        var challenge = await fixture.BeginChallenge(Administrator);
        var continuation = Assert.IsType<string>(challenge.Continuation);
        var code = CodeAt(seed, fixture.Clock.GetUtcNow());
        var auditBefore = fixture.AuditCount("local.signedIn");
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<(MfaSignInResult Result, string[] SetCookies)> Attempt() => Task.Run(async () =>
        {
            await ready.Task;
            return await fixture.Complete(continuation, code);
        }, TestContext.Current.CancellationToken);
        var first = Attempt();
        var second = Attempt();
        ready.SetResult();

        var results = await Task.WhenAll(first, second);
        var winner = Assert.Single(results, attempt => attempt.Result.Status == MfaSignInStatus.SignedIn);
        Denied(Assert.Single(results, attempt => attempt.Result.Status != MfaSignInStatus.SignedIn));
        Assert.Equal(auditBefore + 1, fixture.AuditCount("local.signedIn"));
        var (cookie, _) = await fixture.RequireAdministratorCookie(winner);

        await fixture.RestartServices();
        Assert.NotNull(await fixture.Authenticate(cookie));
        Denied(await fixture.Complete(continuation, code));

        // Open a different proof in the same TOTP step. The used code is denied there as well.
        fixture.Clock.Now = fixture.Clock.Now.AddSeconds(1);
        var replacement = await fixture.BeginChallenge(Administrator);
        Assert.NotEqual(continuation, replacement.Continuation);
        Retry(replacement, await fixture.Complete(Assert.IsType<string>(replacement.Continuation), code));
    }

    /// <summary>An audit failure rolls back proof consumption and code acceptance, so the same request can retry.</summary>
    [Fact]
    public async Task Continuation_AuditFailureRollsBackCompletionBeforeCookie()
    {
        await using var fixture = await Fixture.Create();
        var seed = await fixture.Enroll(Administrator);
        var first = await fixture.BeginChallenge(Administrator);
        var (previousCookie, _) = await fixture.RequireAdministratorCookie(
            await fixture.Complete(Assert.IsType<string>(first.Continuation), CodeAt(seed, fixture.Clock.Now)));
        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        var challenge = await fixture.BeginChallenge(Administrator);
        var continuation = Assert.IsType<string>(challenge.Continuation);
        var code = CodeAt(seed, fixture.Clock.GetUtcNow());
        var auditBefore = fixture.AuditCount();
        fixture.Scalar("""
            CREATE TRIGGER fixture_mfa_audit_failure BEFORE INSERT ON IdentityAudit
            WHEN NEW.Action = 'local.signedIn'
            BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END
            """);

        var failed = await fixture.Request((accounts, _) =>
            Assert.ThrowsAsync<AccountStoreException>(() => accounts.CompleteMfaSignInAsync(continuation, code, fixture.Keys,
                TestContext.Current.CancellationToken)));
        Assert.Equal("account.databaseError", failed.Result.Code);
        Assert.Empty(failed.SetCookies);
        Assert.Equal(auditBefore, fixture.AuditCount());
        Assert.NotNull(await fixture.Authenticate(previousCookie));

        fixture.Scalar("DROP TRIGGER fixture_mfa_audit_failure");
        await fixture.RequireAdministratorCookie(await fixture.Complete(continuation, code));
        Assert.Equal(auditBefore + 1, fixture.AuditCount());
        Assert.Null(await fixture.Authenticate(previousCookie));
        Denied(await fixture.Complete(continuation, code));
    }

    /// <summary>A policy generation change invalidates previously issued cookies and outstanding proofs.</summary>
    [Fact]
    public async Task PolicyChange_RevokesOldCookieAndPendingProof()
    {
        const string auditor = "fixture-auditor";
        await using var fixture = await Fixture.Create();
        var (_, setupAdmin) = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Run(accounts => accounts.CreateUserAsync(setupAdmin, auditor, Password, NergalRoles.Auditor))).Succeeded);
        var (oldCookie, _) = await fixture.SignIn(auditor);
        var seed = await fixture.Enroll(Administrator);
        var challenge = await fixture.BeginChallenge(Administrator);
        var (adminCookie, _) = await fixture.RequireAdministratorCookie(await fixture.Complete(
            Assert.IsType<string>(challenge.Continuation), CodeAt(seed, fixture.Clock.GetUtcNow())));
        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        var pending = await fixture.BeginChallenge(Administrator);
        var admin = Assert.IsType<ClaimsPrincipal>(await fixture.Authenticate(adminCookie));
        Assert.NotNull(await fixture.Authenticate(oldCookie));

        var original = await fixture.Run(accounts => accounts.ReadMfaPolicyAsync(admin));
        Assert.True((await fixture.SavePolicy(admin, original.Version, MfaRequirement.Administrators)).Succeeded);
        Assert.Null(await fixture.Authenticate(oldCookie));
        Assert.Null(await fixture.Authenticate(adminCookie));
        var staleActor = await Assert.ThrowsAsync<AccountStoreException>(() => fixture.SavePolicy(admin, original.Version + 1, MfaRequirement.All));
        Assert.Equal("account.denied", staleActor.Code);
        var code = CodeAt(seed, fixture.Clock.GetUtcNow());
        Denied(await fixture.Complete(Assert.IsType<string>(pending.Continuation), code));

        var current = await fixture.BeginChallenge(Administrator);
        var (_, currentAdmin) = await fixture.RequireAdministratorCookie(
            await fixture.Complete(Assert.IsType<string>(current.Continuation), code));
        Assert.Equal(new MfaPolicySnapshot(original.Version + 1, MfaRequirement.Administrators),
            await fixture.Run(accounts => accounts.ReadMfaPolicyAsync(currentAdmin)));
        Assert.Equal(["mfa.stale"], (await fixture.SavePolicy(currentAdmin, original.Version, MfaRequirement.All)).ErrorCodes);
        await fixture.SignIn(auditor);
    }

    /// <summary>A second enabled Administrator without TOTP cannot replace the last administrator eligible to recover.</summary>
    [Theory]
    [InlineData(NergalRoles.Auditor, true)]
    [InlineData(NergalRoles.Administrator, false)]
    public async Task EnforcedPolicy_PreservesLastEligibleLocalAdministrator(string newRole, bool enabled)
    {
        const string otherAdmin = "fixture-unenrolled-admin";
        await using var fixture = await Fixture.Create();
        var (_, setupAdmin) = await fixture.SignIn(Administrator);
        Assert.True((await fixture.Run(accounts => accounts.CreateUserAsync(setupAdmin, otherAdmin, Password, NergalRoles.Administrator))).Succeeded);
        var seed = await fixture.Enroll(Administrator);
        var admin = await fixture.SignInWithFactor(seed);
        var policy = await fixture.Run(accounts => accounts.ReadMfaPolicyAsync(admin));
        Assert.True((await fixture.SavePolicy(admin, policy.Version, MfaRequirement.All)).Succeeded);
        Denied(await fixture.Begin(otherAdmin));

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        admin = await fixture.SignInWithFactor(seed);
        var users = await fixture.Run(accounts => accounts.ListUsersAsync(admin));
        var target = Assert.Single(users, user => user.UserName == Administrator);
        var auditBefore = fixture.AuditCount();
        var rejected = await fixture.Run(accounts => accounts.UpdateUserAsync(admin, target.Id, target.Version, newRole, enabled, fixture.Keys));
        Assert.Equal(["account.lastAdministrator"], rejected.ErrorCodes);
        Assert.Equal(auditBefore, fixture.AuditCount());
        Assert.Equal(target, Assert.Single(await fixture.Run(accounts => accounts.ListUsersAsync(admin)), user => user.Id == target.Id));
    }

    private static void Denied((MfaSignInResult Result, string[] SetCookies) attempt)
    {
        Assert.Equal(MfaSignInStatus.Denied, attempt.Result.Status);
        Assert.Null(attempt.Result.Continuation);
        Assert.Empty(attempt.SetCookies);
    }

    private static void Retry(MfaSignInResult original, (MfaSignInResult Result, string[] SetCookies) attempt)
    {
        Assert.Equal(original, attempt.Result);
        Assert.Empty(attempt.SetCookies);
    }

    // Model the authenticator from its displayed Base32 key without calling the store's validator.
    private static byte[] DecodeKey(string manualKey)
    {
        Assert.Matches("^[A-Z2-7]{32}$", manualKey);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var seed = new byte[20];
        var buffer = 0;
        var bits = 0;
        var index = 0;
        foreach (var character in manualKey)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character);
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                seed[index++] = (byte)(buffer >> bits);
            }
        }
        return seed;
    }

    private static string CodeAt(byte[] seed, DateTimeOffset at)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, at.ToUnixTimeSeconds() / 30);
        var digest = HMACSHA1.HashData(seed, counter);
        var value = BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(digest[^1] & 15)) & 0x7fff_ffff;
        return (value % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private static string WrongCode(byte[] seed, DateTimeOffset now)
    {
        string[] acceptedWindow = [CodeAt(seed, now.AddSeconds(-30)), CodeAt(seed, now), CodeAt(seed, now.AddSeconds(30))];
        return new[] { "000000", "000001", "000002", "000003" }.First(code => !acceptedWindow.Contains(code));
    }

    private sealed class FixtureClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Fixture(string directory, ProtectedSessionKeyRing keys) : IAsyncDisposable
    {
        private readonly LocalAccountOptions options = new(directory);
        private ServiceProvider services = null!;
        internal FixtureClock Clock { get; } = new();
        internal ProtectedSessionKeyRing Keys => keys;

        internal static async Task<Fixture> Create()
        {
            var path = Path.Combine(Path.GetTempPath(), "nergal-mfa-store-" + Guid.NewGuid().ToString("N"));
            const UnixFileMode directoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(path, directoryMode);
            ProtectedSessionKeyRing? ring = null;
            Fixture? fixture = null;
            try
            {
                var keyDirectory = Path.Combine(path, "keys");
                Directory.CreateDirectory(keyDirectory, directoryMode);
                using var rsa = RSA.Create(3072);
                var request = new CertificateRequest("CN=synthetic-mfa-store", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var now = DateTimeOffset.UtcNow;
                using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
                ring = ProtectedSessionKeyRing.Open(new(keyDirectory), certificate);
                fixture = new Fixture(path, ring);
                fixture.services = fixture.StartServices();
                await LocalAccountDatabase.InitializeAsync(fixture.options);
                Assert.True((await fixture.Run(accounts => accounts.ProvisionAsync(Administrator, Password))).Succeeded);
                return fixture;
            }
            catch
            {
                if (fixture?.services is { } active) { await active.DisposeAsync(); }
                ring?.Dispose();
                Directory.Delete(path, recursive: true);
                throw;
            }
        }

        private ServiceProvider StartServices()
        {
            var collection = new ServiceCollection();
            collection.AddSingleton<TimeProvider>(Clock);
            collection.AddLocalAdministratorAccounts(options).AddLocalAdministratorSessions(Keys);
            collection.Configure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options => options.TimeProvider = Clock);
            return collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        }

        internal async Task RestartServices()
        {
            await services.DisposeAsync();
            services = StartServices();
        }

        internal async Task<T> Run<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
            => (await Request((accounts, _) => operation(accounts))).Result;

        internal async Task<(T Result, string[] SetCookies)> Request<T>(
            Func<LocalAdministratorAccounts, HttpContext, Task<T>> operation, string? cookie = null)
        {
            await using var scope = services.CreateAsyncScope();
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            http.Request.Scheme = "https";
            if (cookie is not null) { http.Request.Headers.Cookie = cookie; }
            var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
            accessor.HttpContext = http;
            try
            {
                var result = await operation(scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>(), http);
                return (result, http.Response.Headers.SetCookie.Select(value => value!).ToArray());
            }
            finally { accessor.HttpContext = null; }
        }

        internal async Task<ClaimsPrincipal?> Authenticate(string cookie)
        {
            var (result, _) = await Request((_, http) => http.AuthenticateAsync(IdentityConstants.ApplicationScheme), cookie);
            return result.Succeeded ? result.Principal : null;
        }

        internal Task<(MfaSignInResult Result, string[] SetCookies)> Begin(string username)
            => Request((accounts, _) => accounts.BeginLocalSignInAsync(username, Password, Keys));

        internal Task<(MfaSignInResult Result, string[] SetCookies)> Complete(string continuation, string code)
            => Request((accounts, _) => accounts.CompleteMfaSignInAsync(continuation, code, Keys));

        internal async Task<MfaSignInResult> BeginChallenge(string username)
        {
            var (result, cookies) = await Begin(username);
            Assert.Equal(MfaSignInStatus.Challenge, result.Status);
            Assert.NotEmpty(Assert.IsType<string>(result.Continuation));
            Assert.Empty(cookies);
            return result;
        }

        private static string SessionCookie((MfaSignInResult Result, string[] SetCookies) response)
        {
            Assert.Equal(MfaSignInStatus.SignedIn, response.Result.Status);
            Assert.Null(response.Result.Continuation);
            var cookie = Assert.Single(response.SetCookies).Split(';', 2)[0];
            Assert.StartsWith("__Host-nergal-admin=", cookie);
            return cookie;
        }

        internal async Task<(string Cookie, ClaimsPrincipal Principal)> SignIn(string username)
        {
            var cookie = SessionCookie(await Begin(username));
            var principal = Assert.IsType<ClaimsPrincipal>(await Authenticate(cookie));
            Assert.Equal(username, principal.Identity?.Name);
            return (cookie, principal);
        }

        internal async Task<(string Cookie, ClaimsPrincipal Principal)> RequireAdministratorCookie(
            (MfaSignInResult Result, string[] SetCookies) response)
        {
            var cookie = SessionCookie(response);
            var principal = Assert.IsType<ClaimsPrincipal>(await Authenticate(cookie));
            Assert.Equal(Administrator, principal.Identity?.Name);
            Assert.True(principal.IsInRole(NergalRoles.Administrator));
            return (cookie, principal);
        }

        internal async Task<ClaimsPrincipal> SignInWithFactor(byte[] seed)
        {
            var challenge = await BeginChallenge(Administrator);
            var completed = await Complete(Assert.IsType<string>(challenge.Continuation), CodeAt(seed, Clock.Now));
            var (_, principal) = await RequireAdministratorCookie(completed);
            return principal;
        }

        internal async Task<TotpEnrollment> BeginEnrollment(ClaimsPrincipal principal)
            => Assert.IsType<TotpEnrollment>(await Run(accounts => accounts.BeginTotpEnrollmentAsync(principal, Keys)));

        internal async Task ConfirmEnrollment(ClaimsPrincipal principal, TotpEnrollment enrollment, byte[] seed)
        {
            Assert.True((await Run(accounts => accounts.ConfirmTotpEnrollmentAsync(principal, enrollment.Id, CodeAt(seed, Clock.Now), Keys))).Succeeded);
            Clock.Now = Clock.Now.AddMinutes(1);
        }

        internal async Task<byte[]> Enroll(string username)
        {
            var (_, principal) = await SignIn(username);
            var enrollment = await BeginEnrollment(principal);
            var seed = DecodeKey(enrollment.ManualKey);
            await ConfirmEnrollment(principal, enrollment, seed);
            return seed;
        }

        internal Task<LocalProvisionResult> SavePolicy(ClaimsPrincipal principal, long version, MfaRequirement requirement)
            => Run(accounts => accounts.SaveMfaPolicyAsync(principal, version, requirement, Keys));

        internal long AuditCount(string? action = null) => Assert.IsType<long>(action is null
            ? Scalar("SELECT count(*) FROM IdentityAudit")
            : Scalar("SELECT count(*) FROM IdentityAudit WHERE Action = $action", action));

        internal object? Scalar(string statement, string? action = null)
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
            if (action is not null) { command.Parameters.AddWithValue("$action", action); }
            return command.ExecuteScalar();
        }

        public async ValueTask DisposeAsync()
        {
            try { await services.DisposeAsync(); }
            finally
            {
                Keys.Dispose();
                Directory.Delete(options.Directory, recursive: true);
            }
        }
    }
}
