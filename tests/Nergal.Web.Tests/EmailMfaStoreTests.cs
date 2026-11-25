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

/// <summary>Verifies email enrollment and sign-in against the durable account store without a mail server.</summary>
[SupportedOSPlatform("linux")]
public sealed class EmailMfaStoreTests
{
    private const string Administrator = "fixture-admin";
    private const string Auditor = "fixture-auditor";
    private const string Password = "synthetic local account password";
    private const string Address = "delivery@example.test";
    private static readonly EmailDeliverySettings Relay = new(true, "smtp.example.test", 587, "nergal@example.test", "");

    /// <summary>Profile mail never gates sign-in. A verified delivery mailbox gates it and each proof has one winner.</summary>
    [Fact]
    public async Task VerifiedAddressIsSeparateFromProfileAndCompletionIsSingleUse()
    {
        await using var fixture = await Fixture.Create();
        var (_, admin) = await fixture.SignIn(Administrator);
        await fixture.SaveDelivery(admin, 0);
        Assert.True((await fixture.Run(accounts => accounts.CreateUserAsync(admin, Auditor, Password, NergalRoles.Auditor))).Succeeded);
        var (_, initialAuditor) = await fixture.SignIn(Auditor);
        Assert.True((await fixture.Run(accounts => accounts.SaveProfileAsync(initialAuditor, 0,
            new ProfileMetadata(Email: "profile@example.test")))).Succeeded);
        var (oldCookie, auditor) = await fixture.SignIn(Auditor);
        var observedReservations = new List<long>();
        var sender = new CapturingSender(_ => observedReservations.Add(fixture.Scalar("SELECT count(*) FROM EmailMfaCode")));
        var enrollment = Assert.IsType<EmailMfaEnrollment>(await fixture.Enroll(auditor, sender));
        var setupMail = Assert.Single(sender.Deliveries);
        Assert.Equal(Address, setupMail.Address);
        Assert.Equal(1L, setupMail.Generation);
        Assert.DoesNotContain(Address, setupMail.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(setupMail.Code, setupMail.ToString(), StringComparison.Ordinal);
        Assert.False((await fixture.Run(accounts => accounts.ReadEmailMfaEnrollmentAsync(auditor))).Enrolled);
        Assert.False((await fixture.Confirm(auditor, enrollment, WrongCode(setupMail))).Succeeded);
        Assert.True((await fixture.Confirm(auditor, enrollment, setupMail.Code)).Succeeded);
        Assert.Null(await fixture.Authenticate(oldCookie));

        var (challenge, headers) = await fixture.Begin(Auditor, sender);
        Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
        Assert.Empty(headers);
        var continuation = Assert.IsType<string>(challenge.Continuation);
        var signInMail = sender.Deliveries[1];
        Assert.Equal(Address, signInMail.Address);

        Assert.Equal([1L, 1L], observedReservations);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<(MfaSignInResult Result, string[] Cookies)> Attempt() => Task.Run(async () =>
        {
            await ready.Task;
            return await fixture.Complete(continuation, signInMail.Code);
        }, TestContext.Current.CancellationToken);
        var first = Attempt();
        var second = Attempt();
        ready.SetResult();
        var outcomes = await Task.WhenAll(first, second);
        Assert.Single(outcomes, outcome => outcome.Result.Status == MfaSignInStatus.SignedIn && outcome.Cookies.Length == 1);
        Assert.Single(outcomes, outcome => outcome.Result.Status == MfaSignInStatus.Denied && outcome.Cookies.Length == 0);
        Assert.Equal(MfaSignInStatus.Denied, (await fixture.Complete(continuation, signInMail.Code)).Result.Status);
        Assert.Equal(0L, fixture.Scalar("SELECT count(*) FROM EmailMfaCode"));
    }

    /// <summary>Changing relay generation retires previously sent codes and fresh reservations still share the original send budget.</summary>
    [Fact]
    public async Task DeliveryRotationRetiresCodesAndKeepsTheSharedSendBudget()
    {
        await using var fixture = await Fixture.Create();
        var (_, admin) = await fixture.SignIn(Administrator);
        await fixture.SaveDelivery(admin, 0);
        Assert.True((await fixture.Run(accounts => accounts.CreateUserAsync(admin, Auditor, Password, NergalRoles.Auditor))).Succeeded);
        var (_, auditor) = await fixture.SignIn(Auditor);
        var sender = new CapturingSender();
        var enrollment = Assert.IsType<EmailMfaEnrollment>(await fixture.Enroll(auditor, sender));
        await fixture.SaveDelivery(admin, 1);
        Assert.False((await fixture.Confirm(auditor, enrollment, sender.Deliveries[0].Code)).Succeeded);

        var replacement = Assert.IsType<EmailMfaEnrollment>(await fixture.Enroll(auditor, sender));
        Assert.Equal(2L, sender.Deliveries[1].Generation);
        Assert.True((await fixture.Confirm(auditor, replacement, sender.Deliveries[1].Code)).Succeeded);
        var (challenge, _) = await fixture.Begin(Auditor, sender);
        var continuation = Assert.IsType<string>(challenge.Continuation);
        Assert.Equal(3, sender.Deliveries.Count);
        await fixture.SaveDelivery(admin, 2);
        Assert.Equal(MfaSignInStatus.Denied, (await fixture.Complete(continuation, sender.Deliveries[2].Code)).Result.Status);
        Assert.Equal(MfaSignInStatus.Denied, (await fixture.Begin(Auditor, sender)).Result.Status);
        Assert.Equal(3, sender.Deliveries.Count);

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(15);
        var (fresh, _) = await fixture.Begin(Auditor, sender);
        fixture.Clock.Now = Assert.IsType<DateTimeOffset>(fresh.ExpiresUtc);
        Assert.Equal(3L, sender.Deliveries[3].Generation);
        Assert.Equal(MfaSignInStatus.Denied, (await fixture.Complete(Assert.IsType<string>(fresh.Continuation),
            sender.Deliveries[3].Code)).Result.Status);
    }

    /// <summary>There must always be a local Administrator who can sign in during a mail outage.</summary>
    [Fact]
    public async Task SoleAdministratorCannotEnrollAnEmailOnlyFactor()
    {
        await using var fixture = await Fixture.Create();
        var (_, admin) = await fixture.SignIn(Administrator);
        await fixture.SaveDelivery(admin, 0);
        var sender = new CapturingSender();
        Assert.Null(await fixture.Enroll(admin, sender));
        Assert.Empty(sender.Deliveries);
        Assert.Equal(MfaSignInStatus.SignedIn, (await fixture.Begin(Administrator, sender)).Result.Status);
    }

    /// <summary>When both factors are enrolled, starting and completing TOTP does not depend on SMTP.</summary>
    [Fact]
    public async Task EnrolledAuthenticatorStaysPreferredAfterEmailVerification()
    {
        await using var fixture = await Fixture.Create();
        var (_, initialAdmin) = await fixture.SignIn(Administrator);
        await fixture.SaveDelivery(initialAdmin, 0);
        var totp = await fixture.EnrollAuthenticator(initialAdmin);

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        var (_, admin) = await fixture.CompleteAuthenticator(totp);
        var sender = new CapturingSender();
        var enrollment = Assert.IsType<EmailMfaEnrollment>(await fixture.Enroll(admin, sender));
        Assert.True((await fixture.Confirm(admin, enrollment, Assert.Single(sender.Deliveries).Code)).Succeeded);

        fixture.Clock.Now = fixture.Clock.Now.AddMinutes(1);
        var (_, afterEnrollment) = await fixture.CompleteAuthenticator(totp, sender);
        Assert.True((await fixture.Run(accounts => accounts.ReadEmailMfaEnrollmentAsync(afterEnrollment))).Enrolled);
        Assert.Single(sender.Deliveries);
    }

    private static string WrongCode(EmailMfaDelivery delivery) => delivery.Code == "000000" ? "000001" : "000000";

    // Model the authenticator independently from the verification code in Identity.
    private static string AuthenticatorCode(TotpEnrollment enrollment, DateTimeOffset now)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        Span<byte> seed = stackalloc byte[20];
        var bits = 0;
        var buffer = 0;
        var index = 0;
        foreach (var character in enrollment.ManualKey)
        {
            buffer = (buffer << 5) | alphabet.IndexOf(character);
            bits += 5;
            if (bits < 8) { continue; }
            bits -= 8;
            seed[index++] = (byte)(buffer >> bits);
        }
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, now.ToUnixTimeSeconds() / 30);
        var digest = HMACSHA1.HashData(seed, counter);
        var value = BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(digest[^1] & 15)) & 0x7fff_ffff;
        return (value % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private sealed class CapturingSender(Action<EmailMfaDelivery>? onDelivery = null) : IMfaEmailSender
    {
        internal List<EmailMfaDelivery> Deliveries { get; } = [];
        public Task SendAsync(EmailMfaDelivery delivery, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            onDelivery?.Invoke(delivery);
            Deliveries.Add(delivery);
            return Task.CompletedTask;
        }
    }

    private sealed class FixtureClock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Fixture(string path, ProtectedSessionKeyRing keys, FixtureClock clock, ServiceProvider services) : IAsyncDisposable
    {
        internal FixtureClock Clock => clock;

        internal static async Task<Fixture> Create()
        {
            var directory = Path.Combine(Path.GetTempPath(), "nergal-email-mfa-" + Guid.NewGuid().ToString("N"));
            const UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(directory, mode);
            ProtectedSessionKeyRing? ring = null;
            ServiceProvider? provider = null;
            try
            {
                var keyDirectory = Path.Combine(directory, "keys");
                Directory.CreateDirectory(keyDirectory, mode);
                using var rsa = RSA.Create(3072);
                var request = new CertificateRequest("CN=synthetic-email-mfa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var now = DateTimeOffset.UtcNow;
                using var certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
                ring = ProtectedSessionKeyRing.Open(new(keyDirectory), certificate);
                var options = new LocalAccountOptions(directory);
                var time = new FixtureClock();
                var collection = new ServiceCollection();
                collection.AddSingleton<TimeProvider>(time);
                collection.AddLocalAdministratorAccounts(options).AddLocalAdministratorSessions(ring);
                collection.Configure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options => options.TimeProvider = time);
                provider = collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
                await LocalAccountDatabase.InitializeAsync(options);
                var fixture = new Fixture(directory, ring, time, provider);
                Assert.True((await fixture.Run(accounts => accounts.ProvisionAsync(Administrator, Password))).Succeeded);
                return fixture;
            }
            catch
            {
                if (provider is not null) { await provider.DisposeAsync(); }
                ring?.Dispose();
                Directory.Delete(directory, recursive: true);
                throw;
            }
        }

        internal async Task<T> Run<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
            => (await Request((accounts, _) => operation(accounts))).Result;

        private async Task<(T Result, string[] Cookies)> Request<T>(
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

        internal async Task<(string Cookie, ClaimsPrincipal Principal)> SignIn(string username)
        {
            var (result, cookies) = await Begin(username);
            Assert.Equal(MfaSignInStatus.SignedIn, result.Status);
            var cookie = Assert.Single(cookies).Split(';', 2)[0];
            return (cookie, Assert.IsType<ClaimsPrincipal>(await Authenticate(cookie)));
        }

        internal Task<(MfaSignInResult Result, string[] Cookies)> Begin(string username, IMfaEmailSender? sender = null)
            => Request((accounts, _) => accounts.BeginLocalSignInAsync(username, Password, keys, sender: sender));

        internal Task<(MfaSignInResult Result, string[] Cookies)> Complete(string continuation, string code)
            => Request((accounts, _) => accounts.CompleteMfaSignInAsync(continuation, code, keys));

        internal async Task SaveDelivery(ClaimsPrincipal admin, long version)
            => Assert.True((await Run(accounts => accounts.SaveEmailDeliveryAsync(admin, version, Relay, "", keys))).Succeeded);

        internal Task<EmailMfaEnrollment?> Enroll(ClaimsPrincipal actor, IMfaEmailSender sender)
            => Run(accounts => accounts.BeginEmailMfaEnrollmentAsync(actor, Address, keys, sender));

        internal Task<LocalProvisionResult> Confirm(ClaimsPrincipal actor, EmailMfaEnrollment enrollment, string code)
            => Run(accounts => accounts.ConfirmEmailMfaEnrollmentAsync(actor, enrollment.Id, code, keys));

        internal async Task<TotpEnrollment> EnrollAuthenticator(ClaimsPrincipal actor)
        {
            var setup = Assert.IsType<TotpEnrollment>(await Run(accounts => accounts.BeginTotpEnrollmentAsync(actor, keys)));
            Assert.True((await Run(accounts => accounts.ConfirmTotpEnrollmentAsync(actor, setup.Id,
                AuthenticatorCode(setup, clock.Now), keys))).Succeeded);
            return setup;
        }

        internal async Task<(string Cookie, ClaimsPrincipal Principal)> CompleteAuthenticator(TotpEnrollment setup, IMfaEmailSender? sender = null)
        {
            var (challenge, _) = await Begin(Administrator, sender);
            Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
            var (result, cookies) = await Complete(Assert.IsType<string>(challenge.Continuation), AuthenticatorCode(setup, clock.Now));
            Assert.Equal(MfaSignInStatus.SignedIn, result.Status);
            var cookie = Assert.Single(cookies).Split(';', 2)[0];
            return (cookie, Assert.IsType<ClaimsPrincipal>(await Authenticate(cookie)));
        }

        internal long Scalar(string statement)
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = Path.Combine(path, "accounts.db"),
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = statement;
            return Assert.IsType<long>(command.ExecuteScalar());
        }

        public async ValueTask DisposeAsync()
        {
            try { await services.DisposeAsync(); }
            finally
            {
                keys.Dispose();
                Directory.Delete(path, recursive: true);
            }
        }
    }
}
