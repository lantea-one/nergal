using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Nergal.Identity;

namespace Nergal.Web.Tests;

[SupportedOSPlatform("linux")]
internal sealed class RecoveryFixture : IAsyncDisposable
{
    internal const string Name = "recovery-admin";
    internal const string Password = "synthetic account password for recovery";
    internal IDataProtectionProvider Keys { get; } = new EphemeralDataProtectionProvider();
    private readonly string directory;
    private readonly ServiceProvider services;
    private readonly Clock clock = new();

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private RecoveryFixture(string directory)
    {
        this.directory = directory;
        var collection = new ServiceCollection();
        collection.AddSingleton<TimeProvider>(clock);
        collection.AddLocalAdministratorAccounts(new(directory));
        collection.AddAuthentication(IdentityConstants.ApplicationScheme).AddCookie(IdentityConstants.ApplicationScheme,
            options => { options.DataProtectionProvider = Keys; options.TimeProvider = clock; });
        services = collection.BuildServiceProvider();
    }

    internal static async Task<RecoveryFixture> Create()
    {
        var directory = Path.Combine(Path.GetTempPath(), "nergal-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var fixture = new RecoveryFixture(directory);
        try
        {
            await LocalAccountDatabase.InitializeAsync(new(directory));
            Assert.True((await fixture.Run(a => a.ProvisionAsync(Name, Password))).Succeeded);
            return fixture;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }

    internal void Advance(int minutes = 1) => clock.Now = clock.Now.AddMinutes(minutes);

    internal async Task<T> Run<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
        => (await Request(operation)).Result;

    private async Task<(T Result, ClaimsPrincipal Principal)> Request<T>(Func<LocalAdministratorAccounts, Task<T>> operation)
    {
        using var scope = services.CreateScope();
        var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
        var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
        http.Request.Scheme = "https";
        accessor.HttpContext = http;
        try { return (await operation(scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>()), http.User); }
        finally { accessor.HttpContext = null; }
    }

    internal async Task<ClaimsPrincipal> Admin(string? key = null)
    {
        var (result, principal) = await Request(a => a.BeginLocalSignInAsync(Name, Password, Keys));
        if (key is not null) { return await Complete(result, key); }
        Assert.Equal(MfaSignInStatus.SignedIn, result.Status);
        return principal;
    }

    internal async Task<ClaimsPrincipal> Complete(MfaSignInResult challenge, string key)
    {
        Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
        var (result, principal) = await Request(a => a.CompleteMfaSignInAsync(challenge.Continuation!, Code(key), Keys));
        Assert.Equal(MfaSignInStatus.SignedIn, result.Status);
        return principal;
    }

    internal Task<RecoverySetup?> Begin(string authorization, string username = Name, string password = Password)
        => Run(a => a.BeginLocalRecoveryAsync(authorization, username, password, Keys));

    internal Task<bool> Confirm(RecoverySetup setup, string code)
        => Run(a => a.ConfirmRecoveryAsync(setup.Continuation, code, Keys));

    internal async Task Sql(string statement)
    {
        using var scope = services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<LocalAccountContext>();
        await context.Database.ExecuteSqlRawAsync(statement, TestContext.Current.CancellationToken);
    }

    // Compute the authenticator response independently using only the displayed Base32 key.
    internal string Code(string manualKey)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var bytes = new List<byte>();
        int accumulator = 0, bits = 0;
        foreach (var digit in manualKey)
        {
            accumulator = (accumulator << 5) | alphabet.IndexOf(digit);
            bits += 5;
            if (bits >= 8) { bits -= 8; bytes.Add((byte)(accumulator >> bits)); }
        }
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, clock.Now.ToUnixTimeSeconds() / 30);
        var hash = HMACSHA1.HashData(bytes.ToArray(), counter);
        var value = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(hash[^1] & 15)) & 0x7fffffff;
        return (value % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync()
    {
        await services.DisposeAsync();
        Directory.Delete(directory, recursive: true);
    }
}
