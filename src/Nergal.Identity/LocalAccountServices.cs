using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Nergal.Identity;

/// <summary>Registers local credential verification only; no cookie, HTTP endpoint, default account or automatic database creation.</summary>
public static class LocalAccountServices
{
    /// <summary>Registers one explicitly configured existing private account database and standard Identity password/lockout services.</summary>
    /// <exception cref="ArgumentNullException">Services or options are null.</exception>
    /// <exception cref="InvalidOperationException">A local account store is already registered.</exception>
    /// <exception cref="PlatformNotSupportedException">Storage platform is not Linux.</exception>
    [SupportedOSPlatform("linux")]
    public static IServiceCollection AddLocalAdministratorAccounts(this IServiceCollection services, LocalAccountOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("Local accounts require Linux private storage."); }
        if (services.Any(service => service.ServiceType == typeof(LocalAccountOptions)))
        { throw new InvalidOperationException("A local account store is already registered."); }
        services.AddLogging();
        services.AddAuthenticationCore();
        services.AddSingleton(options);
        services.AddDbContext<LocalAccountContext>(builder => ConfigureDatabase(builder, options));
        services.AddIdentityCore<LocalAdministrator>(identity =>
        {
            identity.Password.RequiredLength = 15;
            identity.Password.RequireDigit = false;
            identity.Password.RequireLowercase = false;
            identity.Password.RequireUppercase = false;
            identity.Password.RequireNonAlphanumeric = false;
            identity.Lockout.AllowedForNewUsers = true;
            identity.Lockout.MaxFailedAccessAttempts = 5;
            identity.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        }).AddPasswordValidator<BoundedPasswordValidator>().AddSignInManager().AddEntityFrameworkStores<LocalAccountContext>()
          .AddClaimsPrincipalFactory<LocalAccountClaimsPrincipalFactory>();
        services.Configure<PasswordHasherOptions>(password =>
        {
            password.CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV3;
            password.IterationCount = 210_000;
        });
        services.AddSingleton<DummyPasswordVerification>();
        services.AddScoped(provider => new LocalAdministratorAccounts(
            provider.GetRequiredService<LocalAccountContext>(), provider.GetRequiredService<UserManager<LocalAdministrator>>(),
            provider.GetRequiredService<SignInManager<LocalAdministrator>>(), provider.GetRequiredService<DummyPasswordVerification>()));
        return services;
    }

    [SupportedOSPlatform("linux")]
    internal static void ConfigureDatabase(DbContextOptionsBuilder builder, LocalAccountOptions options, bool initializing = false)
        => builder.UseSqlite(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(options.Directory, "accounts.db"),
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString()).AddInterceptors(new AccountConnectionPolicy(options, initializing));
}

internal sealed class BoundedPasswordValidator : IPasswordValidator<LocalAdministrator>
{
    public Task<IdentityResult> ValidateAsync(UserManager<LocalAdministrator> manager, LocalAdministrator user, string? password)
        => Task.FromResult(Valid(password) ? IdentityResult.Success : IdentityResult.Failed(new IdentityError { Code = "password.bounds" }));

    internal static bool Valid(string? password)
    {
        if (password is null || password.Length > 256) { return false; }
        try { _ = new UTF8Encoding(false, true).GetByteCount(password); }
        catch (EncoderFallbackException) { return false; }
        var count = password.EnumerateRunes().Count();
        return count is >= 15 and <= 128;
    }
}

// Real standard Identity verification for absent/locked users, with a process-local
// random dummy secret. Neither this dummy hash nor account hashes leave the service.
internal sealed class DummyPasswordVerification
{
    private readonly PasswordHasher<LocalAdministrator> hasher;
    private readonly LocalAdministrator dummy = new();
    private readonly string hash;
    public DummyPasswordVerification(IOptions<PasswordHasherOptions> options)
    {
        hasher = new(options);
        hash = hasher.HashPassword(dummy, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }
    internal void Verify(string password) => _ = hasher.VerifyHashedPassword(dummy, hash, password);
}
