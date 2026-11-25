using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

// Immutable per-request generation selected before any authentication handler runs.
[SupportedOSPlatform("linux")]
internal sealed class OidcRequestConnection(OidcBootstrapConnection bootstrap, LocalAdministratorAccounts accounts, IDataProtectionProvider keys)
{
    internal OidcConnectionRuntime? Runtime { get; private set; }
    internal string Generation => Runtime is null ? "none" : Runtime.Snapshot.Version.ToString(CultureInfo.InvariantCulture);
    internal bool Enabled => Runtime?.Snapshot.Settings.Enabled == true;

    internal async Task LoadAsync() => Runtime = await accounts.ReadOidcRuntimeAsync(keys) ?? bootstrap.Runtime;

    internal async Task<bool> IsCurrentAsync(string generation)
    {
        var latest = await accounts.ReadOidcRuntimeAsync(keys) ?? bootstrap.Runtime;
        return latest?.Snapshot.Settings.Enabled == true && latest.Snapshot.Version.ToString(CultureInfo.InvariantCulture) == generation;
    }

    internal static OidcConnectionRuntime? Bootstrap(IConfiguration config)
    {
        if (!config.GetValue<bool>("Enabled")) { return null; }
        var admins = config.GetSection("AdministratorGroups").GetChildren().Select(v => v.Value ?? "").ToArray();
        if (admins.Length == 0) { admins = config.GetSection("AllowedGroups").GetChildren().Select(v => v.Value ?? "").ToArray(); }
        var settings = new OidcConnectionSettings(true, config["Issuer"] ?? "", config["ClientId"] ?? "", config["CallbackUri"] ?? "",
            config["GroupClaim"] ?? "", admins, config.GetSection("AuditorGroups").GetChildren().Select(v => v.Value ?? ""));
        var secret = config["ClientSecret"] ?? "";
        if (!settings.IsValid || string.IsNullOrWhiteSpace(secret) || secret.Length > 4096 || secret.Any(char.IsControl))
        { throw new InvalidOperationException("Invalid protected OIDC bootstrap configuration."); }
        return new(new(0, settings, true, DateTimeOffset.UnixEpoch), secret);
    }
}

// Snapshot operator bootstrap inputs once. Reloadable configuration must not
// silently reuse generation zero with different issuer/client/role settings.
[SupportedOSPlatform("linux")]
internal sealed class OidcBootstrapConnection
{
    private readonly Lazy<OidcConnectionRuntime?> runtime;
    internal OidcBootstrapConnection(IConfigurationSection config)
    {
        var snapshot = new ConfigurationBuilder().AddInMemoryCollection(config.AsEnumerable(makePathsRelative: true).ToArray()).Build();
        runtime = new(() => OidcRequestConnection.Bootstrap(snapshot));
    }
    internal OidcConnectionRuntime? Runtime => runtime.Value;
}

// Shared options are immutable after publication. Version keys prevent concurrent
// old requests from overwriting current trust. Eviction never changes live handlers.
internal sealed class OidcGenerationCache
{
    private readonly Dictionary<string, OpenIdConnectOptions> options = new(StringComparer.Ordinal);
    private readonly object gate = new();
    internal OpenIdConnectOptions Get(string generation, Func<OpenIdConnectOptions> create)
    {
        lock (gate)
        {
            if (options.TryGetValue(generation, out var value)) { return value; }
            value = create();
            if (options.Count >= 4) { options.Remove(options.Keys.First()); }
            options.Add(generation, value); return value;
        }
    }
}

[SupportedOSPlatform("linux")]
internal sealed class OidcRequestOptions(IOptionsFactory<OpenIdConnectOptions> factory, OidcRequestConnection connection,
    OidcGenerationCache cache) : IOptionsMonitor<OpenIdConnectOptions>
{
    public OpenIdConnectOptions CurrentValue => Get(FederatedLogin.Protocol);
    public OpenIdConnectOptions Get(string? name)
    {
        if (name != FederatedLogin.Protocol) { throw new InvalidOperationException("Unknown OIDC scheme."); }
        return cache.Get(connection.Generation, () => factory.Create(name));
    }
    public IDisposable? OnChange(Action<OpenIdConnectOptions, string?> listener) => null;
}
