using System.Text.Json;

namespace Nergal.Core.Controller;

/// <summary>Branding and UI appearance configuration stored by the controller.</summary>
public sealed record BrandingSettings(
    string ApplicationName = "nergal",
    string InstanceSubtitle = "Self-hosted Linux nftables firewall controller",
    string AccentColor = "emerald",
    string DefaultTheme = "system",
    string? LoginBanner = null);

/// <summary>Local account authentication settings.</summary>
public sealed record LocalAuthSettings(
    bool Enabled = true,
    int SessionIdleTimeoutMinutes = 30,
    int LockoutMaxFailedAttempts = 5,
    int LockoutDurationMinutes = 15,
    int MinimumPasswordLength = 12);

/// <summary>Optional OpenID Connect / OAuth 2.0 provider settings (client secret is managed outside the database).</summary>
public sealed record OidcAuthSettings(
    bool Enabled = false,
    string? AuthorityUrl = null,
    string? ClientId = null,
    string Scopes = "openid profile email groups",
    string? RedirectUri = null,
    string GroupsClaim = "groups",
    string? AdministratorGroups = null,
    string? AuditorGroups = null,
    int MaxAuthAgeSeconds = 3600);

/// <summary>Optional LDAP / Active Directory provider settings (bind password is managed outside the database).</summary>
public sealed record LdapAuthSettings(
    bool Enabled = false,
    string? ServerUri = null,
    bool UseStartTls = true,
    string? BaseDn = null,
    string? BindDn = null,
    string UserSearchFilter = "(uid={0})",
    string GroupMembershipAttribute = "memberOf",
    string? AdministratorGroupDn = null,
    string? AuditorGroupDn = null);

/// <summary>Controller database backend configuration (passwords are managed via environment/secret files).</summary>
public sealed record DatabaseBackendSettings(
    string Provider = "sqlite",
    string? Host = null,
    int? Port = null,
    string? DatabaseName = null,
    string? Username = null,
    string TlsMode = "require");

/// <summary>Default firewall authoring and confirmed-apply safety settings.</summary>
public sealed record FirewallDefaultsSettings(
    int DefaultConfirmationTimeoutSeconds = 30,
    int DefaultFilterSchemaVersion = 2,
    string DefaultInputVerdict = "drop",
    string DefaultForwardVerdict = "drop",
    string DefaultOutputVerdict = "accept",
    bool RequireChangeSummary = false);

/// <summary>Complete validated controller system settings snapshot.</summary>
public sealed record SystemSettingsSnapshot(
    BrandingSettings Branding,
    LocalAuthSettings LocalAuth,
    OidcAuthSettings Oidc,
    LdapAuthSettings Ldap,
    DatabaseBackendSettings Database,
    FirewallDefaultsSettings FirewallDefaults)
{
    /// <summary>Default safe settings for a fresh controller installation.</summary>
    public static SystemSettingsSnapshot Default { get; } = new(
        new BrandingSettings(),
        new LocalAuthSettings(),
        new OidcAuthSettings(),
        new LdapAuthSettings(),
        new DatabaseBackendSettings(),
        new FirewallDefaultsSettings());
}

/// <summary>Strict validator and JSON serializer for <see cref="SystemSettingsSnapshot"/>.</summary>
public static class SystemSettingsCodec
{
    private static readonly HashSet<string> ValidAccents = new(["blue", "emerald", "violet", "amber", "rose", "slate"], StringComparer.Ordinal);
    private static readonly HashSet<string> ValidThemes = new(["system", "light", "dark"], StringComparer.Ordinal);
    private static readonly HashSet<string> ValidDbProviders = new(["sqlite", "postgresql", "mariadb"], StringComparer.Ordinal);
    private static readonly HashSet<string> ValidTlsModes = new(["disable", "prefer", "require", "verify-full"], StringComparer.Ordinal);
    private static readonly HashSet<string> ValidVerdicts = new(["accept", "drop"], StringComparer.Ordinal);

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        RespectNullableAnnotations = true,
        WriteIndented = false,
    };

    /// <summary>Validates all bounds and allowlists on <paramref name="settings"/>, returning stable error codes.</summary>
    public static IReadOnlyList<string> Validate(SystemSettingsSnapshot settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var errors = new List<string>();
        if (settings.Branding is null || settings.LocalAuth is null || settings.Oidc is null || settings.Ldap is null ||
            settings.Database is null || settings.FirewallDefaults is null) { return ["settings.sectionRequired"]; }
        var strings = new (string? Value, int Limit)[]
        {
            (settings.Branding.ApplicationName, 64), (settings.Branding.InstanceSubtitle, 160),
            (settings.Oidc.AuthorityUrl, 2048), (settings.Oidc.ClientId, 128), (settings.Oidc.Scopes, 512),
            (settings.Oidc.RedirectUri, 2048), (settings.Oidc.GroupsClaim, 128),
            (settings.Oidc.AdministratorGroups, 1024), (settings.Oidc.AuditorGroups, 1024),
            (settings.Ldap.ServerUri, 2048), (settings.Ldap.BaseDn, 256), (settings.Ldap.BindDn, 256),
            (settings.Ldap.UserSearchFilter, 512), (settings.Ldap.GroupMembershipAttribute, 128),
            (settings.Ldap.AdministratorGroupDn, 256), (settings.Ldap.AuditorGroupDn, 256),
            (settings.Database.Host, 253), (settings.Database.DatabaseName, 128), (settings.Database.Username, 128),
        };
        if (strings.Any(s => s.Value is not null && (s.Value.Length > s.Limit || s.Value.Any(char.IsControl))))
        { errors.Add("settings.textBounds"); }
        if (settings.Branding.ApplicationName is null || settings.Branding.InstanceSubtitle is null || settings.Oidc.Scopes is null ||
            settings.Oidc.GroupsClaim is null || settings.Ldap.UserSearchFilter is null || settings.Ldap.GroupMembershipAttribute is null)
        { return ["settings.fieldRequired"]; }


        if (string.IsNullOrWhiteSpace(settings.Branding.ApplicationName) ||
            settings.Branding.ApplicationName.Length > 64 ||
            settings.Branding.ApplicationName.Any(char.IsControl))
        {
            errors.Add("branding.applicationName");
        }

        if (settings.Branding.InstanceSubtitle.Length > 160 || settings.Branding.InstanceSubtitle.Any(char.IsControl))
        {
            errors.Add("branding.instanceSubtitle");
        }

        if (!ValidAccents.Contains(settings.Branding.AccentColor))
        {
            errors.Add("branding.accentColor");
        }

        if (!ValidThemes.Contains(settings.Branding.DefaultTheme))
        {
            errors.Add("branding.defaultTheme");
        }

        if (settings.Branding.LoginBanner is not null &&
            (settings.Branding.LoginBanner.Length > 256 || settings.Branding.LoginBanner.Any(char.IsControl)))
        {
            errors.Add("branding.loginBanner");
        }

        if (settings.LocalAuth.SessionIdleTimeoutMinutes is < 5 or > 1440)
        {
            errors.Add("auth.local.sessionIdleTimeoutMinutes");
        }

        if (settings.LocalAuth.LockoutMaxFailedAttempts is < 3 or > 20)
        {
            errors.Add("auth.local.lockoutMaxFailedAttempts");
        }

        if (settings.LocalAuth.LockoutDurationMinutes is < 1 or > 1440)
        {
            errors.Add("auth.local.lockoutDurationMinutes");
        }

        if (settings.LocalAuth.MinimumPasswordLength is < 8 or > 128)
        {
            errors.Add("auth.local.minimumPasswordLength");
        }

        if (settings.Oidc.Enabled)
        {
            if (string.IsNullOrWhiteSpace(settings.Oidc.AuthorityUrl) ||
                !Uri.TryCreate(settings.Oidc.AuthorityUrl, UriKind.Absolute, out var authUri) ||
                authUri.Scheme != Uri.UriSchemeHttps)
            {
                errors.Add("auth.oidc.authorityUrl");
            }

            if (string.IsNullOrWhiteSpace(settings.Oidc.ClientId) || settings.Oidc.ClientId.Length > 128)
            {
                errors.Add("auth.oidc.clientId");
            }
        }

        if (settings.Oidc.MaxAuthAgeSeconds is < 60 or > 86400)
        {
            errors.Add("auth.oidc.maxAuthAgeSeconds");
        }

        if (settings.Ldap.Enabled)
        {
            if (string.IsNullOrWhiteSpace(settings.Ldap.ServerUri) ||
                !Uri.TryCreate(settings.Ldap.ServerUri, UriKind.Absolute, out var ldapUri) ||
                ldapUri.Scheme is not ("ldap" or "ldaps"))
            {
                errors.Add("auth.ldap.serverUri");
            }

            if (string.IsNullOrWhiteSpace(settings.Ldap.BaseDn) || settings.Ldap.BaseDn.Length > 256)
            {
                errors.Add("auth.ldap.baseDn");
            }
        }

        if (!ValidDbProviders.Contains(settings.Database.Provider))
        {
            errors.Add("database.provider");
        }

        if (!ValidTlsModes.Contains(settings.Database.TlsMode))
        {
            errors.Add("database.tlsMode");
        }

        if (settings.Database.Port is < 1 or > 65535)
        {
            errors.Add("database.port");
        }

        if (settings.Database.Provider is "postgresql" or "mariadb")
        {
            if (string.IsNullOrWhiteSpace(settings.Database.Host) || settings.Database.Host.Length > 253)
            {
                errors.Add("database.host");
            }

            if (string.IsNullOrWhiteSpace(settings.Database.DatabaseName) || settings.Database.DatabaseName.Length > 128)
            {
                errors.Add("database.databaseName");
            }
        }

        if (settings.FirewallDefaults.DefaultConfirmationTimeoutSeconds is < 1 or > 3600)
        {
            errors.Add("firewall.defaultConfirmationTimeoutSeconds");
        }

        if (settings.FirewallDefaults.DefaultFilterSchemaVersion is not (1 or 2))
        {
            errors.Add("firewall.defaultFilterSchemaVersion");
        }

        if (!ValidVerdicts.Contains(settings.FirewallDefaults.DefaultInputVerdict) ||
            !ValidVerdicts.Contains(settings.FirewallDefaults.DefaultForwardVerdict) ||
            !ValidVerdicts.Contains(settings.FirewallDefaults.DefaultOutputVerdict))
        {
            errors.Add("firewall.defaultVerdict");
        }

        return errors;
    }

    /// <summary>Serializes a validated <see cref="SystemSettingsSnapshot"/> to canonical UTF-8 JSON.</summary>
    public static string Serialize(SystemSettingsSnapshot settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (Validate(settings).Count > 0) { throw new ArgumentException("settings.invalid", nameof(settings)); }
        return JsonSerializer.Serialize(settings, SerializerOptions);
    }

    /// <summary>Deserializes a stored settings JSON payload, falling back to <see cref="SystemSettingsSnapshot.Default"/> when empty.</summary>
    public static SystemSettingsSnapshot Deserialize(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return SystemSettingsSnapshot.Default;
        }

        if (json.Length > 32_768) { throw new JsonException("settings.bounds"); }
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object || HasDuplicateSettingsProperties(document.RootElement))
        { throw new JsonException("settings.invalid"); }
        var parsed = JsonSerializer.Deserialize<SystemSettingsSnapshot>(json, SerializerOptions);
        if (parsed is null || Validate(parsed).Count > 0) { throw new JsonException("settings.invalid"); }
        return parsed;
    }

    private static bool HasDuplicateSettingsProperties(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object) { return false; }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return el.EnumerateObject().Any(p => !seen.Add(p.Name) || HasDuplicateSettingsProperties(p.Value));
    }
}
