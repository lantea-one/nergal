using System.Text.Json;

namespace Nergal.Core.Identity;

/// <summary>Literal optional string selectors for descriptive fields from the authenticated OAuth profile endpoint.</summary>
public sealed record OAuthProfileFields(string DisplayName = "", string GivenName = "", string FamilyName = "", string Email = "");

/// <summary>Credential-free settings for one OAuth authorization server and its authoritative current-user endpoint.</summary>
public sealed record OAuthConnectionSettings(bool Enabled, string AuthorizationEndpoint, string TokenEndpoint, string ProfileEndpoint,
    string CallbackUri, string ClientId, string Scope, string SubjectField, string GroupField, string AdministratorGroups,
    string AuditorGroups, OAuthProfileFields Fields, bool TrustProviderMfa = false)
{
    /// <summary>Checks exact endpoints, literal selectors and disjoint group allowlists before any authentication request.</summary>
    public bool IsValid
    {
        get
        {
            if (!Endpoint(AuthorizationEndpoint, out var authorize) || !Endpoint(TokenEndpoint, out var token) ||
                !Endpoint(ProfileEndpoint, out var profile) || !Endpoint(CallbackUri, out var callback) ||
                !SameOrigin(authorize, token) || !SameOrigin(authorize, profile) || callback.AbsolutePath != "/signin-oauth" ||
                new[] { authorize.AbsoluteUri, token.AbsoluteUri, profile.AbsoluteUri }.Distinct(StringComparer.Ordinal).Count() != 3 ||
                !Text(ClientId, 256) || !ValidScope(Scope) || !Selector(SubjectField) || !Selector(GroupField) ||
                SubjectField == GroupField || Fields is null) { return false; }

            var mapped = new[] { Fields.DisplayName, Fields.GivenName, Fields.FamilyName, Fields.Email };
            return mapped.All(selector => selector == "" || Selector(selector) && selector != GroupField && selector != SubjectField) &&
                OidcProfileMapper.IsValid(Mapping(1)) && ReadGroups(AdministratorGroups) is { } administrators &&
                ReadGroups(AuditorGroups) is { } auditors && administrators.Count + auditors.Count > 0 && !administrators.Overlaps(auditors);
        }
    }

    /// <summary>Checks whether settings still identify the same upstream subject namespace.</summary>
    public bool SameIdentityBinding(OAuthConnectionSettings previous) =>
        AuthorizationEndpoint == previous.AuthorizationEndpoint && TokenEndpoint == previous.TokenEndpoint &&
        ProfileEndpoint == previous.ProfileEndpoint && ClientId == previous.ClientId && SubjectField == previous.SubjectField;

    /// <summary>Projects an authoritative current-user response after server-side token exchange and TLS verification.</summary>
    /// <remarks>Missing or ambiguous authority fields deny sign-in; invalid descriptive fields yield value-free diagnostics.</remarks>
    public OAuthProfileProof? ReadProfile(JsonElement profile, long generation, DateTimeOffset now)
    {
        if (!Enabled || !IsValid || generation < 1 || profile.ValueKind != JsonValueKind.Object) { return null; }
        try
        {
            // The common literal projection rejects duplicate top-level fields before authority is read.
            var metadata = OidcProfileMapper.Project(Mapping(generation), profile, now);
            if (!profile.TryGetProperty(SubjectField, out var subjectValue) || subjectValue.ValueKind != JsonValueKind.String ||
                subjectValue.GetString() is not { Length: >= 1 and <= 255 } subject ||
                !subject.All(c => c is >= '!' and <= '~') ||
                !profile.TryGetProperty(GroupField, out var groups) || groups.ValueKind != JsonValueKind.Array ||
                groups.GetArrayLength() is < 1 or > 256) { return null; }

            var observed = new HashSet<string>(StringComparer.Ordinal);
            foreach (var group in groups.EnumerateArray())
            {
                if (group.ValueKind != JsonValueKind.String || group.GetString() is not { } value ||
                    !Text(value, 256) || !observed.Add(value)) { return null; }
            }
            var administrator = ReadGroups(AdministratorGroups)!.Overlaps(observed);
            var auditor = ReadGroups(AuditorGroups)!.Overlaps(observed);
            return administrator == auditor ? null : new(subject, administrator ? NergalRoles.Administrator : NergalRoles.Auditor, metadata);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException) { return null; }
    }

    private OidcProfileMapping Mapping(long version) => new(ProfileEndpoint, version, true,
        Fields.DisplayName, Fields.GivenName, Fields.FamilyName, Fields.Email, null);

    private static bool Endpoint(string? value, out Uri uri)
    {
        uri = null!;
        if (value is null || !Text(value, 512) || value.Any(char.IsWhiteSpace) || value.Contains('\\') ||
            !Uri.TryCreate(value, UriKind.Absolute, out var parsed) || parsed.Scheme != "https" || parsed.Host.Length == 0 ||
            parsed.UserInfo.Length != 0 || parsed.Query.Length != 0 || parsed.Fragment.Length != 0 ||
            parsed.AbsoluteUri != value) { return false; }
        uri = parsed;
        return true;
    }

    private static bool SameOrigin(Uri left, Uri right) => left.IdnHost == right.IdnHost && left.Port == right.Port;

    private static bool Selector(string? value) => value is { Length: >= 1 and <= 128 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':' or '/');

    private static bool ValidScope(string? value) =>
        value is { Length: <= 512 } && (value.Length == 0 ||
        value.Split(' ').All(token => token.Length != 0 && token.All(c => c is >= '!' and <= '~' && c is not ('"' or '\\'))));

    private static HashSet<string>? ReadGroups(string? value)
    {
        if (value is null || value.Length > 8192) { return null; }
        var groups = new HashSet<string>(StringComparer.Ordinal);
        if (value.Length == 0) { return groups; }
        foreach (var item in value.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        { if (!Text(item, 256) || item.Trim() != item || !groups.Add(item) || groups.Count > 32) { return null; } }
        return groups;
    }

    private static bool Text(string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && ProfileMetadata.ValidText(value, maximum);
}

/// <summary>Immutable identity and descriptive projection from the verified OAuth profile endpoint.</summary>
public sealed record OAuthProfileProof(string Subject, string Role, ProviderProfileSnapshot Profile);

/// <summary>Credential-free current provider settings and concurrency generation.</summary>
public sealed record OAuthConnectionSnapshot(long Version, OAuthConnectionSettings Settings, bool HasSecret, DateTimeOffset UpdatedUtc);
