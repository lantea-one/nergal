using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    /// <summary>Lists bounded OIDC metadata mappings for a currently authorized Administrator; this does not expose secrets or activate providers.</summary>
    public async Task<IReadOnlyList<OidcProfileMapping>> ReadOidcProfileMappingsAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        _ = await ActorAsync(principal, true);
        var rows = await context.Set<OidcProfileMap>().AsNoTracking().OrderBy(m => m.Issuer).Take(17).ToArrayAsync();
        if (rows.Length > 16) { throw new AccountStoreException("profile.mappingCapacity"); }
        return Array.AsReadOnly(rows.Select(Mapping).ToArray());
    }

    /// <summary>Saves literal claim selectors with expected-version, serialized current-authority recheck and atomic audit.</summary>
    public Task<LocalProvisionResult> SaveOidcProfileMappingAsync(ClaimsPrincipal principal, OidcProfileMapping mapping)
        => MutateAsync(principal, true, async actor =>
        {
            if (!OidcProfileMapper.IsValid(mapping)) { return Failure("profile.mappingInvalid"); }
            var row = await context.Set<OidcProfileMap>().SingleOrDefaultAsync(m => m.Issuer == mapping.Issuer);
            if ((row?.Version ?? 0) != mapping.Version) { return Failure("profile.mappingStale"); }
            if (row is null)
            {
                if (await context.Set<OidcProfileMap>().CountAsync() >= 16) { return Failure("profile.mappingCapacity"); }
                row = new() { Issuer = mapping.Issuer }; context.Add(row);
            }
            row.Enabled = mapping.Enabled;
            row.DisplayNameClaim = mapping.DisplayNameClaim; row.GivenNameClaim = mapping.GivenNameClaim;
            row.FamilyNameClaim = mapping.FamilyNameClaim; row.EmailClaim = mapping.EmailClaim;
            row.Version = checked(row.Version + 1); row.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, "profile.mappingSaved", mapping.Issuer);
            return Success();
        });

    /// <summary>Persists metadata only from a completed, independently validated OIDC sign-in. Never pass browser/userinfo claims to this method.</summary>
    /// <remarks>The caller is the protocol handler after nonce/correlation validation. Metadata cannot link identities, grant authority, verify email or enroll MFA.</remarks>
    public Task<LocalProvisionResult> RefreshVerifiedOidcProfileAsync(ClaimsPrincipal principal, JsonElement verifiedClaims)
        => MutateAsync(principal, false, async actor =>
        {
            if (actor.LocalId is not null || verifiedClaims.ValueKind != JsonValueKind.Object ||
                !verifiedClaims.TryGetProperty("iss", out var issuer) || issuer.ValueKind != JsonValueKind.String ||
                !verifiedClaims.TryGetProperty("sub", out var subject) || subject.ValueKind != JsonValueKind.String ||
                issuer.GetString() != principal.FindFirstValue("iss") || subject.GetString() != principal.FindFirstValue("sub"))
            { return Failure("profile.providerIdentity"); }
            var connection = await ConnectionAsync();
            var generation = principal.FindFirstValue("nergal.oidc-generation") ?? "0";
            if (connection is null ? generation != "0" : !ConnectionSnapshot(connection).Settings.Enabled ||
                generation != connection.Version.ToString(CultureInfo.InvariantCulture) || connection.Issuer != issuer.GetString())
            { return Failure("profile.providerRetired"); }

            var map = await context.Set<OidcProfileMap>().SingleOrDefaultAsync(m => m.Issuer == issuer.GetString());
            if (map is null || !Mapping(map).Enabled) { return Success(); }
            ProviderProfileSnapshot projected;
            try { projected = OidcProfileMapper.Project(Mapping(map), verifiedClaims, clock.GetUtcNow()); }
            catch (ArgumentException) { return Failure("profile.providerClaims"); }
            var row = await context.Set<OidcProfileObservation>().SingleOrDefaultAsync(p => p.ActorId == actor.Id);
            if (row is null) { row = new() { ActorId = actor.Id }; context.Add(row); }
            row.Issuer = projected.Issuer; row.MappingVersion = projected.MappingVersion;
            row.DisplayName = projected.Metadata.DisplayName; row.GivenName = projected.Metadata.GivenName;
            row.FamilyName = projected.Metadata.FamilyName; row.Email = projected.Metadata.Email;
            row.ObservedUtc = Now(); row.Diagnostics = string.Join(",", projected.Diagnostics);
            Audit(actor.Id, actor.Role, "profile.providerRefreshed", actor.Id);
            return Success();
        });

    private async Task<ProviderProfileSnapshot?> ReadProviderAsync(string actorId, string issuer)
    {
        var map = await context.Set<OidcProfileMap>().AsNoTracking().SingleOrDefaultAsync(m => m.Issuer == issuer);
        if (map is null || !Mapping(map).Enabled) { return null; }
        var row = await context.Set<OidcProfileObservation>().AsNoTracking().SingleOrDefaultAsync(p => p.ActorId == actorId);
        if (row is null || row.MappingVersion != map.Version) { return null; }
        var metadata = new ProfileMetadata(row.DisplayName, row.GivenName, row.FamilyName, row.Email);
        var diagnostics = row.Diagnostics.Length == 0 ? [] : row.Diagnostics.Split(',');
        var validDiagnostics = new[] { "displayName", "givenName", "familyName", "email" }
            .SelectMany(field => new[] { field + ".missing", field + ".invalid" }).ToHashSet(StringComparer.Ordinal);
        if (row.Issuer != issuer || !metadata.IsValid || diagnostics.Length > 4 ||
            diagnostics.Distinct(StringComparer.Ordinal).Count() != diagnostics.Length || diagnostics.Any(d => !validDiagnostics.Contains(d)) ||
            diagnostics.Select(d => d.Split('.')[0]).Distinct(StringComparer.Ordinal).Count() != diagnostics.Length)
        { throw new AccountStoreException("account.corrupt"); }
        return new(issuer, row.MappingVersion, metadata, ReadTime(row.ObservedUtc)!.Value, diagnostics);
    }

    private static OidcProfileMapping Mapping(OidcProfileMap row)
    {
        var result = new OidcProfileMapping(row.Issuer, row.Version, row.Enabled, row.DisplayNameClaim,
            row.GivenNameClaim, row.FamilyNameClaim, row.EmailClaim, ReadTime(row.UpdatedUtc));
        if (row.Version < 1 || !OidcProfileMapper.IsValid(result)) { throw new AccountStoreException("account.corrupt"); }
        return result;
    }
}
