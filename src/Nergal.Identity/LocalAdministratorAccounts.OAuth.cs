using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Server-only OAuth runtime. The client secret is never part of the displayed connection snapshot.</summary>
public sealed class OAuthConnectionRuntime(OAuthConnectionSnapshot snapshot, string clientSecret)
{
    /// <summary>Credential-free current connection settings.</summary>
    public OAuthConnectionSnapshot Snapshot { get; } = snapshot;

    /// <summary>Decrypted credential for the configured token endpoint.</summary>
    public string ClientSecret { get; } = clientSecret;
}

public sealed partial class LocalAdministratorAccounts
{
    private const string OAuthSaved = "provider.oauthConnectionSaved";
    private const string OAuthScheme = "nergal.oauth-session";
    private const string OAuthGeneration = "nergal.oauth-generation";
    private const string OAuthMfaGeneration = "nergal.oauth-mfa-generation";

    /// <summary>Returns credential-free settings under current local Administrator authority.</summary>
    public async Task<OAuthConnectionSnapshot?> ReadOAuthConnectionAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        if ((await ActorAsync(principal, true)).LocalId is null) { throw new AccountStoreException("account.denied"); }
        return await OAuthConnectionAsync() is { } row ? OAuthSnapshot(row) : null;
    }

    /// <summary>Saves a versioned protected connection under local Administrator authority and records its audit atomically.</summary>
    public Task<LocalProvisionResult> SaveOAuthConnectionAsync(ClaimsPrincipal principal, long expectedVersion,
        OAuthConnectionSettings settings, string replacementSecret, IDataProtectionProvider keys)
        => MutateAsync(principal, true, async actor =>
        {
            if (actor.LocalId is null) { return Failure("provider.localAdministratorRequired"); }
            if (expectedVersion is < 0 or >= long.MaxValue - 1 || settings is null || !settings.IsValid ||
                replacementSecret is null || replacementSecret.Length != 0 && !ValidConnectionSecret(replacementSecret))
            { return Failure("provider.oauthInvalid"); }

            var row = await OAuthConnectionAsync();
            if ((row?.Version ?? 0) != expectedVersion) { return Failure("provider.stale"); }
            var sameBinding = row is not null && settings.SameIdentityBinding(OAuthSnapshot(row).Settings);
            if (!sameBinding && replacementSecret.Length == 0) { return Failure("provider.secretRequired"); }

            var connectionId = sameBinding ? row!.ConnectionId : Guid.NewGuid().ToString("D");
            var protectedSecret = row?.ProtectedSecret ?? "";
            if (replacementSecret.Length != 0)
            {
                try { protectedSecret = OAuthProtector(keys, settings, connectionId).Protect(replacementSecret); }
                catch (CryptographicException) { throw new AccountStoreException("provider.secretUnavailable"); }
            }

            if (row is null) { row = new(); context.Add(row); }
            else { context.Attach(row); context.Entry(row).State = EntityState.Modified; }
            row.Version = expectedVersion + 1;
            row.ConnectionId = connectionId;
            row.Settings = JsonSerializer.Serialize(settings);
            row.ProtectedSecret = protectedSecret;
            row.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, OAuthSaved, "oauth");
            return Success();
        });

    /// <summary>Returns the configured enabled generation for the browser sign-in entry point.</summary>
    public async Task<long?> ReadOAuthSignInGenerationAsync()
    {
        try
        {
            return await OAuthConnectionAsync() is { } row && OAuthSnapshot(row).Settings.Enabled ? row.Version : null;
        }
        catch (AccountStoreException error) when (error.Code == "account.corrupt") { return null; }
    }

    /// <summary>Opens the configured secret solely for direct OAuth protocol handling.</summary>
    public async Task<OAuthConnectionRuntime?> ReadOAuthRuntimeAsync(IDataProtectionProvider keys)
    {
        if (await OAuthConnectionAsync() is not { } row) { return null; }
        var snapshot = OAuthSnapshot(row);
        if (!snapshot.Settings.Enabled) { return null; }
        try
        {
            var secret = OAuthProtector(keys, snapshot.Settings, row.ConnectionId).Unprotect(row.ProtectedSecret);
            if (!ValidConnectionSecret(secret)) { throw new AccountStoreException("provider.secretUnavailable"); }
            return new(snapshot, secret);
        }
        catch (CryptographicException) { throw new AccountStoreException("provider.secretUnavailable"); }
    }

    /// <summary>Completes verified OAuth authentication and refreshes descriptive defaults in one account transaction.</summary>
    /// <remarks>Call only after code exchange and a successful authenticated request to the configured profile endpoint.</remarks>
    public async Task<ClaimsPrincipal?> CompleteOAuthSignInAsync(long generation, JsonElement profile, DateTimeOffset deadline,
        CancellationToken cancellationToken = default)
    {
        var remaining = deadline - clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero || remaining > TimeSpan.FromMinutes(5)) { return null; }
        using var expiry = new CancellationTokenSource(remaining, clock);
        using var current = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, expiry.Token);
        try
        {
            return await WithCredentialTransactionAsync<ClaimsPrincipal?>(async () =>
                {
                    if (deadline <= clock.GetUtcNow() || await OAuthConnectionAsync() is not { } row || row.Version != generation) { return null; }
                    var settings = OAuthSnapshot(row).Settings;
                    if (settings.ReadProfile(profile, generation, clock.GetUtcNow()) is not { } proof ||
                        await ReadOidcMfaGenerationAsync(proof.Role, settings.TrustProviderMfa) is not { } policyGeneration ||
                        deadline <= clock.GetUtcNow() || current.IsCancellationRequested)
                    { return null; }

                    var actorId = ControllerActorIdentity.FromOAuthAccount(Guid.Parse(row.ConnectionId), proof.Subject);
                    var observed = await context.Set<OAuthProfileObservation>().FindAsync(actorId);
                    if (observed is null) { observed = new() { ActorId = actorId }; context.Add(observed); }
                    observed.Generation = generation;
                    observed.Endpoint = settings.ProfileEndpoint;
                    observed.DisplayName = proof.Profile.Metadata.DisplayName;
                    observed.GivenName = proof.Profile.Metadata.GivenName;
                    observed.FamilyName = proof.Profile.Metadata.FamilyName;
                    observed.Email = proof.Profile.Metadata.Email;
                    observed.Diagnostics = string.Join(",", proof.Profile.Diagnostics);
                    observed.ObservedUtc = Now();
                    Audit(actorId, proof.Role, "oauth.signedIn", actorId);

                    return new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new(ControllerActorIdentity.ActorClaimType, actorId), new(ClaimTypes.Role, proof.Role),
                        new(ClaimTypes.Name, proof.Subject), new("iss", settings.ProfileEndpoint), new("sub", proof.Subject),
                        new(OAuthGeneration, Generation(generation)), new(OAuthMfaGeneration, Generation(policyGeneration))
                    ], OAuthScheme));
                }, current.Token, cancelBeforeCommit: true);
        }
        catch (OperationCanceledException) when (expiry.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        { return null; }
    }

    /// <summary>Checks that the connection identity, generation, role and MFA policy still authorize an OAuth cookie.</summary>
    public async Task<bool> ValidateOAuthSessionAsync(ClaimsPrincipal principal)
    {
        try { return await ReadCurrentOAuthActorAsync(principal) is not null; }
        catch (AccountStoreException error) when (error.Code == "account.corrupt") { return false; }
    }

    private async Task<AccountActor?> ReadCurrentOAuthActorAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.AuthenticationType != OAuthScheme || await OAuthConnectionAsync() is not { } row ||
            SingleClaim(principal, OAuthGeneration) != Generation(row.Version)) { return null; }
        var settings = OAuthSnapshot(row).Settings;
        var subject = SingleClaim(principal, "sub");
        var role = SingleClaim(principal, ClaimTypes.Role);
        if (!settings.Enabled || SingleClaim(principal, "iss") != settings.ProfileEndpoint || subject is null ||
            SingleClaim(principal, ClaimTypes.Name) != subject ||
            await ReadOidcMfaGenerationAsync(role, settings.TrustProviderMfa) is not { } policy ||
            SingleClaim(principal, OAuthMfaGeneration) != Generation(policy)) { return null; }
        try
        {
            var id = ControllerActorIdentity.FromOAuthAccount(Guid.Parse(row.ConnectionId), subject);
            return SingleClaim(principal, ControllerActorIdentity.ActorClaimType) == id ? new(id, role!, subject, null) : null;
        }
        catch (ArgumentException) { return null; }
    }

    private async Task<ProviderProfileSnapshot?> ReadOAuthProfileAsync(string actorId, string endpoint)
    {
        var connection = await OAuthConnectionAsync();
        var observed = await context.Set<OAuthProfileObservation>().AsNoTracking().SingleOrDefaultAsync(row => row.ActorId == actorId);
        if (connection is null || observed is null || connection.Version != observed.Generation) { return null; }
        if (observed.Endpoint != endpoint) { throw new AccountStoreException("account.corrupt"); }
        try
        {
            return new(endpoint, observed.Generation,
                new(observed.DisplayName, observed.GivenName, observed.FamilyName, observed.Email),
                ReadTime(observed.ObservedUtc) ?? throw new AccountStoreException("account.corrupt"),
                observed.Diagnostics.Length == 0 ? [] : observed.Diagnostics.Split(','));
        }
        catch (ArgumentException) { throw new AccountStoreException("account.corrupt"); }
    }

    private async Task<OAuthConnection?> OAuthConnectionAsync()
    {
        var history = context.Database.SqlQuery<long>($"SELECT count(*) AS Value FROM IdentityAudit WHERE Action = {OAuthSaved}");
        var entries = await (from generation in history
                             from row in context.Set<OAuthConnection>().AsNoTracking().DefaultIfEmpty()
                             select new { Generation = generation, Row = row }).Take(2).ToArrayAsync();
        if (entries.Length != 1 || entries[0].Row is { Id: not 1 } ||
            entries[0].Generation != (entries[0].Row?.Version ?? 0))
        { throw new AccountStoreException("account.corrupt"); }
        return entries[0].Row;
    }

    private static OAuthConnectionSnapshot OAuthSnapshot(OAuthConnection row)
    {
        try
        {
            if (!Guid.TryParseExact(row.ConnectionId, "D", out var id) || id == Guid.Empty || id.ToString("D") != row.ConnectionId ||
                row.Version is < 1 or >= long.MaxValue || row.Settings.Length > 128_000 || row.ProtectedSecret.Length is < 1 or > 30_000 ||
                JsonSerializer.Deserialize<OAuthConnectionSettings>(row.Settings) is not { IsValid: true } settings)
            { throw new AccountStoreException("account.corrupt"); }
            return new(row.Version, settings, true, ReadTime(row.UpdatedUtc) ?? throw new AccountStoreException("account.corrupt"));
        }
        catch (JsonException) { throw new AccountStoreException("account.corrupt"); }
    }

    private static IDataProtector OAuthProtector(IDataProtectionProvider keys, OAuthConnectionSettings settings, string connectionId) =>
        keys.CreateProtector("Nergal.OAuth.ClientSecret.v1", connectionId, settings.TokenEndpoint, settings.ClientId);

    private static string Generation(long version) => version.ToString(CultureInfo.InvariantCulture);

    private static string? SingleClaim(ClaimsPrincipal principal, string claim)
    {
        var values = principal.FindAll(claim).Take(2).ToArray();
        return values.Length == 1 ? values[0].Value : null;
    }
}
