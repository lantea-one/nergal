using System.Data;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using Nergal.Core.Identity;

namespace Nergal.Identity;

public sealed partial class LocalAdministratorAccounts
{
    private const int LdapActorCapacity = 4096;
    private const string LdapSessionScheme = "nergal.ldap-session";
    private const string LdapSessionIdClaim = "nergal.ldap-session-id";

    /// <summary>Returns the enabled LDAP connection generation for a new sign-in form without reading the bind secret.</summary>
    public async Task<long?> ReadLdapSignInGenerationAsync()
    {
        try
        {
            var row = await ReadLdapConnectionRowAsync();
            return row is not null && LdapSnapshot(row).Settings.Enabled ? row.Version : null;
        }
        catch (AccountStoreException error) when (error.Code == "account.corrupt") { return null; }
    }

    /// <summary>Checks credentials against the current configured LDAPS peer before entering shared MFA completion.</summary>
    public async Task<MfaSignInResult> BeginLdapSignInAsync(long generation, string username, string password,
        IDataProtectionProvider keys, CancellationToken cancellationToken = default, IMfaEmailSender? emailSender = null)
    {
        if (generation < 1 || !LdapUserLookup.IsValidUsername(username) || !LdapDirectoryAuthenticator.ValidPassword(password))
        { return new(MfaSignInStatus.Denied); }

        LdapConnectionRuntime? runtime;
        try { runtime = await ReadLdapRuntimeAsync(generation, keys); }
        catch (AccountStoreException error) when (error.Code is "provider.secretUnavailable" or "account.corrupt")
        { return new(MfaSignInStatus.Denied); }
        if (runtime is null) { return new(MfaSignInStatus.Denied); }

        var directoryProof = await new LdapDirectoryAuthenticator(clock).VerifyAsync(runtime.Directory, runtime.DialAddress,
            runtime.SearchPassword, username, password, cancellationToken);
        if (directoryProof is null) { return new(MfaSignInStatus.Denied); }

        return await BeginMfaSignInAsync(new(directoryProof.ActorId, username, directoryProof.Role, "", generation,
            directoryProof.VerifiedAtUtc, directoryProof.Metadata, directoryProof.Diagnostics.ToArray()), keys, cancellationToken, emailSender);
    }

    /// <summary>Returns the current policy generation if the OIDC role can sign in without local MFA.</summary>
    public async Task<long?> ReadOidcMfaGenerationAsync(string? role, bool assured = false)
    {
        if (!NergalRoles.IsDefined(role)) { return null; }
        var policy = await CurrentMfaPolicyAsync();
        return assured || !RequiresMfa(policy.Requirement, role!) ? policy.Version : null;
    }

    /// <summary>Validates an LDAP browser ticket against the current protected session, connection, and MFA policy.</summary>
    public async Task<bool> ValidateLdapSessionAsync(ClaimsPrincipal principal)
    {
        try { return await ReadCurrentLdapSessionAsync(principal) is not null; }
        catch (AccountStoreException error) when (error.Code == "account.corrupt") { return false; }
    }

    /// <summary>Revokes the matching LDAP ticket. A delayed logout cannot revoke a newer session.</summary>
    public async Task RevokeLdapSessionAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.AuthenticationType != LdapSessionScheme) { return; }
        context.ChangeTracker.Clear();
        try
        {
            await using var transaction = await context.Database.BeginTransactionAsync(IsolationLevel.Serializable);
            AccountConnectionPolicy.RequireSchema(context.Database.GetDbConnection(), transaction.GetDbTransaction());
            var current = await ReadCurrentLdapSessionAsync(principal);
            if (current is null) { return; }
            await RetireLdapSessionAsync(current.ActorId);
            Audit(current.ActorId, current.Role, "ldap.signedOut", current.ActorId);
            await context.SaveChangesAsync(CancellationToken.None);
            await transaction.CommitAsync(CancellationToken.None);
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException)
        { throw new AccountStoreException("account.databaseError"); }
    }

    private async Task<bool> CheckLdapProofAsync(MfaFirstFactor proof)
    {
        var connection = await ReadLdapConnectionSnapshotAsync();
        if (connection is null || !connection.Settings.Enabled || connection.Version != proof.LdapGeneration ||
            !IsDirectoryActor(proof.ActorId, connection.DirectoryId)) { return false; }
        var previous = await context.Set<LdapSession>().AsNoTracking().SingleOrDefaultAsync(row => row.ActorId == proof.ActorId);
        if (previous is not null) { return ReadTime(previous.ProofUtc) < proof.VerifiedAtUtc; }

        // A required factor can deny a new actor before it ever has a session.
        // Bound that durable actor state as well as the issued-session population.
        var directoryPrefix = $"ldap:{connection.DirectoryId:D}:";
        var actors = context.Set<MfaActorState>().Where(row => row.ActorId.StartsWith(directoryPrefix));
        return await actors.AnyAsync(row => row.ActorId == proof.ActorId) ||
            await actors.CountAsync() < LdapActorCapacity;
    }

    private async Task<ClaimsPrincipal> RecordLdapSignInAsync(MfaFirstFactor proof, long policyVersion, DateTimeOffset expiresUtc)
    {
        var connection = await ReadLdapConnectionSnapshotAsync() ?? throw new AccountStoreException("account.corrupt");
        var directoryId = connection.DirectoryId;
        var observation = new LdapProfileSnapshot(directoryId, proof.LdapGeneration, proof.Metadata, proof.VerifiedAtUtc,
            proof.Diagnostics);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var session = await context.Set<LdapSession>().SingleOrDefaultAsync(row => row.ActorId == proof.ActorId);
        if (session is null) { context.Add(session = new() { ActorId = proof.ActorId }); }
        session.ConnectionGeneration = proof.LdapGeneration;
        session.PolicyVersion = policyVersion;
        session.Role = proof.Role;
        session.Name = proof.Name;
        session.TokenDigest = LdapTokenDigest(token);
        session.ProofUtc = LdapTime(proof.VerifiedAtUtc);
        session.ExpiresUtc = LdapTime(expiresUtc);

        var profile = await context.Set<LdapProfileObservation>().SingleOrDefaultAsync(row => row.ActorId == proof.ActorId);
        if (profile is null) { context.Add(profile = new() { ActorId = proof.ActorId }); }
        profile.DirectoryId = directoryId;
        profile.ConnectionGeneration = observation.MappingVersion;
        profile.DisplayName = observation.Metadata.DisplayName;
        profile.GivenName = observation.Metadata.GivenName;
        profile.FamilyName = observation.Metadata.FamilyName;
        profile.Email = observation.Metadata.Email;
        profile.ObservedUtc = LdapTime(observation.ObservedUtc);
        profile.Diagnostics = JsonSerializer.Serialize(observation.Diagnostics);
        Audit(proof.ActorId, proof.Role, "ldap.signedIn", proof.ActorId);

        return new(new ClaimsIdentity(
        [
            new(ControllerActorIdentity.ActorClaimType, proof.ActorId),
            new(ClaimTypes.NameIdentifier, proof.ActorId),
            new(ClaimTypes.Name, proof.Name),
            new(ClaimTypes.Role, proof.Role),
            new(LdapSessionIdClaim, token),
        ], LdapSessionScheme));
    }

    private async Task RetireLdapSessionAsync(string actorId)
    {
        var row = await context.Set<LdapSession>().SingleOrDefaultAsync(session => session.ActorId == actorId);
        if (row is not null) { row.TokenDigest = ""; }
        // A bind can finish before logout but reach the write reservation afterward.
        // Retain a watermark and remove any already-reserved continuation.
        var state = await context.Set<MfaActorState>().SingleOrDefaultAsync(actor => actor.ActorId == actorId);
        if (state is not null) { state.LatestProofUtcTicks = Math.Max(state.LatestProofUtcTicks, clock.GetUtcNow().UtcTicks); }
        var pending = await context.Set<MfaPendingProof>().SingleOrDefaultAsync(proof => proof.ActorId == actorId);
        if (pending is not null) { context.Remove(pending); }
    }

    private async Task<LdapSession?> ReadCurrentLdapSessionAsync(ClaimsPrincipal principal)
    {
        var actorId = principal.FindFirstValue(ControllerActorIdentity.ActorClaimType);
        var token = principal.FindFirstValue(LdapSessionIdClaim);
        if (principal.Identity?.AuthenticationType != LdapSessionScheme || actorId?.StartsWith("ldap:", StringComparison.Ordinal) != true ||
            !ControllerActorIdentity.IsValid(actorId) || token is not { Length: 64 } ||
            !token.All(char.IsAsciiHexDigit)) { return null; }

        var current = await context.Set<LdapSession>().AsNoTracking().SingleOrDefaultAsync(row => row.ActorId == actorId);
        if (current is null || current.TokenDigest.Length != 64 ||
            !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(current.TokenDigest), Encoding.ASCII.GetBytes(LdapTokenDigest(token))) ||
            current.Role != principal.FindFirstValue(ClaimTypes.Role) || current.Name != principal.Identity.Name ||
            ReadTime(current.ExpiresUtc) <= clock.GetUtcNow()) { return null; }

        var connection = await ReadLdapConnectionSnapshotAsync();
        return connection is not null && connection.Settings.Enabled &&
            connection.Version == current.ConnectionGeneration && IsDirectoryActor(actorId, connection.DirectoryId) &&
            (await CurrentMfaPolicyAsync()).Version == current.PolicyVersion ? current : null;
    }

    private async Task<LdapProfileSnapshot?> ReadLdapProfileAsync(string actorId)
    {
        var connection = await ReadLdapConnectionSnapshotAsync();
        if (connection is null || !connection.Settings.Enabled || !IsDirectoryActor(actorId, connection.DirectoryId))
        { return null; }
        var profile = await context.Set<LdapProfileObservation>().AsNoTracking().SingleOrDefaultAsync(row => row.ActorId == actorId);
        if (profile is null || profile.ConnectionGeneration != connection.Version) { return null; }
        if (profile.DirectoryId != connection.DirectoryId || profile.Diagnostics.Length > 1024)
        { throw new AccountStoreException("account.corrupt"); }
        try
        {
            return new(profile.DirectoryId, profile.ConnectionGeneration,
                new(profile.DisplayName, profile.GivenName, profile.FamilyName, profile.Email),
                ReadTime(profile.ObservedUtc) ?? throw new AccountStoreException("account.corrupt"),
                JsonSerializer.Deserialize<string[]>(profile.Diagnostics) ?? throw new JsonException());
        }
        catch (Exception error) when (error is ArgumentException or JsonException)
        { throw new AccountStoreException("account.corrupt"); }
    }

    private async Task<LdapConnectionSnapshot?> ReadLdapConnectionSnapshotAsync()
        => await ReadLdapConnectionRowAsync() is { } row ? LdapSnapshot(row) : null;

    private static bool IsDirectoryActor(string actorId, Guid directoryId) => ControllerActorIdentity.IsValid(actorId) &&
        actorId.StartsWith($"ldap:{directoryId:D}:", StringComparison.Ordinal);

    private static string LdapTokenDigest(string token) => Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
    private static string LdapTime(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
}
