using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Trusted server-only runtime connection. Never serialize or pass this object to a view or log.</summary>
public sealed class OidcConnectionRuntime(OidcConnectionSnapshot snapshot, string clientSecret)
{
    /// <summary>Credential-free configuration and its generation.</summary>
    public OidcConnectionSnapshot Snapshot { get; } = snapshot;
    /// <summary>Decrypted secret for the OIDC protocol handler only.</summary>
    public string ClientSecret { get; } = clientSecret;
}

public sealed partial class LocalAdministratorAccounts
{
    private const string ConnectionSecretPurpose = "Nergal.OidcConnection.ClientSecret.v1";
    private const string ConnectionSaved = "provider.connectionSaved";

    /// <summary>Reads credential-free configuration for a current Administrator. Does not decrypt stored secrets.</summary>
    public async Task<OidcConnectionSnapshot?> ReadOidcConnectionAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        _ = await ActorAsync(principal, true);
        var row = await ConnectionAsync();
        return row is null ? null : ConnectionSnapshot(row);
    }

    /// <summary>Reads the protected connection for trusted server authentication code, independently of browser authority.</summary>
    /// <remarks>This is not an HTTP API. Missing configuration returns null; invalid stored state never becomes a bootstrap fallback.</remarks>
    public async Task<OidcConnectionRuntime?> ReadOidcRuntimeAsync(IDataProtectionProvider keys)
    {
        context.ChangeTracker.Clear();
        var row = await ConnectionAsync();
        if (row is null) { return null; }
        var snapshot = ConnectionSnapshot(row);
        try
        {
            var secret = keys.CreateProtector(ConnectionSecretPurpose, row.Issuer, row.ClientId).Unprotect(row.ProtectedSecret);
            if (!ValidConnectionSecret(secret)) { throw new AccountStoreException("provider.secretUnavailable"); }
            return new(snapshot, secret);
        }
        catch (CryptographicException) { throw new AccountStoreException("provider.secretUnavailable"); }
    }

    /// <summary>Saves current trust under local Administrator authority, expected version, encryption and atomic audit.</summary>
    /// <remarks>Blank secret retains it only for the same issuer/client. Changes retire existing federated tickets. Local login is unaffected.</remarks>
    public Task<LocalProvisionResult> SaveOidcConnectionAsync(ClaimsPrincipal principal, long expectedVersion,
        OidcConnectionSettings settings, string replacementSecret, IDataProtectionProvider keys)
        => MutateAsync(principal, true, async actor =>
        {
            if (actor.LocalId is null) { return Failure("provider.localAdministratorRequired"); }
            if (expectedVersion < 0 || expectedVersion >= long.MaxValue - 1 || settings is null || !settings.IsValid ||
                replacementSecret is null || replacementSecret.Length != 0 && !ValidConnectionSecret(replacementSecret))
            { return Failure("provider.invalid"); }
            var row = await ConnectionAsync();
            if ((row?.Version ?? 0) != expectedVersion) { return Failure("provider.stale"); }
            if (replacementSecret.Length == 0 && (row is null || row.Issuer != settings.Issuer || row.ClientId != settings.ClientId))
            { return Failure("provider.secretRequired"); }
            var protectedSecret = row?.ProtectedSecret ?? "";
            if (replacementSecret.Length != 0)
            {
                try { protectedSecret = keys.CreateProtector(ConnectionSecretPurpose, settings.Issuer, settings.ClientId).Protect(replacementSecret); }
                catch (CryptographicException) { throw new AccountStoreException("provider.secretUnavailable"); }
            }
            if (row is null) { row = new(); context.Add(row); }
            else { context.Attach(row); context.Entry(row).State = EntityState.Modified; }
            row.Version = expectedVersion + 1; row.Enabled = settings.Enabled;
            row.Issuer = settings.Issuer; row.ClientId = settings.ClientId; row.CallbackUri = settings.CallbackUri;
            row.GroupClaim = settings.GroupClaim;
            row.AdministratorGroups = JsonSerializer.Serialize(settings.AdministratorGroups);
            row.AuditorGroups = JsonSerializer.Serialize(settings.AuditorGroups);
            row.MfaAssuranceMode = (int)settings.MfaAssuranceMode;
            row.MfaAssuranceClaim = settings.MfaAssuranceClaim;
            row.MfaAssuranceValue = settings.MfaAssuranceValue;
            row.ProtectedSecret = protectedSecret; row.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, ConnectionSaved, "oidc");
            return Success();
        });

    // Called from ActorAsync, within the serialized transaction for identity mutations and profile refresh.
    private async Task<bool> IsCurrentOidcGenerationAsync(string? generation, string issuer)
    {
        var row = await ConnectionAsync();
        if (row is null) { return generation == "0"; }
        var snapshot = ConnectionSnapshot(row);
        return snapshot.Settings.Enabled && snapshot.Settings.Issuer == issuer &&
            generation == snapshot.Version.ToString(CultureInfo.InvariantCulture);
    }

    private async Task<OidcConnection?> ConnectionAsync()
    {
        // Check the row and its save watermark in the same SQLite snapshot.
        var history = context.Database.SqlQuery<long>(
            $"SELECT count(*) AS Value FROM IdentityAudit WHERE Action = {ConnectionSaved}");
        var entries = await (from generation in history
                             from row in context.Set<OidcConnection>().AsNoTracking().DefaultIfEmpty()
                             select new { Generation = generation, Row = row }).Take(2).ToArrayAsync();
        if (entries.Length != 1 || entries[0].Row is { Id: not 1 } ||
            entries[0].Generation != (entries[0].Row?.Version ?? 0))
        { throw new AccountStoreException("account.corrupt"); }
        // Mutations attach the detached snapshot only after serialized reservation.
        return entries[0].Row;
    }

    private static OidcConnectionSnapshot ConnectionSnapshot(OidcConnection row)
    {
        try
        {
            if (row.AdministratorGroups.Length > 16384 || row.AuditorGroups.Length > 16384) { throw new JsonException(); }
            var settings = new OidcConnectionSettings(row.Enabled, row.Issuer, row.ClientId, row.CallbackUri, row.GroupClaim,
                JsonSerializer.Deserialize<string[]>(row.AdministratorGroups) ?? throw new JsonException(),
                JsonSerializer.Deserialize<string[]>(row.AuditorGroups) ?? throw new JsonException(),
                (OidcMfaAssuranceMode)row.MfaAssuranceMode, row.MfaAssuranceClaim, row.MfaAssuranceValue);
            if (row.Version < 1 || row.Version >= long.MaxValue || !settings.IsValid || row.ProtectedSecret.Length is < 1 or > 16384)
            { throw new AccountStoreException("account.corrupt"); }
            return new(row.Version, settings, true, ReadTime(row.UpdatedUtc) ?? throw new AccountStoreException("account.corrupt"));
        }
        catch (JsonException) { throw new AccountStoreException("account.corrupt"); }
    }

    private static bool ValidConnectionSecret(string value)
    {
        if (value.Length is < 1 or > 4096 || string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl)) { return false; }
        try { _ = new UTF8Encoding(false, true).GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }
}
