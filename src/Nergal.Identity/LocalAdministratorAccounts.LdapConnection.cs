using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Protected server-side adapter input for one explicit LDAP attempt.</summary>
internal sealed class LdapConnectionRuntime(LdapConnectionSnapshot snapshot, string searchPassword)
{
    internal LdapConnectionSnapshot Snapshot { get; } = snapshot;
    internal LdapDirectorySettings Directory { get; } = snapshot.Settings.ToDirectorySettings(snapshot.DirectoryId);
    internal IPAddress DialAddress { get; } = IPAddress.Parse(snapshot.Settings.DialIp);
    internal string SearchPassword { get; } = searchPassword;
}

public sealed partial class LocalAdministratorAccounts
{
    private const string LdapSecretPurpose = "Nergal.LdapConnection.SearchPassword.v1";
    private const string LdapConnectionSaved = "provider.ldapConnectionSaved";

    /// <summary>Reads credential-free configuration under current local Administrator authority.</summary>
    /// <returns>The saved configuration, or null before the first save.</returns>
    /// <exception cref="AccountStoreException">The actor is denied or the account store fails validation.</exception>
    public async Task<LdapConnectionSnapshot?> ReadLdapConnectionAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        if ((await ActorAsync(principal, administrator: true)).LocalId is null)
        { throw new AccountStoreException("provider.localAdministratorRequired"); }
        var row = await ReadLdapConnectionRowAsync();
        return row is null ? null : LdapSnapshot(row);
    }

    /// <summary>Loads a bind secret for an explicit adapter attempt with the current enabled generation.</summary>
    /// <returns>Adapter input, or null when the generation is stale or LDAP is unavailable by configuration.</returns>
    /// <remarks>The caller must recheck the generation before accepting directory evidence.</remarks>
    internal async Task<LdapConnectionRuntime?> ReadLdapRuntimeAsync(long expectedGeneration, IDataProtectionProvider keys)
    {
        context.ChangeTracker.Clear();
        var row = await ReadLdapConnectionRowAsync();
        if (row is null) { return null; }
        var snapshot = LdapSnapshot(row);
        if (!snapshot.Settings.Enabled || snapshot.Version != expectedGeneration) { return null; }
        try
        {
            var secret = LdapProtector(keys, snapshot.DirectoryId, snapshot.Settings).Unprotect(row.ProtectedSecret);
            if (!LdapDirectoryAuthenticator.ValidPassword(secret))
            { throw new AccountStoreException("provider.secretUnavailable"); }
            return new(snapshot, secret);
        }
        catch (Exception error) when (error is CryptographicException or FormatException)
        { throw new AccountStoreException("provider.secretUnavailable"); }
    }

    /// <summary>Saves trust with a serialized local Administrator recheck, expected version and atomic audit.</summary>
    /// <remarks>Version zero creates the singleton. An empty replacement retains the bind password only for unchanged bind trust.
    /// Saving settings does not contact the directory.</remarks>
    /// <exception cref="AccountStoreException">Current local authority or the protected store failed validation.</exception>
    public Task<LocalProvisionResult> SaveLdapConnectionAsync(ClaimsPrincipal principal, long expectedVersion,
        LdapConnectionSettings settings, string replacementSecret, IDataProtectionProvider keys)
        => MutateAsync(principal, true, async actor =>
        {
            if (actor.LocalId is null) { return Failure("provider.localAdministratorRequired"); }
            if (expectedVersion < 0 || expectedVersion >= long.MaxValue - 1 || settings is null ||
                replacementSecret is null || replacementSecret.Length != 0 && !LdapDirectoryAuthenticator.ValidPassword(replacementSecret))
            { return Failure("provider.invalid"); }

            var row = await ReadLdapConnectionRowAsync();
            var current = row is null ? null : LdapSnapshot(row);
            if ((current?.Version ?? 0) != expectedVersion) { return Failure("provider.stale"); }

            var newDirectory = current is null || current.Settings.ServerUri != settings.ServerUri ||
                current.Settings.DialIp != settings.DialIp || current.Settings.UserBaseDn != settings.UserBaseDn;
            var directoryId = newDirectory ? Guid.NewGuid() : current!.DirectoryId;
            if (!settings.IsValid(directoryId)) { return Failure("provider.invalid"); }
            if (replacementSecret.Length == 0 && (newDirectory || current!.Settings.SearchBindDn != settings.SearchBindDn))
            { return Failure("provider.secretRequired"); }

            var protectedSecret = row?.ProtectedSecret ?? "";
            if (replacementSecret.Length != 0)
            {
                try { protectedSecret = LdapProtector(keys, directoryId, settings).Protect(replacementSecret); }
                catch (CryptographicException) { throw new AccountStoreException("provider.secretUnavailable"); }
            }

            if (newDirectory && current is not null)
            {
                // A replacement receives a fresh namespace. Keep descriptive
                // profiles and audit, but retire obsolete authentication state.
                var retiredPrefix = $"ldap:{current.DirectoryId:D}:";
                await context.Set<MfaPendingProof>().Where(proof => proof.ActorId.StartsWith(retiredPrefix)).ExecuteDeleteAsync();
                await context.Set<MfaActorState>().Where(state => state.ActorId.StartsWith(retiredPrefix)).ExecuteDeleteAsync();
                await context.Set<LdapSession>().Where(session => session.ActorId.StartsWith(retiredPrefix)).ExecuteDeleteAsync();
            }

            if (row is null) { row = new(); context.Add(row); }
            else { context.Attach(row); context.Entry(row).State = EntityState.Modified; }
            row.Version = expectedVersion + 1;
            row.DirectoryId = directoryId.ToString("D");
            row.Enabled = settings.Enabled;
            row.ServerUri = settings.ServerUri;
            row.DialIp = settings.DialIp;
            row.UserBaseDn = settings.UserBaseDn;
            row.SearchBindDn = settings.SearchBindDn;
            row.LoginAttribute = settings.LoginAttribute;
            row.AdministratorGroupDn = settings.AdministratorGroupDn;
            row.AuditorGroupDn = settings.AuditorGroupDn;
            row.DisplayNameAttribute = settings.ProfileMapping.DisplayNameAttribute;
            row.GivenNameAttribute = settings.ProfileMapping.GivenNameAttribute;
            row.FamilyNameAttribute = settings.ProfileMapping.FamilyNameAttribute;
            row.EmailAttribute = settings.ProfileMapping.EmailAttribute;
            row.ProtectedSecret = protectedSecret;
            row.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, LdapConnectionSaved, "ldap");
            return Success();
        });

    private async Task<LdapConnection?> ReadLdapConnectionRowAsync()
    {
        // Each generation commits exactly one append-only event. Compare both in
        // one SQLite statement so a concurrent save cannot split the snapshot.
        var generations = context.Database.SqlQuery<long>(
            $"SELECT count(*) AS Value FROM IdentityAudit WHERE Action = {LdapConnectionSaved}");
        var entries = await (from generation in generations
                             from row in context.Set<LdapConnection>().AsNoTracking().DefaultIfEmpty()
                             select new { Generation = generation, Row = row }).Take(2).ToArrayAsync();
        if (entries.Length != 1) { throw new AccountStoreException("account.corrupt"); }
        var entry = entries[0];
        if (entry.Row is { Id: not 1 } || (entry.Row?.Version ?? 0) != entry.Generation)
        { throw new AccountStoreException("account.corrupt"); }
        return entry.Row;
    }

    private static LdapConnectionSnapshot LdapSnapshot(LdapConnection row)
    {
        var settings = new LdapConnectionSettings(row.Enabled, row.ServerUri, row.DialIp, row.UserBaseDn,
            row.SearchBindDn, row.LoginAttribute, row.AdministratorGroupDn, row.AuditorGroupDn,
            new(row.DisplayNameAttribute, row.GivenNameAttribute, row.FamilyNameAttribute, row.EmailAttribute));
        if (row.Version is < 1 or >= long.MaxValue || !Guid.TryParseExact(row.DirectoryId, "D", out var directoryId) ||
            row.DirectoryId != directoryId.ToString("D") || !settings.IsValid(directoryId) ||
            row.ProtectedSecret.Length is < 1 or > 16384)
        { throw new AccountStoreException("account.corrupt"); }
        return new(row.Version, directoryId, settings, true,
            ReadTime(row.UpdatedUtc) ?? throw new AccountStoreException("account.corrupt"));
    }

    private static IDataProtector LdapProtector(IDataProtectionProvider keys, Guid directoryId, LdapConnectionSettings settings)
        => keys.CreateProtector(LdapSecretPurpose, directoryId.ToString("D"), settings.ServerUri, settings.DialIp,
            settings.UserBaseDn, settings.SearchBindDn);
}
