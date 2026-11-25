using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Nergal.Core.Identity;

namespace Nergal.Identity;

/// <summary>Verifies a first factor and reads role and profile evidence from one explicitly trusted directory.</summary>
/// <remarks>A directory proof grants no application session or MFA assurance. The caller must bind it to current trust and policy.</remarks>
internal sealed class LdapDirectoryAuthenticator(TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan VerificationLimit = TimeSpan.FromSeconds(10);
    private const string EntryUuid = "entryUUID";
    private const string EntryCsn = "entryCSN";

    /// <summary>Returns a credential-free proof, or null when configuration, credentials, the directory or its evidence fail validation.</summary>
    /// <exception cref="OperationCanceledException">The caller cancelled verification.</exception>
    internal async Task<LdapDirectoryProof?> VerifyAsync(LdapDirectorySettings settings, IPAddress dialAddress,
        string searchPassword, string username, string password, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!settings.IsValid || !LdapUserLookup.IsValidUsername(username) ||
            !ValidPassword(searchPassword) || !ValidPassword(password)) { return null; }

        var endpoint = settings.GetEndpoint();
        var peerName = endpoint.IdnHost;
        if (IPAddress.TryParse(peerName, out var literalAddress) && !literalAddress.Equals(dialAddress)) { return null; }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(VerificationLimit);
        var token = deadline.Token;
        try
        {
            using var service = await LdapWireConnection.OpenAsync(dialAddress, peerName, endpoint.Port, token);
            if (!await service.BindAsync(settings.SearchBindDn, searchPassword, token)) { return null; }

            var results = await service.SearchAsync(settings.UserBaseDn, subtree: true,
                settings.LoginAttribute, username, [EntryUuid], token);
            if (results.Count != 1 || ReadUuid(results[0]) is not { } entryId) { return null; }
            var userDn = results[0].DistinguishedName;
            if (string.IsNullOrWhiteSpace(userDn) || !ProfileMetadata.ValidText(userDn, 512)) { return null; }

            DateTimeOffset verifiedAtUtc;
            using (var user = await LdapWireConnection.OpenAsync(dialAddress, peerName, endpoint.Port, token))
            {
                if (!await user.BindAsync(userDn, password, token)) { return null; }
                verifiedAtUtc = clock.GetUtcNow().ToUniversalTime();
                // Re-read the immutable identity through the connection that accepted the password.
                var boundEntry = await ReadMatchingEntryAsync(user, userDn, entryId, [EntryUuid], token);
                if (boundEntry is null) { return null; }
            }

            var role = await ReadRoleAsync(service, settings, userDn, token);
            if (role is null) { return null; }

            var entry = await ReadMatchingEntryAsync(service, userDn, entryId,
                [EntryUuid, .. settings.ProfileMapping.SelectedAttributes], token);
            if (entry is null) { return null; }
            var (metadata, diagnostics) = settings.ProfileMapping.Project(entry.Attributes);
            token.ThrowIfCancellationRequested();
            return new(ControllerActorIdentity.FromLdapAccount(settings.DirectoryId, entryId), role,
                verifiedAtUtc, metadata, diagnostics);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return null; }
        catch (Exception exception) when (exception is IOException or SocketException or AuthenticationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    private static async Task<string?> ReadRoleAsync(LdapWireConnection connection, LdapDirectorySettings settings,
        string userDn, CancellationToken cancellationToken)
    {
        var administratorBefore = await ReadGroupVersionAsync(connection, settings.AdministratorGroupDn, cancellationToken);
        var auditorBefore = await ReadGroupVersionAsync(connection, settings.AuditorGroupDn, cancellationToken);
        if (administratorBefore is null || auditorBefore is null || administratorBefore.Id == auditorBefore.Id) { return null; }

        var administrator = await connection.CompareMemberAsync(settings.AdministratorGroupDn, userDn, cancellationToken);
        var auditor = await connection.CompareMemberAsync(settings.AuditorGroupDn, userDn, cancellationToken);
        if (administrator == auditor) { return null; }

        // Both comparisons must fall inside a single interval with unchanged versions of both role groups.
        var administratorAfter = await ReadGroupVersionAsync(connection, settings.AdministratorGroupDn, cancellationToken);
        var auditorAfter = await ReadGroupVersionAsync(connection, settings.AuditorGroupDn, cancellationToken);
        return ResolveRole(administrator, auditor, administratorBefore, auditorBefore, administratorAfter, auditorAfter);
    }

    internal static string? ResolveRole(bool administrator, bool auditor, LdapGroupVersion administratorBefore,
        LdapGroupVersion auditorBefore, LdapGroupVersion? administratorAfter, LdapGroupVersion? auditorAfter) =>
        administrator != auditor && administratorBefore.Id != auditorBefore.Id &&
        administratorBefore == administratorAfter && auditorBefore == auditorAfter
            ? administrator ? NergalRoles.Administrator : NergalRoles.Auditor
            : null;

    private static async Task<LdapGroupVersion?> ReadGroupVersionAsync(LdapWireConnection connection, string groupDn,
        CancellationToken cancellationToken)
    {
        var groups = await connection.SearchAsync(groupDn, subtree: false, "objectClass", "groupOfNames",
            [EntryUuid, EntryCsn], cancellationToken);
        if (groups.Count != 1 || ReadUuid(groups[0]) is not { } id ||
            !groups[0].Attributes.TryGetValue(EntryCsn, out var values) || values is not { Count: 1 } ||
            values[0] is not { Length: > 0 and <= 128 } bytes || bytes.Any(value => value is <= 0x20 or > 0x7e))
        { return null; }
        return new(id, groups[0].DistinguishedName, Encoding.ASCII.GetString(bytes));
    }

    private static async Task<LdapWireEntry?> ReadMatchingEntryAsync(LdapWireConnection connection, string userDn,
        Guid entryId, IReadOnlyList<string> attributes, CancellationToken cancellationToken)
    {
        var entries = await connection.SearchAsync(userDn, subtree: false, EntryUuid, entryId.ToString("D"),
            attributes, cancellationToken);
        if (entries.Count != 1 || entries[0].DistinguishedName != userDn || ReadUuid(entries[0]) != entryId)
        { return null; }
        return entries[0];
    }

    internal static Guid? ReadUuid(LdapWireEntry entry)
    {
        if (!entry.Attributes.TryGetValue(EntryUuid, out var values) ||
            values is not { Count: 1 } || values[0] is not { Length: 36 } bytes)
        { return null; }
        var text = Encoding.ASCII.GetString(bytes);
        return Guid.TryParseExact(text, "D", out var uuid) && uuid != Guid.Empty &&
            string.Equals(text, uuid.ToString("D"), StringComparison.OrdinalIgnoreCase) ? uuid : null;
    }

    /// <summary>Checks the supported simple-bind credential format without altering submitted text.</summary>
    internal static bool ValidPassword(string? password)
    {
        if (password is not { Length: > 0 and <= 2048 } || password.Contains('\0')) { return false; }
        try { return StrictUtf8.GetByteCount(password) <= 4096; }
        catch (EncoderFallbackException) { return false; }
    }
}

/// <summary>Credential-free LDAP evidence available to the controller after directory verification.</summary>
internal sealed record LdapDirectoryProof(string ActorId, string Role, DateTimeOffset VerifiedAtUtc,
    ProfileMetadata Metadata, IReadOnlyList<string> Diagnostics);

/// <summary>An observed version of one OpenLDAP role group entry.</summary>
internal sealed record LdapGroupVersion(Guid Id, string DistinguishedName, string ChangeSequence);
