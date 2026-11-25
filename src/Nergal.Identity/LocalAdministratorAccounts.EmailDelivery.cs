using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Nergal.Core.Identity;

namespace Nergal.Identity;

internal sealed class EmailDeliveryConnection
{
    public int Id { get; set; } = 1;
    public long Version { get; set; }
    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string FromAddress { get; set; } = "";
    public string UserName { get; set; } = "";
    public byte[] ProtectedPassword { get; set; } = [];
    public string UpdatedUtc { get; set; } = "";
}

/// <summary>Transient server-side credentials for the configured SMTP relay.</summary>
public sealed class EmailDeliveryRuntime(EmailDeliverySnapshot snapshot, string password)
{
    /// <summary>Gets the credential-free configuration for this attempt.</summary>
    public EmailDeliverySnapshot Snapshot { get; } = snapshot;

    /// <summary>Gets the SMTP password for immediate use by the delivery client.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string Password { get; } = password;
}

public sealed partial class LocalAdministratorAccounts
{
    private const string EmailDeliverySaved = "mfa.emailDeliverySaved";

    /// <summary>Reads email delivery settings under current local Administrator authority.</summary>
    public async Task<EmailDeliverySnapshot?> ReadEmailDeliveryAsync(ClaimsPrincipal principal)
    {
        context.ChangeTracker.Clear();
        if ((await ActorAsync(principal, true)).LocalId is null)
        { throw new AccountStoreException("provider.localAdministratorRequired"); }
        return await ReadEmailDeliveryRowAsync() is { } row ? DeliverySnapshot(row) : null;
    }

    /// <summary>Saves an explicitly versioned relay and its protected credential without sending mail.</summary>
    public Task<LocalProvisionResult> SaveEmailDeliveryAsync(ClaimsPrincipal principal, long expectedVersion,
        EmailDeliverySettings settings, string replacementPassword, IDataProtectionProvider keys)
        => MutateAsync(principal, true, async actor =>
        {
            if (actor.LocalId is null) { return Failure("provider.localAdministratorRequired"); }
            if (settings is null || !settings.IsValid || expectedVersion is < 0 or >= long.MaxValue - 1 ||
                replacementPassword is not { Length: <= 1024 } || !ValidDeliveryPassword(replacementPassword) ||
                settings.UserName.Length == 0 && replacementPassword.Length != 0)
            { return Failure("mfa.deliveryInvalid"); }

            var row = await ReadEmailDeliveryRowAsync();
            var current = row is null ? null : DeliverySnapshot(row);
            if ((current?.Version ?? 0) != expectedVersion) { return Failure("mfa.stale"); }
            if (settings.UserName.Length != 0 && replacementPassword.Length == 0 &&
                (current is null || !current.HasPassword || settings.Host != current.Settings.Host ||
                 settings.Port != current.Settings.Port || settings.UserName != current.Settings.UserName))
            { return Failure("mfa.deliveryPasswordRequired"); }

            var secret = settings.UserName.Length == 0 ? [] : row?.ProtectedPassword ?? [];
            if (replacementPassword.Length != 0)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(replacementPassword);
                try { secret = DeliveryProtector(keys, settings).Protect(bytes); }
                catch (CryptographicException) { throw new AccountStoreException("mfa.deliveryUnavailable"); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }

            if (row is null) { context.Add(row = new()); }
            else { context.Attach(row); context.Entry(row).State = EntityState.Modified; }
            row.Version = expectedVersion + 1;
            row.Enabled = settings.Enabled;
            row.Host = settings.Host;
            row.Port = settings.Port;
            row.FromAddress = settings.FromAddress;
            row.UserName = settings.UserName;
            row.ProtectedPassword = secret;
            row.UpdatedUtc = Now();
            Audit(actor.Id, actor.Role, EmailDeliverySaved, "smtp");
            return Success();
        });

    /// <summary>Opens the relay credential only for an explicit delivery using the reserved generation.</summary>
    public async Task<EmailDeliveryRuntime?> ReadEmailDeliveryRuntimeAsync(long generation, IDataProtectionProvider keys)
    {
        context.ChangeTracker.Clear();
        var row = await ReadEmailDeliveryRowAsync();
        if (row is null || row.Version != generation) { return null; }
        var snapshot = DeliverySnapshot(row);
        if (!snapshot.Settings.Enabled) { return null; }
        if (!snapshot.HasPassword) { return new(snapshot, ""); }

        byte[]? plaintext = null;
        try
        {
            plaintext = DeliveryProtector(keys, snapshot.Settings).Unprotect(row.ProtectedPassword);
            var password = new System.Text.UTF8Encoding(false, true).GetString(plaintext);
            if (password.Length == 0 || !ValidDeliveryPassword(password))
            { throw new AccountStoreException("mfa.deliveryUnavailable"); }
            return new(snapshot, password);
        }
        catch (Exception error) when (error is CryptographicException or System.Text.DecoderFallbackException)
        { throw new AccountStoreException("mfa.deliveryUnavailable"); }
        finally { if (plaintext is not null) { CryptographicOperations.ZeroMemory(plaintext); } }
    }

    private async Task<bool> HasIndependentLocalRecoveryAsync(string excludedUserId, IDataProtectionProvider? keys)
    {
        var policy = await CurrentMfaPolicyAsync();
        return await HasRecoveryAdministratorAsync(keys, policy.Requirement, excludedUserId);
    }

    private async Task<long?> EnabledEmailDeliveryGenerationAsync()
    {
        var row = await ReadEmailDeliveryRowAsync();
        return row is not null && DeliverySnapshot(row).Settings.Enabled ? row.Version : null;
    }

    private async Task<EmailDeliveryConnection?> ReadEmailDeliveryRowAsync()
    {
        var history = context.Database.SqlQuery<long>(
            $"SELECT count(*) AS Value FROM IdentityAudit WHERE Action = {EmailDeliverySaved}");
        var entries = await (from generation in history
                             from row in context.Set<EmailDeliveryConnection>().AsNoTracking().DefaultIfEmpty()
                             select new { Generation = generation, Row = row }).Take(2).ToArrayAsync();
        if (entries.Length != 1 || entries[0].Row is { Id: not 1 } ||
            entries[0].Generation != (entries[0].Row?.Version ?? 0))
        { throw new AccountStoreException("account.corrupt"); }
        return entries[0].Row;
    }

    private static EmailDeliverySnapshot DeliverySnapshot(EmailDeliveryConnection row)
    {
        var settings = new EmailDeliverySettings(row.Enabled, row.Host, row.Port, row.FromAddress, row.UserName);
        if (!settings.IsValid || row.Version is < 1 or >= long.MaxValue ||
            row.ProtectedPassword.Length > 8192 || (settings.UserName.Length == 0) != (row.ProtectedPassword.Length == 0))
        { throw new AccountStoreException("account.corrupt"); }
        return new(row.Version, settings, row.ProtectedPassword.Length != 0,
            ReadTime(row.UpdatedUtc) ?? throw new AccountStoreException("account.corrupt"));
    }

    private static bool ValidDeliveryPassword(string password) => ProfileMetadata.ValidText(password, 512) && !password.Any(char.IsControl);

    private static IDataProtector DeliveryProtector(IDataProtectionProvider keys, EmailDeliverySettings settings)
        => keys.CreateProtector("Nergal.Mfa.SmtpPassword.v1", settings.Host, settings.Port.ToString(CultureInfo.InvariantCulture), settings.UserName);
}
