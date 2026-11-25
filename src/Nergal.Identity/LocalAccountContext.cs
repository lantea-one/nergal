using System.Data.Common;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Nergal.Identity;

// Framework storage entities remain infrastructure details, never Core or serialized browser DTOs.
internal sealed class LocalAdministrator : IdentityUser { }

internal sealed class LocalAccountContext : IdentityUserContext<LocalAdministrator>
{
    public LocalAccountContext(DbContextOptions<LocalAccountContext> options) : base(options) { }
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<LocalAccountState>().HasKey(state => state.UserId);
        builder.Entity<LocalAccountState>().HasOne<LocalAdministrator>().WithOne()
            .HasForeignKey<LocalAccountState>(state => state.UserId).OnDelete(DeleteBehavior.Restrict);
        builder.Entity<LocalProfile>().HasKey(profile => profile.ActorId);
        builder.Entity<IdentityAudit>().HasKey(entry => entry.Sequence);
        builder.Entity<IdentityAudit>().HasIndex(entry => entry.Action);
        builder.Entity<OidcProfileMap>().HasKey(mapping => mapping.Issuer);
        builder.Entity<OidcProfileObservation>().HasKey(observation => observation.ActorId);
        builder.Entity<OidcConnection>(entity =>
        {
            entity.HasKey(connection => connection.Id);
            entity.ToTable(table => table.HasCheckConstraint("oidc_assurance_mode", AccountSchema.OidcAssuranceCheck));
        });
        builder.Entity<LdapSession>().HasKey(session => session.ActorId);
        builder.Entity<LdapProfileObservation>().HasKey(observation => observation.ActorId);
        MfaSchema.Configure(builder);
        EmailMfaSchema.Configure(builder);
        RecoverySchema.Configure(builder);
        OAuthSchema.Configure(builder);
        builder.Entity<EmailDeliveryConnection>(entity =>
        {
            entity.HasKey(row => row.Id);
            entity.Property(row => row.Id).ValueGeneratedNever();
            entity.ToTable(table => table.HasCheckConstraint("email_delivery_settings",
                """
                "Id" = 1 AND typeof("Version") = 'integer' AND "Version" >= 1 AND
                typeof("Enabled") = 'integer' AND "Enabled" IN (0, 1) AND
                typeof("Port") = 'integer' AND "Port" BETWEEN 1 AND 65535
                """));
        });
        builder.Entity<LdapConnection>(entity =>
        {
            entity.HasKey(connection => connection.Id);
            entity.Property(connection => connection.Id).ValueGeneratedNever();
            entity.ToTable(table =>
            {
                foreach (var (name, predicate) in AccountSchema.LdapConnectionChecks)
                { table.HasCheckConstraint(name, predicate); }
            });
        });
    }
}

[SupportedOSPlatform("linux")]
internal sealed class AccountConnectionPolicy(LocalAccountOptions options, bool initializing = false) : DbConnectionInterceptor
{
    internal const int ApplicationId = 0x4e524741;
    public override InterceptionResult ConnectionOpening(DbConnection connection, ConnectionEventData eventData, InterceptionResult result)
    {
        _ = PrivateAccountPath.Validate(options, true);
        return result;
    }
    public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData,
        InterceptionResult result, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(ConnectionOpening(connection, eventData, result));

    public override void ConnectionOpened(DbConnection connection, ConnectionEndEventData eventData)
    {
        if (!initializing) { RequireSchema(connection); }
        Execute(connection, "PRAGMA foreign_keys=ON; PRAGMA synchronous=EXTRA");
        if (Text(connection, "PRAGMA journal_mode=DELETE") != "delete" || Scalar(connection, "PRAGMA synchronous") != 3)
        { throw new AccountStoreException("account.durability"); }
    }
    public override Task ConnectionOpenedAsync(DbConnection connection, ConnectionEndEventData eventData, CancellationToken cancellationToken = default)
    {
        ConnectionOpened(connection, eventData);
        return Task.CompletedTask;
    }
    internal static void RequireSchema(DbConnection connection, DbTransaction? transaction = null)
    {
        if (Scalar(connection, "PRAGMA application_id", transaction) != ApplicationId ||
            Scalar(connection, "PRAGMA user_version", transaction) != AccountSchema.Version ||
            Text(connection, "PRAGMA quick_check", transaction) != "ok" || Value(connection, "PRAGMA foreign_key_check", transaction) is not null)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        if (Scalar(connection, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('OidcConnection','LdapConnection','LdapSession','LdapProfileObservation')", transaction) != 4)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        var oidcDefinition = Text(connection, "SELECT sql FROM sqlite_master WHERE type='table' AND name='OidcConnection'", transaction);
        if (oidcDefinition is null || !oidcDefinition.Contains(
            $"CONSTRAINT \"oidc_assurance_mode\" CHECK ({AccountSchema.OidcAssuranceCheck})", StringComparison.Ordinal))
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        var oauthDefinition = Text(connection, "SELECT sql FROM sqlite_master WHERE type='table' AND name='OAuthConnection'", transaction);
        if (oauthDefinition is null || !oauthDefinition.Contains(
            $"CONSTRAINT \"oauth_connection\" CHECK ({OAuthSchema.ConnectionCheck})", StringComparison.Ordinal) ||
            Scalar(connection, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='OAuthProfileObservation'", transaction) != 1)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        var ldapDefinition = Text(connection, "SELECT sql FROM sqlite_master WHERE type='table' AND name='LdapConnection'", transaction);
        if (ldapDefinition is null || AccountSchema.LdapConnectionChecks.Any(check =>
            !ldapDefinition.Contains($"CONSTRAINT \"{check.Name}\" CHECK ({check.Predicate})", StringComparison.Ordinal)))
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        if (Scalar(connection, """
            SELECT count(*) = 17 AND sum(CASE WHEN "notnull" = 1 AND (
                (name = 'Id' AND type = 'INTEGER' AND pk = 1) OR
                (name IN ('Version', 'Enabled') AND type = 'INTEGER' AND pk = 0) OR
                (name IN ('DirectoryId', 'ServerUri', 'DialIp', 'UserBaseDn', 'SearchBindDn', 'LoginAttribute',
                    'AdministratorGroupDn', 'AuditorGroupDn', 'DisplayNameAttribute', 'GivenNameAttribute',
                    'FamilyNameAttribute', 'EmailAttribute', 'ProtectedSecret', 'UpdatedUtc') AND type = 'TEXT' AND pk = 0)
            ) THEN 1 ELSE 0 END) = 17
            FROM pragma_table_info('LdapConnection')
            """, transaction) != 1)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        if (Scalar(connection, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('OidcProfileMap','OidcProfileObservation')", transaction) != 2 ||
            Scalar(connection, "SELECT count(*) FROM pragma_table_info('LocalProfile') WHERE name IN ('GivenName','FamilyName','Email')", transaction) != 3)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        if (Scalar(connection, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('MfaPolicy','MfaActorState','MfaPendingProof','EmailDeliveryConnection','EmailMfaActorState','EmailMfaCode','RecoveryGrant')", transaction) != 7 ||
            Scalar(connection, """
                SELECT count(*) = 1 AND sum(Id = 1 AND typeof(Version) = 'integer' AND Version >= 1
                    AND typeof(Requirement) = 'integer' AND Requirement IN (0, 1, 2)) = 1
                FROM MfaPolicy
                """, transaction) != 1)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
        AccountSchema.RequireAudit(connection, transaction);
    }
    private static long Scalar(DbConnection connection, string sql, DbTransaction? transaction = null) => Convert.ToInt64(Value(connection, sql, transaction), System.Globalization.CultureInfo.InvariantCulture);
    private static string? Text(DbConnection connection, string sql, DbTransaction? transaction = null) => Value(connection, sql, transaction) as string;
    private static object? Value(DbConnection connection, string sql, DbTransaction? transaction = null)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        return command.ExecuteScalar();
    }
    internal static void Execute(DbConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
