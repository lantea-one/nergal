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
        var account = builder.Entity<LocalAdministrator>();
        account.Property<int>("AdministratorSlot").HasDefaultValue(1);
        account.HasIndex("AdministratorSlot").IsUnique();
        account.ToTable("AspNetUsers", table => table.HasCheckConstraint("CK_AdministratorSlot", "AdministratorSlot = 1"));
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
        if (Scalar(connection, "PRAGMA application_id", transaction) != ApplicationId || Scalar(connection, "PRAGMA user_version", transaction) != 1 ||
            Text(connection, "PRAGMA quick_check", transaction) != "ok" || Value(connection, "PRAGMA foreign_key_check", transaction) is not null)
        { throw new AccountStoreException("account.schemaOrIntegrity"); }
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
