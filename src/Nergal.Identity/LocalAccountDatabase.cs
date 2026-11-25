using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Nergal.Identity;

/// <summary>Explicit offline creation of a new private application-account database, without creating an administrator.</summary>
public static class LocalAccountDatabase
{
    /// <summary>Creates a new account schema only in an already provisioned private directory; never adopts, overwrites or upgrades existing state.</summary>
    /// <remarks>Failure may leave an incomplete new file, which normal access refuses. Recovery is an explicit offline operator action, not an automatic reset.</remarks>
    /// <exception cref="ArgumentNullException">Options are null.</exception>
    /// <exception cref="AccountStoreException">Protection, existence, schema creation or durability checks fail.</exception>
    /// <exception cref="OperationCanceledException">Initialization was canceled; incomplete state is not adopted later.</exception>
    [SupportedOSPlatform("linux")]
    public static async Task InitializeAsync(LocalAccountOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("Local accounts require Linux private storage."); }
        cancellationToken.ThrowIfCancellationRequested();
        var database = PrivateAccountPath.Validate(options, false);
        if (new[] { "", "-journal", "-wal", "-shm" }.Any(suffix => File.Exists(database + suffix)))
        { throw new AccountStoreException("account.exists"); }
        try
        {
            using (var file = new FileStream(database, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            })) { file.Flush(true); }
            var builder = new DbContextOptionsBuilder<LocalAccountContext>();
            LocalAccountServices.ConfigureDatabase(builder, options, initializing: true);
            await using var context = new LocalAccountContext(builder.Options);
            if (!await context.Database.EnsureCreatedAsync(cancellationToken)) { throw new AccountStoreException("account.schemaCreation"); }
            await context.Database.ExecuteSqlRawAsync(AccountSchema.NoUpdate, cancellationToken);
            await context.Database.ExecuteSqlRawAsync(AccountSchema.NoDelete, cancellationToken);
            await context.Database.ExecuteSqlRawAsync("PRAGMA application_id=0x4e524741; PRAGMA user_version=3", cancellationToken);
            await context.Database.CloseConnectionAsync();
            // Reopen through normal header/integrity/private-path policy before
            // declaring initialization complete. No bootstrap bypass remains active.
            var validated = new DbContextOptionsBuilder<LocalAccountContext>();
            LocalAccountServices.ConfigureDatabase(validated, options);
            await using var check = new LocalAccountContext(validated.Options);
            await check.Database.OpenConnectionAsync(cancellationToken);
        }
        catch (Exception error) when (error is SqliteException or DbUpdateException or IOException or UnauthorizedAccessException)
        { throw new AccountStoreException("account.databaseError"); }
    }

}
