using System.Runtime.Versioning;

namespace Nergal.Identity;

[SupportedOSPlatform("linux")]
internal static class PrivateAccountPath
{
    internal static string Validate(LocalAccountOptions options, bool requireDatabase)
    {
        PrivateIdentityPath.RequireDirectory(options.Directory);
        var database = Path.Combine(options.Directory, "accounts.db");
        foreach (var suffix in new[] { "", "-journal", "-wal", "-shm" })
        {
            var node = PrivateIdentityPath.ReadFile(database + suffix);
            if (node is null && suffix == "" && requireDatabase)
            { throw new AccountStoreException("account.databaseMissing"); }
        }
        return database;
    }
}
