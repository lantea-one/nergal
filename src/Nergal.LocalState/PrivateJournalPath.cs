namespace Nergal.LocalState;

internal static class PrivateJournalPath
{
    internal const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    internal const UnixFileMode FileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static string Validate(string directory, bool databaseRequired)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The local journal requires Linux.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory))
        {
            throw new JournalException("path.absoluteRequired");
        }

        var full = Path.GetFullPath(directory);
        for (DirectoryInfo? part = new(full); part is not null; part = part.Parent)
        {
            if (part.LinkTarget is not null)
            {
                throw new JournalException("path.symlink");
            }
        }

        var directoryMetadata = LinuxFileMetadata.Read(full) ?? throw new JournalException("path.directoryMissing");
        LinuxFileMetadata.Validate(directoryMetadata, true);

        var database = Path.Combine(full, "journal.db");
        var databaseExists = false;
        foreach (var path in new[] { database, database + "-journal", database + "-wal", database + "-shm" })
        {
            var metadata = LinuxFileMetadata.Read(path);
            if (metadata is null)
            {
                continue;
            }

            LinuxFileMetadata.Validate(metadata.Value, false);
            if (path == database)
            {
                databaseExists = true;
            }
        }
        if (databaseRequired && !databaseExists)
        {
            throw new JournalException("journal.missing");
        }

        return database;
    }
}
