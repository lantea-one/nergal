using System.Security.Cryptography;
using System.Runtime.Versioning;
using Nergal.Linux;
using System.Text;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>A private, read-only source snapshot. Import does not grant execution or management authority.</summary>
/// <param name="Name">Local operator-assigned source name.</param>
/// <param name="Text">Exact native source, retained for inspection without lossy translation.</param>
/// <param name="Digest">SHA-256 of the original UTF-8 bytes.</param>
public sealed record NativePolicySource(string Name, string Text, string Digest)
{
    /// <summary>Gets the read-only lexical review of this immutable source snapshot.</summary>
    public NativeMigrationReview Review { get; } = NativeMigrationReviewer.Review(Text);
}

/// <summary>A private downloadable review bound to the exact source bytes; it contains no executable candidate.</summary>
public sealed record NativeSourceMigrationReport(string Name, string SourceSha256, NativeMigrationReview Review)
{
    /// <summary>Gets the report contract version, independent of the policy schema.</summary>
    public int SchemaVersion => 1;
}

/// <summary>Bounded startup snapshots from an explicitly configured private import directory.</summary>
/// <remarks>Only trusted deployment configuration selects the directory. HTTP input never selects a path.
/// Native configuration is displayed as escaped text and is never passed to a shell or firewall agent.</remarks>
[SupportedOSPlatform("linux")]
public sealed class NativePolicySourceCatalog
{
    /// <summary>Loads at most 32 regular, non-linked <c>*.conf</c> files, each bounded to 512 KiB.</summary>
    /// <exception cref="IOException">The source directory or a file is linked, oversized, or otherwise unsafe.</exception>
    public NativePolicySourceCatalog(string directory)
    {
        var root = new DirectoryInfo(directory);
        if (!root.Exists || root.LinkTarget is not null) { throw new IOException("source.directoryInvalid"); }
        var paths = root.GetFiles("*.conf").OrderBy(f => f.Name, StringComparer.Ordinal).ToArray();
        if (paths.Length > 32) { throw new IOException("source.tooManyFiles"); }
        var sources = new List<NativePolicySource>();
        foreach (var file in paths)
        {
            var metadata = LinuxFileSystem.Read(file.FullName);
            if (metadata is not { Type: LinuxNodeType.RegularFile, LinkCount: 1 } || file.Length > 524_288)
            { throw new IOException("source.fileInvalid"); }
            // Startup-only operator input. A bounded read also handles growth after metadata inspection.
            using var stream = file.OpenRead();
            using var buffer = new MemoryStream();
            var bytes = new byte[8192];
            int count;
            while ((count = stream.Read(bytes)) > 0)
            {
                if (buffer.Length + count > 524_288) { throw new IOException("source.fileInvalid"); }
                buffer.Write(bytes, 0, count);
            }
            var content = buffer.ToArray();
            sources.Add(new(Path.GetFileNameWithoutExtension(file.Name), new UTF8Encoding(false, true).GetString(content),
                Convert.ToHexStringLower(SHA256.HashData(content))));
        }
        Sources = sources.AsReadOnly();
    }

    /// <summary>Gets immutable imported sources; no native configuration is executed.</summary>
    public IReadOnlyList<NativePolicySource> Sources { get; }
}
