using System.Security.Cryptography;
using System.Runtime.Versioning;
using Nergal.Linux;
using System.Text;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>A private, read-only source snapshot. Import does not grant execution or management authority.</summary>
public sealed class NativePolicySource
{
    /// <summary>Snapshots exact source and its shared viewer/import analysis; callers supply a verified content digest.</summary>
    /// <param name="name">Local operator-assigned source name.</param>
    /// <param name="text">Exact native source, retained without lossy translation.</param>
    /// <param name="digest">SHA-256 of original UTF-8 bytes, verified by database ingestion or staging.</param>
    /// <exception cref="ArgumentNullException">A required value is null.</exception>
    public NativePolicySource(string name, string text, string digest)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(text);
        ArgumentNullException.ThrowIfNull(digest);
        Name = name; Text = text; Digest = digest;
        Analysis = NativeSourceAnalyzer.Analyze(text);
    }

    /// <summary>Gets the operator-assigned private display name.</summary>
    public string Name { get; }
    /// <summary>Gets the exact private source text.</summary>
    public string Text { get; }
    /// <summary>Gets the previously verified original UTF-8 digest.</summary>
    public string Digest { get; }
    /// <summary>Gets the one analysis used by source viewing and future semantic import from this snapshot.</summary>
    public NativeSourceAnalysis Analysis { get; }
    /// <summary>Gets the value-masked review from the shared source analysis.</summary>
    public NativeMigrationReview Review => Analysis.Review;
    /// <summary>Returns a type description without private source names or values.</summary>
    public override string ToString() => "Native policy source snapshot";
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
