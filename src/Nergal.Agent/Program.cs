using System.ComponentModel;
using System.Globalization;
using System.Text;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Linux;
using Nergal.LocalState;
using Nergal.Nftables;

if (!OperatingSystem.IsLinux() || args is not ["enroll", var directory] || !Path.IsPathFullyQualified(directory))
{
    Console.Error.WriteLine("Usage: nergal-agent enroll ABSOLUTE_PRIVATE_JOURNAL_DIRECTORY");
    return 2;
}
try
{
    var context = new FileInfo("/proc/self/ns/net").LinkTarget;
    if (context is null || !context.StartsWith("net:[", StringComparison.Ordinal) || !context.EndsWith(']') ||
        !ulong.TryParse(context.AsSpan(5, context.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture, out var ns) || ns == 0)
    {
        throw new IOException("Namespace unavailable.");
    }
    var clock = new LinuxBootClock();
    var boot = clock.Read().BootId;
    var ownership = new ResourceOwnership(Guid.NewGuid(), Guid.NewGuid(), 1);
    var identity = new NftTableIdentity(ownership.OwnerId, Guid.NewGuid());
    var baseline = NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, []), identity).Candidate!;
    var journal = ApplyJournal.InitializeResourceIntent(directory, ownership, baseline, clock);
    LinuxDirectoryDurability.Synchronize(directory);

    await NativeNft.Run(["--check", "--file", "-"], baseline);
    var echo = await NativeNft.Run(["--echo", "--handle", "--json", "--file", "-"], baseline);
    var created = NftTableObservation.ParseEnrollmentEcho(echo).Observation;
    if (created is null || created.Identity != identity) { throw new IOException("Creation evidence unavailable."); }
    var expected = new NftTableReceipt(boot, ns, identity, created.TableHandle, created.StateDigest);
    var listed = await NativeNft.Run(["--json", "list", "table", "inet", NftFilterCompiler.TableName], "");
    var actual = NftTableObservation.Parse(listed).Observation ?? throw new IOException("Complete observation unavailable.");
    journal.BindExpectedResource(ownership, expected, actual, ns);
    Console.WriteLine("Enrolled inet nergal_filter with an empty accept input chain.");
    return 0;
}
catch (JournalException error) { Console.Error.WriteLine(error.Code); }
catch (Exception error) when (error is IOException or UnauthorizedAccessException or Win32Exception or
    OperationCanceledException or DecoderFallbackException or Microsoft.Data.Sqlite.SqliteException or PlatformNotSupportedException)
{
    Console.Error.WriteLine("Enrollment incomplete. Inspect local journal and kernel state before recovery.");
}
return 1;
