using System.Globalization;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.LocalState;
using Nergal.Nftables;

// Storage/observation probe only: all nft execution belongs to the guarded Python harness.
if (args.Length != 2)
{
    return 2;
}

var owner = Guid.Parse("00000000-0000-0000-0000-000000000001");
var resource = Guid.Parse("00000000-0000-0000-0000-000000000002");
var agent = Guid.Parse("00000000-0000-0000-0000-000000000003");
var identity = new NftTableIdentity(owner, resource);
string Artifact(FilterVerdict verdict) => NftFilterCompiler.Compile(new(1, verdict, []), identity).Candidate!;
try
{
    if (args[0] == "foreign")
    {
        Console.Write(NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, []), new NftTableIdentity(agent, resource)).Candidate);
        return 0;
    }
    if (args[0] is "prepare" or "prepare-family")
    {
        FilterRule[] rules = args[0] == "prepare" ? [] :
            [new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop), new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept)];
        var baseline = NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, rules), identity).Candidate!;
        ApplyJournal.Initialize(args[1], new(agent, owner, 1), baseline);
        Console.Write(baseline);
        return 0;
    }
    var store = ApplyJournal.Open(args[1]);
    if (args[0] == "receipt")
    {
        var receipt = store.ReadExpectedResource();
        Console.WriteLine(receipt is null ? "UNBOUND" : JsonSerializer.Serialize(new { receipt.TableHandle, Digest = receipt.StateDigest.Value }));
        return 0;
    }
    if (args[0] == "try-start")
    {
        store.Start(new(Guid.NewGuid(), store.ReadEnrollment().Ownership, CandidateDigest.FromText(Artifact(FilterVerdict.Drop)),
            CandidateDigest.FromText(Artifact(FilterVerdict.Accept)), TimeSpan.FromSeconds(30)), Artifact(FilterVerdict.Drop), Artifact(FilterVerdict.Accept));
        return 0;
    }
    if (args[0] is not ("bind" or "verify"))
    {
        return 2;
    }

    var parsed = NftTableObservation.Parse(Console.In.ReadToEnd());
    if (!parsed.IsSuccess) { Console.Error.WriteLine(parsed.ErrorCode); return 1; }
    var actual = parsed.Observation!;
    var name = new FileInfo("/proc/self/ns/net").LinkTarget ?? throw new InvalidOperationException("context.unavailable");
    if (!name.StartsWith("net:[", StringComparison.Ordinal) || !name.EndsWith(']'))
    {
        throw new InvalidOperationException("context.invalid");
    }

    var currentNamespace = ulong.Parse(name.AsSpan(5, name.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture);
    if (args[0] == "bind")
    {
        var expected = new NftTableReceipt(new LinuxBootClock().Read().BootId, currentNamespace, actual.Identity, actual.TableHandle, actual.StateDigest);
        store.BindExpectedResource(store.ReadEnrollment().Ownership, expected, actual, currentNamespace);
        Console.WriteLine("BOUND");
        return 0;
    }
    var result = store.VerifyExpectedResource(actual, currentNamespace);
    Console.WriteLine(JsonSerializer.Serialize(new { result.IsMatch, result.ErrorCodes }));
    return result.IsMatch ? 0 : 1;
}
catch (JournalException error) { Console.Error.WriteLine(error.Code); return 1; }
