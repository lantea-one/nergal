using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

// Unprivileged probe only: emits candidates or compares supplied observations. No process/host operations.
if (args.Length == 3 && args[0] == "emit")
{
    var result = NftFilterCompiler.Compile(new(1, FilterVerdict.Accept, []), new(Guid.Parse(args[1]), Guid.Parse(args[2])));
    Console.Write(result.Candidate);
    return result.IsSuccess ? 0 : 1;
}
if (args.Length != 1 || args[0] is not ("inspect" or "verify"))
{
    return 2;
}

var text = Console.In.ReadToEnd();
using var envelope = args[0] == "verify" ? JsonDocument.Parse(text) : null;
var parsed = NftTableObservation.Parse(envelope is null ? text : envelope.RootElement.GetProperty("observation").GetString()!);
if (!parsed.IsSuccess) { Console.WriteLine(JsonSerializer.Serialize(new { error = parsed.ErrorCode })); return 1; }
var actual = parsed.Observation!;
if (envelope is null)
{
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        actual.TableHandle,
        actual.ChainHandle,
        Digest = actual.StateDigest.Value,
        actual.Identity.OwnerId,
        actual.Identity.ResourceId
    }));
    return 0;
}
// This envelope is harness-only, not an agent transport or an enrollment API.
var root = envelope.RootElement;
var expected = new NftTableReceipt(Guid.Parse(root.GetProperty("boot").GetString()!), root.GetProperty("namespace").GetUInt64(),
    new(Guid.Parse(root.GetProperty("owner").GetString()!), Guid.Parse(root.GetProperty("resource").GetString()!)),
    root.GetProperty("handle").GetUInt64(), new CandidateDigest(root.GetProperty("digest").GetString()!));
var comparison = NftReceiptVerifier.Verify(expected, actual, Guid.Parse(root.GetProperty("currentBoot").GetString()!),
    root.GetProperty("currentNamespace").GetUInt64());
Console.WriteLine(JsonSerializer.Serialize(new { comparison.IsMatch, comparison.ErrorCodes }));
return comparison.IsMatch ? 0 : 1;
