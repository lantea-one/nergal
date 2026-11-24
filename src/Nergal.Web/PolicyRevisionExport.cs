using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Complete saved intent and native projection, released together only after saved artifact verification.</summary>
internal sealed record PolicyRevisionExport(string PolicyJson, string NativeText)
{
    /// <summary>Recompiles an immutable revision without consulting current objects or observed host state.</summary>
    /// <remarks>A matching digest binds bytes; it does not authorize applying them or establish kernel validity.</remarks>
    internal static PolicyRevisionExport? Create(PolicyRevisionRecord revision)
    {
        var decoded = PolicyBundleJsonCodec.DecodeBundle(revision.PolicyJson);
        if (decoded.Value is not { } bundle) { return null; }
        var compiled = NftPolicyBundleCompiler.Compile(bundle);
        if (compiled.Candidate is null || compiled.Digest?.Value != revision.CandidateDigest) { return null; }
        return new(PolicyBundleJsonCodec.EncodeBundle(bundle), compiled.Candidate);
    }
}
