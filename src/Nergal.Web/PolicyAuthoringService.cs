using System.Globalization;
using System.Text;
using Nergal.ControllerState;
using Nergal.Core;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal sealed record PolicyEvaluationReport(
    bool IsValid,
    FirewallPolicyBundle? Bundle,
    string? CanonicalJson,
    BackendCompatibilityReport? Compatibility,
    string? CandidateText,
    string? CandidateDigest,
    string? UnifiedDiff,
    IReadOnlyList<PolicyDiagnostic> Diagnostics);

/// <summary>Pure in-memory JSON bundle codec, compatibility check, native candidate compiler preview, and unified line diff builder.</summary>
internal static class PolicyAuthoringService
{
    internal const string DefaultStarterBundleJson = """
        {
          "schemaVersion": 1,
          "filter": {
            "schemaVersion": 2,
            "inputDefaultVerdict": "drop",
            "forwardDefaultVerdict": "drop",
            "outputDefaultVerdict": "accept",
            "rules": [
              {
                "family": "ipv4",
                "protocol": "tcp",
                "verdict": "accept",
                "chain": "input",
                "connectionStates": ["established", "related"]
              }
            ]
          }
        }
        """;

    internal static readonly BackendCapabilities NativeNftablesCapabilities = new(
        "nftables",
        Enum.GetValues<FirewallFeature>());

    internal static PolicyEvaluationReport EvaluateDraft(
        string bundleJson,
        ControllerStateStore? store = null,
        ulong? compareRevision = null,
        BackendCapabilities? targetCapabilities = null)
    {
        if (!TryDecodeBundle(bundleJson, out var bundle, out var parseErrors))
        {
            return new PolicyEvaluationReport(false, null, null, null, null, null, null, parseErrors);
        }

        var compiled = NftPolicyBundleCompiler.Compile(bundle!);
        if (!compiled.IsSuccess || compiled.Candidate is null || compiled.Digest is null)
        {
            return new PolicyEvaluationReport(false, bundle, null, null, null, null, null, compiled.Diagnostics);
        }

        var caps = targetCapabilities ?? NativeNftablesCapabilities;
        var compatibility = BackendCompatibilityEvaluator.Evaluate(bundle!.GetRequiredFeatures(), caps);
        if (!compatibility.IsCompatible)
        {
            var missing = compatibility.UnsupportedFeatures
                .Select(feature => new PolicyDiagnostic("backend.unsupportedFeature", feature.ToString()))
                .ToArray();
            return new PolicyEvaluationReport(false, bundle, null, compatibility, null, null, null, missing);
        }

        var canonical = EncodeBundle(bundle);
        string? baselineCandidate = null;
        var baselineLabel = "empty";
        if (OperatingSystem.IsLinux() && store is not null && compareRevision is { } rev and > 0)
        {
            var prior = store.GetPolicyRevision(rev);
            if (prior is not null && TryDecodeBundle(prior.PolicyJson, out var priorBundle, out _))
            {
                var priorCompiled = NftPolicyBundleCompiler.Compile(priorBundle!);
                if (priorCompiled.IsSuccess)
                {
                    baselineCandidate = priorCompiled.Candidate;
                    baselineLabel = $"revision-{rev.ToString(CultureInfo.InvariantCulture)}";
                }
            }
        }

        var diff = ComputeUnifiedDiff(
            baselineCandidate ?? "",
            compiled.Candidate,
            baselineLabel,
            $"candidate-{compiled.Digest.Value[..8]}");

        return new PolicyEvaluationReport(
            true,
            bundle,
            canonical,
            compatibility,
            compiled.Candidate,
            compiled.Digest.Value,
            diff,
            []);
    }

    internal static bool TryDecodeBundle(string json, out FirewallPolicyBundle? bundle, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        var result = PolicyBundleJsonCodec.DecodeBundle(json);
        bundle = result.Value;
        diagnostics = result.Diagnostics.Select(d => new PolicyDiagnostic(d.Code, d.Path)).ToArray();
        return result.IsSuccess;
    }

    internal static string EncodeBundle(FirewallPolicyBundle bundle) =>
        PolicyBundleJsonCodec.EncodeBundle(bundle, indented: true);

    internal static string ComputeUnifiedDiff(string before, string after, string beforeLabel, string afterLabel)
    {
        var a = SplitLines(before);
        var b = SplitLines(after);
        var n = a.Length;
        var m = b.Length;

        var lcs = new int[n + 1, m + 1];
        for (var i = n - 1; i >= 0; i--)
        {
            for (var j = m - 1; j >= 0; j--)
            {
                lcs[i, j] = string.Equals(a[i], b[j], StringComparison.Ordinal)
                    ? 1 + lcs[i + 1, j + 1]
                    : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);
            }
        }

        var output = new StringBuilder();
        output.Append("--- ").Append(beforeLabel).Append('\n');
        output.Append("+++ ").Append(afterLabel).Append('\n');

        var x = 0;
        var y = 0;
        while (x < n || y < m)
        {
            if (x < n && y < m && string.Equals(a[x], b[y], StringComparison.Ordinal))
            {
                output.Append("  ").Append(a[x]).Append('\n');
                x++;
                y++;
            }
            else if (y < m && (x == n || lcs[x, y + 1] >= lcs[x + 1, y]))
            {
                output.Append("+ ").Append(b[y]).Append('\n');
                y++;
            }
            else
            {
                output.Append("- ").Append(a[x]).Append('\n');
                x++;
            }
        }

        return output.ToString();
    }

    private static string[] SplitLines(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return [];
        }

        return text.TrimEnd('\n').Split('\n');
    }
}
