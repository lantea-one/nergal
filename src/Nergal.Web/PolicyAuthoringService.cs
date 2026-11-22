using System.Globalization;
using System.Text;
using Nergal.ControllerState;
using Nergal.Core;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal sealed record VisualFilterRuleInput(
    string? Chain,
    string? Family,
    string? Protocol,
    string? Verdict,
    string? Sources,
    string? Destinations,
    string? DestinationPorts,
    string? IcmpType,
    string? InputInterface,
    string? OutputInterface,
    string? ConnectionStates);

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

    internal static bool TryAppendFilterRule(
        string currentJson,
        VisualFilterRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (!TryParseVisualRule(input, out var rule, out diagnostics) || rule is null)
        {
            return false;
        }

        var nextRules = bundle.Filter.Rules.ToList();
        nextRules.Add(rule);
        var nextSchema = bundle.Filter.SchemaVersion;
        if (nextSchema < 2 && RequiresSchema2(rule))
        {
            nextSchema = 2;
        }

        var nextFilter = new FilterPolicy(
            nextSchema,
            bundle.Filter.InputDefaultVerdict,
            bundle.Filter.ForwardDefaultVerdict,
            bundle.Filter.OutputDefaultVerdict,
            nextRules);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge);
        var compiled = NftPolicyBundleCompiler.Compile(nextBundle);
        if (!compiled.IsSuccess)
        {
            diagnostics = compiled.Diagnostics;
            return false;
        }

        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryRemoveFilterRule(
        string currentJson,
        int ruleIndex,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (ruleIndex < 0 || ruleIndex >= bundle.Filter.Rules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "filter.rules")];
            return false;
        }

        var nextRules = bundle.Filter.Rules.ToList();
        nextRules.RemoveAt(ruleIndex);
        var nextFilter = new FilterPolicy(
            bundle.Filter.SchemaVersion,
            bundle.Filter.InputDefaultVerdict,
            bundle.Filter.ForwardDefaultVerdict,
            bundle.Filter.OutputDefaultVerdict,
            nextRules);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryMoveFilterRule(
        string currentJson,
        int ruleIndex,
        int direction,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        var targetIndex = ruleIndex + (direction < 0 ? -1 : 1);
        if (ruleIndex < 0 || ruleIndex >= bundle.Filter.Rules.Count ||
            targetIndex < 0 || targetIndex >= bundle.Filter.Rules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "filter.rules")];
            return false;
        }

        var nextRules = bundle.Filter.Rules.ToList();
        (nextRules[ruleIndex], nextRules[targetIndex]) = (nextRules[targetIndex], nextRules[ruleIndex]);
        var nextFilter = new FilterPolicy(
            bundle.Filter.SchemaVersion,
            bundle.Filter.InputDefaultVerdict,
            bundle.Filter.ForwardDefaultVerdict,
            bundle.Filter.OutputDefaultVerdict,
            nextRules);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    private static bool RequiresSchema2(FilterRule rule) =>
        rule.Chain != FilterChainKind.Input ||
        rule.InputInterface is not null ||
        rule.OutputInterface is not null ||
        rule.ConnectionStates != ConnectionStateFlags.None ||
        rule.IcmpType is not null ||
        rule.RateLimit is not null ||
        rule.MatchOriginalDestinationDnat ||
        rule.SourcePrefixes is not null ||
        rule.DestinationPrefixes is not null ||
        rule.DestinationPorts is not null;

    private static bool TryParseVisualRule(
        VisualFilterRuleInput input,
        out FilterRule? rule,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        rule = null;
        var errors = new List<PolicyDiagnostic>();

        FilterChainKind chain = (input.Chain ?? "input").Trim().ToLowerInvariant() switch
        {
            "input" => FilterChainKind.Input,
            "forward" => FilterChainKind.Forward,
            "output" => FilterChainKind.Output,
            _ => (FilterChainKind)(-1),
        };
        if (!Enum.IsDefined(chain)) { errors.Add(new("chain.unknown", "rule.chain")); }

        IpFamily family = (input.Family ?? "ipv4").Trim().ToLowerInvariant() switch
        {
            "ipv4" => IpFamily.IPv4,
            "ipv6" => IpFamily.IPv6,
            _ => (IpFamily)(-1),
        };
        if (!Enum.IsDefined(family)) { errors.Add(new("family.unknown", "rule.family")); }

        FilterProtocol protocol = (input.Protocol ?? "tcp").Trim().ToLowerInvariant() switch
        {
            "any" => FilterProtocol.Any,
            "tcp" => FilterProtocol.Tcp,
            "udp" => FilterProtocol.Udp,
            "icmp" => FilterProtocol.Icmp,
            "icmpv6" => FilterProtocol.IcmpV6,
            _ => (FilterProtocol)(-1),
        };
        if (!Enum.IsDefined(protocol)) { errors.Add(new("protocol.unknown", "rule.protocol")); }

        FilterVerdict verdict = (input.Verdict ?? "accept").Trim().ToLowerInvariant() switch
        {
            "accept" => FilterVerdict.Accept,
            "drop" => FilterVerdict.Drop,
            _ => (FilterVerdict)(-1),
        };
        if (!Enum.IsDefined(verdict)) { errors.Add(new("verdict.unknown", "rule.verdict")); }

        NetworkPrefix? source = null;
        IReadOnlyList<NetworkPrefix>? sourcePrefixes = null;
        if (!TryParsePrefixField(input.Sources, "rule.sources", out source, out sourcePrefixes, errors))
        {
            // diagnostics recorded
        }

        NetworkPrefix? destination = null;
        IReadOnlyList<NetworkPrefix>? destinationPrefixes = null;
        if (!TryParsePrefixField(input.Destinations, "rule.destinations", out destination, out destinationPrefixes, errors))
        {
            // diagnostics recorded
        }

        int? destinationPort = null;
        IReadOnlyList<int>? destinationPorts = null;
        TryParsePortField(input.DestinationPorts, "rule.destinationPorts", out destinationPort, out destinationPorts, errors);

        var states = ConnectionStateFlags.None;
        if (!string.IsNullOrWhiteSpace(input.ConnectionStates))
        {
            foreach (var rawToken in input.ConnectionStates.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                switch (rawToken.ToLowerInvariant())
                {
                    case "new": states |= ConnectionStateFlags.New; break;
                    case "established": states |= ConnectionStateFlags.Established; break;
                    case "related": states |= ConnectionStateFlags.Related; break;
                    case "invalid": states |= ConnectionStateFlags.Invalid; break;
                    default: errors.Add(new("connectionState.unknown", "rule.connectionStates")); break;
                }
            }
        }

        var icmpType = string.IsNullOrWhiteSpace(input.IcmpType) ? null : input.IcmpType.Trim().ToLowerInvariant();
        var iif = string.IsNullOrWhiteSpace(input.InputInterface) ? null : input.InputInterface.Trim();
        var oif = string.IsNullOrWhiteSpace(input.OutputInterface) ? null : input.OutputInterface.Trim();

        if (errors.Count > 0)
        {
            diagnostics = errors;
            return false;
        }

        rule = new FilterRule(
            family,
            protocol,
            verdict,
            source,
            destination,
            destinationPort,
            chain,
            iif,
            oif,
            states,
            icmpType,
            null,
            false,
            sourcePrefixes,
            destinationPrefixes,
            destinationPorts);
        diagnostics = [];
        return true;
    }

    private static bool TryParsePrefixField(
        string? raw,
        string path,
        out NetworkPrefix? single,
        out IReadOnlyList<NetworkPrefix>? set,
        List<PolicyDiagnostic> errors)
    {
        single = null;
        set = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var tokens = raw.Split([',', ' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var parsed = new List<NetworkPrefix>(tokens.Length);
        foreach (var token in tokens)
        {
            try
            {
                parsed.Add(new NetworkPrefix(token));
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                errors.Add(new("network.invalid", path));
                return false;
            }
        }

        if (parsed.Count == 1)
        {
            single = parsed[0];
        }
        else if (parsed.Count > 1)
        {
            set = Array.AsReadOnly(parsed.ToArray());
        }

        return true;
    }

    private static void TryParsePortField(
        string? raw,
        string path,
        out int? single,
        out IReadOnlyList<int>? set,
        List<PolicyDiagnostic> errors)
    {
        single = null;
        set = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return;
        }

        var tokens = raw.Split([',', ' ', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var parsed = new List<int>(tokens.Length);
        foreach (var token in tokens)
        {
            if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            {
                errors.Add(new("port.outOfRange", path));
                return;
            }

            parsed.Add(port);
        }

        if (parsed.Count == 1)
        {
            single = parsed[0];
        }
        else if (parsed.Count > 1)
        {
            set = Array.AsReadOnly(parsed.ToArray());
        }
    }

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
