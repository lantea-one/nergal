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
    string? ConnectionStates,
    bool MatchOriginalDestinationDnat = false,
    int? RateLimitPackets = null,
    string? RateLimitUnit = null,
    int? RateLimitBurst = null,
    int? RateLimitTimeout = null,
    string? Description = null);

internal sealed record VisualDnatRuleInput(
    string? Family,
    string? Protocol,
    string? OriginalDestination,
    string? TranslatedAddress,
    int? OriginalPort,
    int? TranslatedPort,
    string? InputInterface,
    string? Source,
    string? Description = null);

internal sealed record VisualSnatRuleInput(
    string? Family,
    string? Source,
    string? TranslatedAddress,
    string? Destination,
    string? OutputInterface,
    string? Description = null);

internal sealed record VisualBridgeRuleInput(
    string? EtherType,
    string? Verdict,
    string? InputInterface,
    string? OutputInterface,
    string? Description = null);

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

        if (OperatingSystem.IsLinux() && store is not null)
        {
            var referenceErrors = store.ValidatePolicyObjects(bundle!);
            if (referenceErrors.Count != 0) { return new(false, bundle, null, null, null, null, null, referenceErrors.Select(d => new PolicyDiagnostic(d.Code, d.Path)).ToArray()); }
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
            nextRules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryUpdateFilterRule(
        string currentJson,
        int ruleIndex,
        VisualFilterRuleInput input,
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

        if (!TryParseVisualRule(input, out var rule, out diagnostics) || rule is null)
        {
            return false;
        }

        var nextRules = bundle.Filter.Rules.ToList();
        var previous = bundle.Filter.Rules[ruleIndex]!;
        nextRules[ruleIndex] = rule with
        {
            SourceObject = previous.SourceObject,
            DestinationObject = previous.DestinationObject,
            DestinationPortObject = previous.DestinationPortObject,
            NegateInputInterface = previous.NegateInputInterface,
            NegateOutputInterface = previous.NegateOutputInterface,
            NegateSource = previous.NegateSource,
            NegateDestination = previous.NegateDestination,
            SourceMac = previous.SourceMac,
            SourceMacs = previous.SourceMacs,
            NegateSourceMac = previous.NegateSourceMac,
            RateLimit = rule.RateLimit is null ? null : rule.RateLimit with { KeyKind = previous.RateLimit?.KeyKind ?? RateLimitKeyKind.SourceAddress },
        };
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
            nextRules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
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
            nextRules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
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
            nextRules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
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

        PerSourceRateLimit? rateLimit = null;
        if (input.RateLimitPackets.HasValue || input.RateLimitBurst.HasValue)
        {
            if (!input.RateLimitPackets.HasValue || !input.RateLimitBurst.HasValue)
            {
                errors.Add(new("rateLimit.incomplete", "rule.rateLimit"));
            }
            else
            {
                var unit = (input.RateLimitUnit ?? "second").Trim().ToLowerInvariant() switch
                {
                    "second" => RateLimitTimeUnit.Second,
                    "minute" => RateLimitTimeUnit.Minute,
                    _ => (RateLimitTimeUnit)(-1),
                };
                if (!Enum.IsDefined(unit))
                {
                    errors.Add(new("rateLimit.unitUnknown", "rule.rateLimit.windowUnit"));
                }
                else
                {
                    rateLimit = new PerSourceRateLimit(
                        input.RateLimitPackets.Value,
                        unit,
                        input.RateLimitBurst.Value,
                        input.RateLimitTimeout ?? 60);
                }
            }
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            errors.Add(new("rule.descriptionInvalid", "rule.description"));
        }

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
            rateLimit,
            input.MatchOriginalDestinationDnat,
            sourcePrefixes,
            destinationPrefixes,
            destinationPorts,
            description);
        diagnostics = [];
        return true;
    }

    private static bool TryNormalizeDescription(string? raw, out string? normalized)
    {
        normalized = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var trimmed = raw.Trim();
        if (trimmed.Length > 160)
        {
            return false;
        }

        foreach (var c in trimmed)
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }

        normalized = trimmed;
        return true;
    }

    internal static bool TryUpdateFilterDefaults(
        string currentJson,
        int schemaVersion,
        string? inputVerdict,
        string? forwardVerdict,
        string? outputVerdict,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (!TryParseVerdict(inputVerdict, out var inV) ||
            !TryParseVerdict(forwardVerdict, out var fwdV) ||
            !TryParseVerdict(outputVerdict, out var outV))
        {
            diagnostics = [new("verdict.unknown", "filter")];
            return false;
        }

        var nextFilter = new FilterPolicy(schemaVersion, inV, fwdV, outV, bundle.Filter.Rules, bundle.Filter.RpFilter, bundle.Filter.ForwardTcpMssClamp);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, nextFilter, bundle.Nat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryAppendDnatRule(
        string currentJson,
        VisualDnatRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (!TryParseFamily(input.Family, out var family))
        {
            diagnostics = [new("family.unknown", "nat.dnatRules")];
            return false;
        }

        if (!TryParseProtocol(input.Protocol, out var protocol))
        {
            diagnostics = [new("protocol.unknown", "nat.dnatRules")];
            return false;
        }

        NetworkPrefix origDst;
        NetworkPrefix? src = null;
        try
        {
            origDst = new NetworkPrefix((input.OriginalDestination ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(input.Source))
            {
                src = new NetworkPrefix(input.Source.Trim());
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            diagnostics = [new("network.invalid", "nat.dnatRules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "nat.dnatRules")];
            return false;
        }

        var dnat = new DnatRule(
            family,
            protocol,
            origDst,
            (input.TranslatedAddress ?? "").Trim(),
            input.OriginalPort,
            input.TranslatedPort,
            string.IsNullOrWhiteSpace(input.InputInterface) ? null : input.InputInterface.Trim(),
            src,
            description);

        var existingDnat = bundle.Nat?.DnatRules.ToList() ?? [];
        var existingSnat = bundle.Nat?.SnatRules.ToList() ?? [];
        existingDnat.Add(dnat);
        var nextNat = new NatPolicy(NatPolicy.CurrentSchemaVersion, existingDnat, existingSnat);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryUpdateDnatRule(
        string currentJson,
        int ruleIndex,
        VisualDnatRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (bundle.Nat is null || ruleIndex < 0 || ruleIndex >= bundle.Nat.DnatRules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "nat.dnatRules")];
            return false;
        }

        if (!TryParseFamily(input.Family, out var family))
        {
            diagnostics = [new("family.unknown", "nat.dnatRules")];
            return false;
        }

        if (!TryParseProtocol(input.Protocol, out var protocol))
        {
            diagnostics = [new("protocol.unknown", "nat.dnatRules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "nat.dnatRules")];
            return false;
        }

        NetworkPrefix origDst;
        NetworkPrefix? src = null;
        try
        {
            origDst = new NetworkPrefix((input.OriginalDestination ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(input.Source))
            {
                src = new NetworkPrefix(input.Source.Trim());
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            diagnostics = [new("network.invalid", "nat.dnatRules")];
            return false;
        }

        var dnat = new DnatRule(
            family,
            protocol,
            origDst,
            (input.TranslatedAddress ?? "").Trim(),
            input.OriginalPort,
            input.TranslatedPort,
            string.IsNullOrWhiteSpace(input.InputInterface) ? null : input.InputInterface.Trim(),
            src,
            description);

        var dnats = bundle.Nat.DnatRules.ToList();
        var previous = bundle.Nat.DnatRules[ruleIndex]!;
        dnats[ruleIndex] = dnat with { NegateSource = previous.NegateSource, NegateDestination = previous.NegateDestination, NegateInputInterface = previous.NegateInputInterface };
        var nextNat = new NatPolicy(NatPolicy.CurrentSchemaVersion, dnats, bundle.Nat.SnatRules.ToList());
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryRemoveDnatRule(
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

        if (bundle.Nat is null || ruleIndex < 0 || ruleIndex >= bundle.Nat.DnatRules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "nat.dnatRules")];
            return false;
        }

        var dnats = bundle.Nat.DnatRules.ToList();
        dnats.RemoveAt(ruleIndex);
        var snats = bundle.Nat.SnatRules.ToList();
        var nextNat = dnats.Count == 0 && snats.Count == 0 ? null : new NatPolicy(NatPolicy.CurrentSchemaVersion, dnats, snats);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryAppendSnatRule(
        string currentJson,
        VisualSnatRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (!TryParseFamily(input.Family, out var family))
        {
            diagnostics = [new("family.unknown", "nat.snatRules")];
            return false;
        }

        NetworkPrefix src;
        NetworkPrefix? dst = null;
        try
        {
            src = new NetworkPrefix((input.Source ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(input.Destination))
            {
                dst = new NetworkPrefix(input.Destination.Trim());
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            diagnostics = [new("network.invalid", "nat.snatRules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "nat.snatRules")];
            return false;
        }

        var snat = new SnatRule(
            family,
            src,
            (input.TranslatedAddress ?? "").Trim(),
            dst,
            string.IsNullOrWhiteSpace(input.OutputInterface) ? null : input.OutputInterface.Trim(),
            description);

        var existingDnat = bundle.Nat?.DnatRules.ToList() ?? [];
        var existingSnat = bundle.Nat?.SnatRules.ToList() ?? [];
        existingSnat.Add(snat);
        var nextNat = new NatPolicy(NatPolicy.CurrentSchemaVersion, existingDnat, existingSnat);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryUpdateSnatRule(
        string currentJson,
        int ruleIndex,
        VisualSnatRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (bundle.Nat is null || ruleIndex < 0 || ruleIndex >= bundle.Nat.SnatRules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "nat.snatRules")];
            return false;
        }

        if (!TryParseFamily(input.Family, out var family))
        {
            diagnostics = [new("family.unknown", "nat.snatRules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "nat.snatRules")];
            return false;
        }

        NetworkPrefix src;
        NetworkPrefix? dst = null;
        try
        {
            src = new NetworkPrefix((input.Source ?? "").Trim());
            if (!string.IsNullOrWhiteSpace(input.Destination))
            {
                dst = new NetworkPrefix(input.Destination.Trim());
            }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            diagnostics = [new("network.invalid", "nat.snatRules")];
            return false;
        }

        var snat = new SnatRule(
            family,
            src,
            (input.TranslatedAddress ?? "").Trim(),
            dst,
            string.IsNullOrWhiteSpace(input.OutputInterface) ? null : input.OutputInterface.Trim(),
            description);

        var snats = bundle.Nat.SnatRules.ToList();
        var previous = bundle.Nat.SnatRules[ruleIndex]!;
        snats[ruleIndex] = snat with
        {
            Action = previous.Action,
            InputInterface = previous.InputInterface,
            Protocol = previous.Protocol,
            DestinationPort = previous.DestinationPort,
            DestinationPorts = previous.DestinationPorts,
            NegateSource = previous.NegateSource,
            NegateDestination = previous.NegateDestination,
            NegateInputInterface = previous.NegateInputInterface,
            NegateOutputInterface = previous.NegateOutputInterface
        };
        var nextNat = new NatPolicy(NatPolicy.CurrentSchemaVersion, bundle.Nat.DnatRules.ToList(), snats);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
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

    internal static bool TryRemoveSnatRule(
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

        if (bundle.Nat is null || ruleIndex < 0 || ruleIndex >= bundle.Nat.SnatRules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "nat.snatRules")];
            return false;
        }

        var dnats = bundle.Nat.DnatRules.ToList();
        var snats = bundle.Nat.SnatRules.ToList();
        snats.RemoveAt(ruleIndex);
        var nextNat = dnats.Count == 0 && snats.Count == 0 ? null : new NatPolicy(NatPolicy.CurrentSchemaVersion, dnats, snats);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, nextNat, bundle.Bridge, bundle.AuxiliaryFilter);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryClearNat(
        string currentJson,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, null, bundle.Bridge, bundle.AuxiliaryFilter);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryUpdateBridgeDefaults(
        string currentJson,
        string? defaultVerdict,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (!TryParseVerdict(defaultVerdict, out var verdict))
        {
            diagnostics = [new("verdict.unknown", "bridge.defaultVerdict")];
            return false;
        }

        var rules = bundle.Bridge?.Rules.ToList() ?? [];
        var nextBridge = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, verdict, rules, bundle.Bridge?.Priority ?? -200, bundle.Bridge?.SubChains);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, nextBridge, bundle.AuxiliaryFilter);
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

    internal static bool TryAppendBridgeRule(
        string currentJson,
        VisualBridgeRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        var etherType = (input.EtherType ?? "any").Trim().ToLowerInvariant() switch
        {
            "any" => BridgeEtherType.Any,
            "ipv4" => BridgeEtherType.IPv4,
            "ipv6" => BridgeEtherType.IPv6,
            "arp" => BridgeEtherType.Arp,
            _ => (BridgeEtherType)(-1),
        };
        if (!Enum.IsDefined(etherType))
        {
            diagnostics = [new("bridge.etherTypeUnknown", "bridge.rules")];
            return false;
        }

        if (!TryParseVerdict(input.Verdict, out var verdict))
        {
            diagnostics = [new("verdict.unknown", "bridge.rules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "bridge.rules")];
            return false;
        }

        var rule = new BridgeFilterRule(
            etherType,
            verdict,
            string.IsNullOrWhiteSpace(input.InputInterface) ? null : input.InputInterface.Trim(),
            string.IsNullOrWhiteSpace(input.OutputInterface) ? null : input.OutputInterface.Trim(),
            description);
        var rules = bundle.Bridge?.Rules.ToList() ?? [];
        rules.Add(rule);
        var defaultVerdict = bundle.Bridge?.DefaultVerdict ?? FilterVerdict.Accept;
        var nextBridge = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, defaultVerdict, rules, bundle.Bridge?.Priority ?? -200, bundle.Bridge?.SubChains);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, nextBridge, bundle.AuxiliaryFilter);
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

    internal static bool TryUpdateBridgeRule(
        string currentJson,
        int ruleIndex,
        VisualBridgeRuleInput input,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        if (bundle.Bridge is null || ruleIndex < 0 || ruleIndex >= bundle.Bridge.Rules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "bridge.rules")];
            return false;
        }

        var etherType = (input.EtherType ?? "any").Trim().ToLowerInvariant() switch
        {
            "any" => BridgeEtherType.Any,
            "ipv4" => BridgeEtherType.IPv4,
            "ipv6" => BridgeEtherType.IPv6,
            "arp" => BridgeEtherType.Arp,
            _ => (BridgeEtherType)(-1),
        };
        if (!Enum.IsDefined(etherType))
        {
            diagnostics = [new("bridge.etherTypeUnknown", "bridge.rules")];
            return false;
        }

        if (!TryParseVerdict(input.Verdict, out var verdict))
        {
            diagnostics = [new("verdict.unknown", "bridge.rules")];
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description))
        {
            diagnostics = [new("rule.descriptionInvalid", "bridge.rules")];
            return false;
        }

        var rule = new BridgeFilterRule(
            etherType,
            verdict,
            string.IsNullOrWhiteSpace(input.InputInterface) ? null : input.InputInterface.Trim(),
            string.IsNullOrWhiteSpace(input.OutputInterface) ? null : input.OutputInterface.Trim(),
            description);
        var rules = bundle.Bridge.Rules.ToList();
        var previous = bundle.Bridge.Rules[ruleIndex]!;
        rules[ruleIndex] = previous with
        {
            EtherType = rule.EtherType,
            Verdict = rule.Verdict,
            InputInterface = rule.InputInterface,
            OutputInterface = rule.OutputInterface,
            Description = rule.Description
        };
        var nextBridge = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, bundle.Bridge.DefaultVerdict, rules, bundle.Bridge.Priority, bundle.Bridge.SubChains);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, nextBridge, bundle.AuxiliaryFilter);
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

    internal static bool TryRemoveBridgeRule(
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

        if (bundle.Bridge is null || ruleIndex < 0 || ruleIndex >= bundle.Bridge.Rules.Count)
        {
            diagnostics = [new("rule.indexOutOfRange", "bridge.rules")];
            return false;
        }

        var rules = bundle.Bridge.Rules.ToList();
        rules.RemoveAt(ruleIndex);
        var nextBridge = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, bundle.Bridge.DefaultVerdict, rules, bundle.Bridge.Priority, bundle.Bridge.SubChains);
        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, nextBridge, bundle.AuxiliaryFilter);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    internal static bool TryClearBridge(
        string currentJson,
        out string? updatedJson,
        out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        updatedJson = null;
        if (!TryDecodeBundle(currentJson, out var bundle, out diagnostics) || bundle is null)
        {
            return false;
        }

        var nextBundle = new FirewallPolicyBundle(bundle.SchemaVersion, bundle.Filter, bundle.Nat, null, bundle.AuxiliaryFilter);
        updatedJson = EncodeBundle(nextBundle);
        diagnostics = [];
        return true;
    }

    private static bool TryParseVerdict(string? value, out FilterVerdict verdict)
    {
        verdict = (value ?? "").Trim().ToLowerInvariant() switch
        {
            "accept" => FilterVerdict.Accept,
            "drop" => FilterVerdict.Drop,
            _ => (FilterVerdict)(-1),
        };
        return Enum.IsDefined(verdict);
    }

    private static bool TryParseFamily(string? value, out IpFamily family)
    {
        family = (value ?? "").Trim().ToLowerInvariant() switch
        {
            "ipv4" => IpFamily.IPv4,
            "ipv6" => IpFamily.IPv6,
            _ => (IpFamily)(-1),
        };
        return Enum.IsDefined(family);
    }

    private static bool TryParseProtocol(string? value, out FilterProtocol protocol)
    {
        protocol = (value ?? "").Trim().ToLowerInvariant() switch
        {
            "any" => FilterProtocol.Any,
            "tcp" => FilterProtocol.Tcp,
            "udp" => FilterProtocol.Udp,
            "icmp" => FilterProtocol.Icmp,
            "icmpv6" => FilterProtocol.IcmpV6,
            _ => (FilterProtocol)(-1),
        };
        return Enum.IsDefined(protocol);
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
