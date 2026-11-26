using Nergal.Core.Policy;
using Nergal.Nftables;
using Nergal.Testing;
using Nergal.Linux;

// Only synthetic documentation addresses; this program emits text or verifies snapshots without host mutations.
var mode = args.Length > 0 ? args[0] : "schema1";
var nativeProjection = mode.StartsWith("named-", StringComparison.Ordinal);
if (nativeProjection) { mode = mode[6..]; }
FilterPolicy FilterProjection(FilterPolicy p) => nativeProjection ? RouterPolicySamples.WithNativeSetReferences(new(1, p)).Filter : p;
NatPolicy NatProjection(NatPolicy p) => nativeProjection ? RouterPolicySamples.WithNativeSetReferences(new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), p)).Nat! : p;
if (mode is "generation" or "generation-denied")
{
    if (!OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException(); }
    try
    {
        var generation = LinuxNftablesGeneration.Read();
        if (mode == "generation-denied") { throw new InvalidOperationException("Generation query unexpectedly authorized."); }
        Console.Write(generation);
    }
    catch (IOException) when (mode == "generation-denied") { Console.Write("denied"); }
    return 0;
}
var routerIdentity = new NftTableIdentity(
    Guid.Parse("00000000-0000-0000-0000-000000000010"),
    Guid.Parse("00000000-0000-0000-0000-000000000020"));

if (mode == "compile-import-json" && args.Length == 2)
{
    var policy = PolicyBundleJsonCodec.DecodeBundle(File.ReadAllText(args[1])).Value ?? throw new InvalidOperationException("Invalid synthetic import policy.");
    var result = NftPolicyBundleCompiler.Compile(policy);
    if (!result.IsSuccess) { throw new InvalidOperationException("Synthetic import compilation failed."); }
    Console.Write(result.Candidate); return 0;
}
if (mode == "import-native" && (args.Length == 4 || args is [_, _, _, _, "--restrict-cleanup"]))
{
    var content = new Nergal.Core.Controller.NativeSourceContent("synthetic-import", File.ReadAllText(args[1]));
    var sourceId = Guid.Parse("00000000-0000-0000-0000-000000000061");
    var source = new Nergal.Core.Controller.NativeSourceSnapshot(new(sourceId, content.Name, content.Digest, content.ByteLength, "synthetic", DateTimeOffset.UnixEpoch), content);
    var bindings = args[3].Split(';').Select(item =>
    {
        var parts = item.Split('='); var name = parts[1].Split('/');
        return new NativeImportTableBinding(name[0], name[1], Enum.Parse<NativeImportTableRole>(parts[0]));
    }).ToArray();
    var plan = NativeImportPlanner.Plan(new(sourceId, bindings, [], restrictGlobalOperations: args.Length == 5), [source]);
    if (!plan.CanCreateRevision) { throw new InvalidOperationException("Native conversion blocked: " + string.Join(",", plan.Gaps.Select(g => g.Code))); }
    var bundle = PolicyBundleJsonCodec.DecodeBundle(plan.PolicyJson!).Value!;
    var output = args[2] switch
    {
        "json" => plan.PolicyJson,
        "filter" => NftFilterCompiler.Compile(bundle.Filter, routerIdentity).Candidate,
        "nat" => NftNatCompiler.Compile(bundle.Nat!, routerIdentity).Candidate,
        "bridge" => NftBridgeCompiler.Compile(bundle.Bridge!, routerIdentity).Candidate,
        "bundle" => NftPolicyBundleCompiler.Compile(bundle, routerIdentity).Candidate,
        _ => throw new ArgumentException("Unknown synthetic import output."),
    };
    Console.Write(output); return 0;
}

if (mode == "verify-import-native" && (args.Length == 6 || args is [_, _, _, _, _, _, "--renamed"]))
{
    var echo = NftTableObservation.ParseBundleReplacementEcho(File.ReadAllText(args[2]), routerIdentity, true, false, true);
    var filter = NftTableObservation.Parse(File.ReadAllText(args[3]));
    var nat = NftNatTableObservation.Parse(File.ReadAllText(args[4]));
    var auxiliary = NftAuxiliaryTableObservation.Parse(File.ReadAllText(args[5]));
    if (!echo.IsSuccess || !filter.IsSuccess || !nat.IsSuccess || auxiliary is null)
    { throw new InvalidOperationException($"Imported bundle observation failed: {echo.ErrorCode} {filter.ErrorCode} {nat.ErrorCode}"); }
    var listed = NftTableObservation.Combine(filter.Observation!, nat.Observation!, null, auxiliary);
    if (args.Length == 7)
    {
        if (echo.Observation!.StateDigest == listed.StateDigest)
        { throw new InvalidOperationException("Interface-index binding drift was not detected."); }
        return 0;
    }
    if (echo.Observation!.StateDigest != listed.StateDigest ||
        NftPolicyBundleCompiler.Compile(listed.Bundle, routerIdentity).Candidate != File.ReadAllText(args[1]))
    { throw new InvalidOperationException("Imported bundle native round-trip diverged."); }
    return 0;
}

if (mode == "native-low-ipv6" && args.Length == 2)
{
    Console.Write(NftFilterCompiler.Compile(LowIpv6(args[1]), routerIdentity).Candidate); return 0;
}
if (mode == "verify-native-low-ipv6" && args.Length == 4)
{
    var expected = NftFilterCompiler.Compile(LowIpv6(args[3]), routerIdentity).Candidate!;
    var listing = File.ReadAllText(args[2]);
    var completed = NftStaticSetCreationEvidence.Complete(File.ReadAllText(args[1]), [listing], expected);
    var echo = NftTableObservation.ParseReplacementEcho(completed);
    var listed = NftTableObservation.Parse(listing);
    if (!echo.IsSuccess || !listed.IsSuccess || echo.Observation!.StateDigest != listed.Observation!.StateDigest || NftFilterCompiler.Compile(listed.Observation.Policy, routerIdentity).Candidate != expected)
    { throw new InvalidOperationException("Low IPv6 creation evidence failed."); }
    return 0;
}
static FilterPolicy LowIpv6(string kind) => new(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept,
    [new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 19001,
        SourceObject: new(Guid.Parse("00000000-0000-0000-0000-000000000031"), 1,
            new("low_ipv6", Nergal.Core.Controller.ReusableObjectKind.Ipv6, "", [kind == "prefix" ? "::/64" : "::1/128"]), true))]);

if (mode is "native-static-sets" or "native-static-sets-json" or "native-static-open-json")
{
    var bundle = NativeStaticBundle(mode != "native-static-open-json");
    if (mode.EndsWith("-json", StringComparison.Ordinal)) { Console.Write(PolicyBundleJsonCodec.EncodeBundle(bundle)); }
    else { var result = NftPolicyBundleCompiler.Compile(bundle, routerIdentity); if (!result.IsSuccess) { throw new InvalidOperationException(string.Join(", ", result.Diagnostics)); } Console.Write(result.Candidate); }
    return 0;
}
if (mode == "verify-native-static-sets" && args.Length == 6)
{
    var echo = NftTableObservation.ParseBundleReplacementEcho(File.ReadAllText(args[1]), routerIdentity, true, true, true);
    if (!echo.IsSuccess) { throw new InvalidOperationException("Native set echo failed: " + echo.ErrorCode); }
    var primary = NftTableObservation.Parse(File.ReadAllText(args[2])).Observation;
    var nat = NftNatTableObservation.Parse(File.ReadAllText(args[3])).Observation;
    var bridge = NftBridgeTableObservation.Parse(File.ReadAllText(args[4])).Observation;
    var auxiliary = NftAuxiliaryTableObservation.Parse(File.ReadAllText(args[5]));
    if (primary is null || nat is null || bridge is null || auxiliary is null) { throw new InvalidOperationException("Native set listing failed."); }
    var listed = NftTableObservation.Combine(primary, nat, bridge, auxiliary);
    if (echo.Observation!.StateDigest != listed.StateDigest || NftPolicyBundleCompiler.Compile(listed.Bundle, routerIdentity).Candidate != NftPolicyBundleCompiler.Compile(NativeStaticBundle(), routerIdentity).Candidate)
    { throw new InvalidOperationException("Native static set identity/contents/lookups did not round-trip."); }
    return 0;
}
static FirewallPolicyBundle NativeStaticBundle(bool blocked = true) => RouterPolicySamples.WithNativeSetReferences(
    RouterPolicySamples.WithTransportReferences(RouterPolicySamples.WithPostroutingAddressReferences(RouterPolicySamples.WithBridgeAddressReferences(RouterPolicySamples.WithDnatAddressReferences(RouterPolicySamples.AuxiliaryAcceptance(blocked))))));

if (mode is "auxiliary-acceptance-json" or "auxiliary-open-json" or "auxiliary-acceptance-native")
{
    var bundle = RouterPolicySamples.WithTransportReferences(RouterPolicySamples.WithPostroutingAddressReferences(RouterPolicySamples.WithBridgeAddressReferences(RouterPolicySamples.WithDnatAddressReferences(RouterPolicySamples.AuxiliaryAcceptance(mode != "auxiliary-open-json")))));
    if (mode.EndsWith("-json", StringComparison.Ordinal)) { Console.Write(PolicyBundleJsonCodec.EncodeBundle(bundle)); }
    else
    {
        var result = NftPolicyBundleCompiler.Compile(bundle, routerIdentity);
        if (!result.IsSuccess) { throw new InvalidOperationException(string.Join(", ", result.Diagnostics)); }
        Console.Write(result.Candidate);
    }
    return 0;
}

if (mode == "router-complete-bundle")
{
    var compiled = NftPolicyBundleCompiler.Compile(CompleteBundle(), routerIdentity);
    if (!compiled.IsSuccess) { throw new InvalidOperationException(string.Join(", ", compiled.Diagnostics)); }
    Console.Write(compiled.Candidate);
    return 0;
}
if (mode == "verify-complete-bundle" && args.Length == 6)
{
    var echo = NftTableObservation.ParseBundleReplacementEcho(File.ReadAllText(args[1]), routerIdentity, true, true, true);
    var primary = NftTableObservation.Parse(File.ReadAllText(args[2])).Observation;
    var nat = NftNatTableObservation.Parse(File.ReadAllText(args[3])).Observation;
    var bridge = NftBridgeTableObservation.Parse(File.ReadAllText(args[4])).Observation;
    var auxiliary = NftAuxiliaryTableObservation.Parse(File.ReadAllText(args[5]));
    if (!echo.IsSuccess || primary is null || nat is null || bridge is null || auxiliary is null)
    { throw new InvalidOperationException("Complete bundle observation failed: " + echo.ErrorCode); }
    var listed = NftTableObservation.Combine(primary, nat, bridge, auxiliary);
    if (echo.Observation!.StateDigest != listed.StateDigest ||
        NftPolicyBundleCompiler.Compile(listed.Bundle, routerIdentity).Candidate != NftPolicyBundleCompiler.Compile(CompleteBundle(), routerIdentity).Candidate)
    { throw new InvalidOperationException("Complete bundle native round-trip diverged."); }
    return 0;
}

static FirewallPolicyBundle CompleteBundle() => new(1, RouterPolicySamples.Filter(), RouterPolicySamples.Nat(), RouterPolicySamples.Bridge(),
    new(-5, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept,
        [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Drop, Destination: new("192.0.2.1/32"),
            DestinationPorts: [8080, 8443], InputInterface: "lo", NegateInputInterface: true)])));

if (mode is "router-packet-nat-source-miss" or "router-packet-nat-destination-miss" or "router-packet-nat-negated")
{
    var policy = RouterPolicySamples.PacketNatMiss(mode.EndsWith("source-miss", StringComparison.Ordinal), mode.EndsWith("negated", StringComparison.Ordinal));
    var bundle = RouterPolicySamples.WithPostroutingAddressReferences(new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), policy));
    var compiled = NftNatCompiler.Compile(bundle.Nat!, routerIdentity);
    if (!compiled.IsSuccess) { throw new InvalidOperationException(string.Join(", ", compiled.Diagnostics)); }
    Console.Write(compiled.Candidate); return 0;
}
if (mode == "verify-postrouting-sets" && args.Length == 3)
{
    var echo = NftNatTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    var listed = NftNatTableObservation.Parse(File.ReadAllText(args[2]));
    if (!echo.IsSuccess || !listed.IsSuccess) { throw new InvalidOperationException("Address set observation: " + echo.ErrorCode + "/" + listed.ErrorCode); }
    if (echo.Observation!.StateDigest != listed.Observation!.StateDigest ||
        NftNatCompiler.Compile(listed.Observation.Policy, routerIdentity).Candidate != NftNatCompiler.Compile(RouterPolicySamples.PacketNat(), routerIdentity).Candidate)
    { throw new InvalidOperationException("Postrouting address sets did not round-trip completely."); }
    return 0;
}

if (mode is "router-packets" or "router-packet-nat" or "router-packet-nat-disabled-return" or "router-bridge" or "router-auxiliary")
{
    var result = mode switch
    {
        "router-packets" => NftFilterCompiler.Compile(RouterPolicySamples.PacketFilter(), routerIdentity),
        "router-packet-nat-disabled-return" => NftNatCompiler.Compile(new(1, RouterPolicySamples.PacketNat().DnatRules, RouterPolicySamples.PacketNat().SnatRules.Select(r => r! with { Enabled = r.Action != NatPostroutingAction.Return })), routerIdentity),
        "router-packet-nat" => NftNatCompiler.Compile(RouterPolicySamples.WithTransportReferences(RouterPolicySamples.WithPostroutingAddressReferences(new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), RouterPolicySamples.PacketNat()))).Nat!, routerIdentity),
        "router-bridge" => NftBridgeCompiler.Compile(RouterPolicySamples.Bridge(), routerIdentity),
        _ => NftPolicyBundleCompiler.Compile(new(1, new(1, FilterVerdict.Accept, []), auxiliaryFilter: new(-5,
            new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Drop,
                Destination: new("192.0.2.1/32"), DestinationPorts: [8080, 8443], InputInterface: "lo", NegateInputInterface: true)]))), routerIdentity),
    };
    if (!result.IsSuccess) { throw new InvalidOperationException(string.Join(", ", result.Diagnostics)); }
    Console.Write(result.Candidate); return 0;
}
if (mode is "router-constructs" or "router-nat")
{
    var result = mode == "router-constructs" ? NftFilterCompiler.Compile(RouterPolicySamples.Filter(), routerIdentity)
        : NftNatCompiler.Compile(RouterPolicySamples.WithTransportReferences(new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), RouterPolicySamples.Nat())).Nat!, routerIdentity);
    if (!result.IsSuccess) { throw new InvalidOperationException(string.Join(", ", result.Diagnostics)); }
    Console.Write(result.Candidate);
    return 0;
}
if (mode == "verify-constructs" && args.Length == 5)
{
    var echo = NftTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    var listed = NftTableObservation.Parse(File.ReadAllText(args[2]));
    if (!echo.IsSuccess || !listed.IsSuccess) { throw new InvalidOperationException("Extended filter observation: " + echo.ErrorCode + "/" + listed.ErrorCode); }
    if (echo.Observation!.StateDigest != listed.Observation!.StateDigest ||
        NftFilterCompiler.Compile(listed.Observation.Policy, routerIdentity).Candidate != NftFilterCompiler.Compile(RouterPolicySamples.Filter(), routerIdentity).Candidate)
    { throw new InvalidOperationException("Extended filter round-trip diverged."); }
    var natEcho = NftNatTableObservation.ParseReplacementEcho(File.ReadAllText(args[3]));
    var natList = NftNatTableObservation.Parse(File.ReadAllText(args[4]));
    if (!natEcho.IsSuccess || !natList.IsSuccess) { throw new InvalidOperationException("Extended NAT observation: " + natEcho.ErrorCode + "/" + natList.ErrorCode); }
    if (natEcho.Observation!.StateDigest != natList.Observation!.StateDigest ||
        NftNatCompiler.Compile(natList.Observation.Policy, routerIdentity).Candidate != NftNatCompiler.Compile(RouterPolicySamples.Nat(), routerIdentity).Candidate)
    { throw new InvalidOperationException("Extended NAT round-trip diverged."); }
    return 0;
}

if (mode == "schema1")
{
    var rules = new List<FilterRule?>();
    foreach (var family in Enum.GetValues<IpFamily>())
    {
        var address = family == IpFamily.IPv4 ? "192.0.2.1/32" : "2001:db8::1/128";
        rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Drop, DestinationPort: 18082));
        rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Accept, new(address), new(address)));
        rules.Add(new(family, FilterProtocol.Udp, FilterVerdict.Accept, new(address), new(address), 18081));
        rules.Add(new(family, family == IpFamily.IPv4 ? FilterProtocol.Icmp : FilterProtocol.IcmpV6, FilterVerdict.Accept));
    }

    var result = NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, rules));
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("The fixed fixture policy must compile.");
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "router")
{
    var policy = FilterProjection(BuildRouterPolicy());
    var result = NftFilterCompiler.Compile(policy, routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Router schema-2 policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-router" && args.Length is 3 or 4)
{
    var expected = NftFilterCompiler.Compile(FilterProjection(BuildRouterPolicy()), routerIdentity).Candidate!;
    var echoJson = File.ReadAllText(args[1]);
    var listJson = File.ReadAllText(args[2]);
    var echoed = NftTableObservation.ParseReplacementEcho(echoJson);
    if (!echoed.IsSuccess)
    {
        throw new InvalidOperationException("Router echo failed: " + echoed.ErrorCode);
    }

    var listed = NftTableObservation.Parse(listJson);
    if (!listed.IsSuccess)
    {
        throw new InvalidOperationException("Router listing failed: " + listed.ErrorCode);
    }

    if (echoed.Observation!.StateDigest != listed.Observation!.StateDigest)
    {
        throw new InvalidOperationException("Router echo and listing state digests diverged.");
    }

    if (args.Length == 4)
    {
        var terseJson = File.ReadAllText(args[3]);
        if (nativeProjection)
        {
            if (NftTableObservation.Parse(terseJson).IsSuccess) { throw new InvalidOperationException("Incomplete static set listing was accepted."); }
            var root = System.Text.Json.Nodes.JsonNode.Parse(listJson)!;
            var meta = root["nftables"]![0]!;
            var names = NftStaticSetCollection.Names(terseJson, "inet", "nergal_filter");
            var replies = root["nftables"]!.AsArray().Where(i => i?["set"] is { } set && names.Contains(set["name"]!.GetValue<string>()))
                .Select(i => new System.Text.Json.Nodes.JsonObject { ["nftables"] = new System.Text.Json.Nodes.JsonArray(meta.DeepClone(), i!.DeepClone()) }.ToJsonString());
            terseJson = NftStaticSetCollection.Complete(terseJson, "inet", "nergal_filter", replies);
        }
        var terse = NftTableObservation.Parse(terseJson);
        if (!terse.IsSuccess)
        {
            throw new InvalidOperationException("Router terse listing failed: " + terse.ErrorCode);
        }

        if (terse.Observation!.StateDigest != listed.Observation.StateDigest)
        {
            throw new InvalidOperationException("Router plain and terse state digests diverged.");
        }
    }

    var recompiled = NftFilterCompiler.Compile(listed.Observation.Policy, listed.Observation.Identity).Candidate;
    if (recompiled != expected)
    {
        throw new InvalidOperationException("Router policy did not round-trip deterministically.");
    }

    return 0;
}

if (mode == "nat-filter")
{
    var result = NftFilterCompiler.Compile(FilterProjection(BuildNatFilterPolicy()), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("NAT filter policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode is "state-accept-on" or "state-accept-off" or "state-drop-on" or "state-drop-off")
{
    FilterPolicy policy;
    if (mode.StartsWith("state-accept", StringComparison.Ordinal)) { policy = BuildPinnedPolicy(); }
    else
    {
        policy = new(2, FilterVerdict.Accept, FilterVerdict.Drop, FilterVerdict.Accept,
        [new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Drop), new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Drop)]);
    }
    if (mode.EndsWith("off", StringComparison.Ordinal))
    { policy = new(policy.SchemaVersion, policy.InputDefaultVerdict, policy.ForwardDefaultVerdict, policy.OutputDefaultVerdict, policy.Rules.Select(r => r! with { Enabled = false })); }
    var result = NftFilterCompiler.Compile(policy, routerIdentity);
    if (!result.IsSuccess) { throw new InvalidOperationException(string.Join(", ", result.Diagnostics)); }
    Console.Write(result.Candidate); return 0;
}

if (mode is "sets" or "pinned")
{
    var result = NftFilterCompiler.Compile(FilterProjection(mode == "pinned" ? BuildPinnedPolicy() : BuildSetsPolicy()), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Sets policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode is "verify-sets" or "verify-pinned" && args.Length == 3)
{
    var expected = NftFilterCompiler.Compile(FilterProjection(mode == "verify-pinned" ? BuildPinnedPolicy() : BuildSetsPolicy()), routerIdentity).Candidate!;
    var echoed = NftTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    if (!echoed.IsSuccess)
    {
        throw new InvalidOperationException("Sets echo failed: " + echoed.ErrorCode);
    }

    var listed = NftTableObservation.Parse(File.ReadAllText(args[2]));
    if (!listed.IsSuccess)
    {
        throw new InvalidOperationException("Sets listing failed: " + listed.ErrorCode);
    }

    if (echoed.Observation!.StateDigest != listed.Observation!.StateDigest)
    {
        throw new InvalidOperationException("Sets echo and listing state digests diverged.");
    }

    var recompiled = NftFilterCompiler.Compile(listed.Observation.Policy, listed.Observation.Identity).Candidate;
    if (recompiled != expected)
    {
        throw new InvalidOperationException("Sets policy did not round-trip deterministically.");
    }

    return 0;
}

if (mode is "nat" or "nat-negated")
{
    var result = NftNatCompiler.Compile(NatProjection(BuildNatPolicy(mode == "nat-negated")), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("NAT policy failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-nat-negated" && args.Length == 3)
{
    var echo = NftNatTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    var listed = NftNatTableObservation.Parse(File.ReadAllText(args[2]));
    if (!echo.IsSuccess || !listed.IsSuccess || echo.Observation!.StateDigest != listed.Observation!.StateDigest ||
        NftNatCompiler.Compile(listed.Observation.Policy, routerIdentity).Candidate != NftNatCompiler.Compile(NatProjection(BuildNatPolicy(true)), routerIdentity).Candidate)
    { throw new InvalidOperationException("Complete negated DNAT address sets failed native round-trip."); }
    return 0;
}

if (mode == "verify-nat" && args.Length == 5)
{
    var expectedFilter = NftFilterCompiler.Compile(FilterProjection(BuildNatFilterPolicy()), routerIdentity).Candidate!;
    var expectedNat = NftNatCompiler.Compile(NatProjection(BuildNatPolicy()), routerIdentity).Candidate!;

    var filterEcho = NftTableObservation.ParseReplacementEcho(File.ReadAllText(args[1]));
    var filterList = NftTableObservation.Parse(File.ReadAllText(args[2]));
    if (!filterEcho.IsSuccess || !filterList.IsSuccess ||
        filterEcho.Observation!.StateDigest != filterList.Observation!.StateDigest ||
        NftFilterCompiler.Compile(filterList.Observation.Policy, filterList.Observation.Identity).Candidate != expectedFilter)
    {
        throw new InvalidOperationException("NAT filter observation verification failed.");
    }

    var natEcho = NftNatTableObservation.ParseReplacementEcho(File.ReadAllText(args[3]));
    var natList = NftNatTableObservation.Parse(File.ReadAllText(args[4]));
    if (!natEcho.IsSuccess || !natList.IsSuccess ||
        natEcho.Observation!.StateDigest != natList.Observation!.StateDigest ||
        NftNatCompiler.Compile(natList.Observation.Policy, natList.Observation.Identity).Candidate != expectedNat)
    {
        throw new InvalidOperationException("NAT table observation verification failed.");
    }

    return 0;
}

if (mode == "bundle-create")
{
    var result = NftPolicyBundleCompiler.Compile(BuildBundleV1(), routerIdentity);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Bundle v1 compile failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "bundle-replace")
{
    var result = NftPolicyBundleCompiler.CompileAtomicReplacement(
        BuildBundleV2(), routerIdentity, filterExists: true, natExists: true, bridgeExists: true);
    if (!result.IsSuccess)
    {
        throw new InvalidOperationException("Bundle v2 replace compile failed: " + string.Join(", ", result.Diagnostics));
    }

    Console.Write(result.Candidate);
    return 0;
}

if (mode == "verify-bundle" && args.Length == 3)
{
    var v2 = BuildBundleV2();
    var expectedFilter = NftFilterCompiler.Compile(v2.Filter, routerIdentity).Candidate!;
    var expectedBridge = NftBridgeCompiler.Compile(v2.Bridge!, routerIdentity).Candidate!;

    var filterList = NftTableObservation.Parse(File.ReadAllText(args[1]));
    if (!filterList.IsSuccess ||
        NftFilterCompiler.Compile(filterList.Observation!.Policy, filterList.Observation.Identity).Candidate != expectedFilter)
    {
        throw new InvalidOperationException("Bundle filter listing failed.");
    }

    var bridgeList = NftBridgeTableObservation.Parse(File.ReadAllText(args[2]));
    if (!bridgeList.IsSuccess ||
        NftBridgeCompiler.Compile(bridgeList.Observation!.Policy, bridgeList.Observation.Identity).Candidate != expectedBridge)
    {
        throw new InvalidOperationException("Bundle bridge listing failed.");
    }

    return 0;
}

throw new ArgumentException("Unsupported fixture mode.");

static FirewallPolicyBundle BuildBundleV1() => new(1,
    new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []),
    new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.99/32"), "192.0.2.20", 80, 8080)], []),
    new(1, FilterVerdict.Drop,
    [
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
    ]));

static FirewallPolicyBundle BuildBundleV2() => new(1,
    new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, []),
    null,
    new(1, FilterVerdict.Drop,
    [
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.Arp, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv4, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
        new(BridgeEtherType.IPv6, FilterVerdict.Accept, "veth_br_a", "veth_br_b"),
        new(BridgeEtherType.IPv6, FilterVerdict.Accept, "veth_br_b", "veth_br_a"),
    ]));

static FilterPolicy BuildNatFilterPolicy()
{
    var rules = new List<FilterRule?>
    {
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        // Permit port 18447 forward ONLY for DNAT-translated connections (`ct status dnat`).
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Destination: new("198.51.100.2/32"), DestinationPort: 18447, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, MatchOriginalDestinationDnat: true),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, Destination: new("2001:db8:2::2/128"), DestinationPort: 18447, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, MatchOriginalDestinationDnat: true),
    };

    return new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, rules);
}

static NatPolicy BuildNatPolicy(bool negate = false)
{
    var literal = new NatPolicy(1,
    [
        new(IpFamily.IPv4, FilterProtocol.Tcp, null, "198.51.100.2", null, 18447, "r_cli", OriginalPorts: [18446, 18448], NegateSource: negate, NegateDestination: negate,
            SourcePrefixes: [new(negate ? "192.0.2.50/32" : "192.0.2.2/32"), new("192.0.2.90/32")], DestinationPrefixes: [new(negate ? "192.0.2.11/32" : "192.0.2.1/32"), new(negate ? "192.0.2.90/32" : "192.0.2.9/32")]),
        new(IpFamily.IPv6, FilterProtocol.Tcp, null, "2001:db8:2::2", null, 18447, "r_cli", OriginalPorts: [18446, 18448], NegateSource: negate, NegateDestination: negate,
            SourcePrefixes: [new(negate ? "2001:db8:1::50/128" : "2001:db8:1::2/128"), new("2001:db8:1::90/128")], DestinationPrefixes: [new(negate ? "2001:db8:1::11/128" : "2001:db8:1::1/128"), new(negate ? "2001:db8:1::90/128" : "2001:db8:1::9/128")]),
    ],
    [
        new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", new("198.51.100.0/24"), "r_srv"),
        new(IpFamily.IPv6, new("2001:db8:1::/64"), "2001:db8:2::1", new("2001:db8:2::/64"), "r_srv"),
    ]);

    return RouterPolicySamples.WithTransportReferences(RouterPolicySamples.WithDnatAddressReferences(new(1, new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []), literal))).Nat!;
}

static FilterPolicy BuildRouterPolicy()
{
    var rules = new List<FilterRule?>
    {
        // Input: allow IPv6 Neighbor Discovery on both router interfaces under drop default.
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Input, InputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        // Output: allow kernel-originated IPv6 Neighbor Discovery on both interfaces under drop default.
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_cli", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Output, OutputInterface: "r_srv", IcmpType: FilterIcmpTypes.NdNeighborAdvert),
        // Forward: permit established/related reply packets from server back to client.
        new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_srv", OutputInterface: "r_cli", ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
        // Forward: permit client -> server TCP 18443 and ICMP/ICMPv6 echo-request (NEW) plus established packets.
        new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, new("192.0.2.0/24"), new("198.51.100.0/24"), 18443, FilterChainKind.Forward, "r_cli", "r_srv", ConnectionStateFlags.New | ConnectionStateFlags.Established),
        new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, new("2001:db8:1::/64"), new("2001:db8:2::/64"), 18443, FilterChainKind.Forward, "r_cli", "r_srv", ConnectionStateFlags.New | ConnectionStateFlags.Established),
        new(IpFamily.IPv4, FilterProtocol.Icmp, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, IcmpType: FilterIcmpTypes.EchoRequest),
        new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept, Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv", ConnectionStates: ConnectionStateFlags.New | ConnectionStateFlags.Established, IcmpType: FilterIcmpTypes.EchoRequest),
        // Forward: per-source UDP 18445 rate limit (burst 2, 2/minute).
        new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, new("192.0.2.0/24"), new("198.51.100.0/24"), 18445, FilterChainKind.Forward, "r_cli", "r_srv", RateLimit: new(2, RateLimitTimeUnit.Minute, 2, 60)),
        new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, new("2001:db8:1::/64"), new("2001:db8:2::/64"), 18445, FilterChainKind.Forward, "r_cli", "r_srv", RateLimit: new(2, RateLimitTimeUnit.Minute, 2, 60)),
    };

    return new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop, rules);
}

static FilterPolicy BuildSetsPolicy() => new(
    2,
    FilterVerdict.Drop,
    FilterVerdict.Drop,
    FilterVerdict.Accept,
    [
        new(
            IpFamily.IPv4,
            FilterProtocol.Tcp,
            FilterVerdict.Accept,
            Chain: FilterChainKind.Input,
            SourcePrefixes: [new("192.0.2.0/24"), new("198.51.100.0/24")],
            DestinationPorts: [80, 443]),
        new(
            IpFamily.IPv6,
            FilterProtocol.Udp,
            FilterVerdict.Accept,
            Chain: FilterChainKind.Forward,
            DestinationPrefixes: [new("2001:db8:1::/48"), new("2001:db8:3::/48")],
            DestinationPorts: [53, 5353]),
        new(
            IpFamily.IPv4,
            FilterProtocol.Icmp,
            FilterVerdict.Accept,
            Chain: FilterChainKind.Input,
            IcmpType: FilterIcmpTypes.ParameterProblem),
    ]);

static FilterPolicy BuildPinnedPolicy()
{
    PolicyObjectReference Ref(string name, Nergal.Core.Controller.ReusableObjectKind kind, params string[] entries)
    {
        var content = new Nergal.Core.Controller.ReusableObjectContent(name, kind, "", entries);
        return new(Guid.ParseExact(content.Digest[..32], "N"), 1, content);
    }
    var rules = new List<FilterRule?>();
    foreach (var family in new[] { IpFamily.IPv4, IpFamily.IPv6 })
    {
        var v4 = family == IpFamily.IPv4;
        var kind = v4 ? Nergal.Core.Controller.ReusableObjectKind.Ipv4 : Nergal.Core.Controller.ReusableObjectKind.Ipv6;
        rules.Add(new(family, FilterProtocol.Udp, FilterVerdict.Accept,
            SourceObject: Ref(v4 ? "clients4" : "clients6", kind, v4 ? "127.0.0.2" : "2001:db8::2", v4 ? "127.0.0.4" : "2001:db8::4"),
            DestinationObject: Ref(v4 ? "server4" : "server6", kind, v4 ? "127.0.0.1" : "2001:db8::1"),
            DestinationPortObject: Ref("services", Nergal.Core.Controller.ReusableObjectKind.Port, "19001", "19003")));
    }
    return new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, rules);
}
