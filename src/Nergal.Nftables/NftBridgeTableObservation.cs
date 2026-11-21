using System.Globalization;
using System.Text;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Result of parsing native JSON for the reserved <c>bridge nergal_bridge</c> table.</summary>
public sealed class NftBridgeObservationResult
{
    internal NftBridgeObservationResult(NftBridgeTableObservation? observation, string? errorCode)
    {
        Observation = observation;
        ErrorCode = errorCode;
    }

    /// <summary>Gets the complete bridge table observation, or null on any validation failure.</summary>
    public NftBridgeTableObservation? Observation { get; }

    /// <summary>Gets the stable denial code, or null on success.</summary>
    public string? ErrorCode { get; }

    /// <summary>Gets whether the native bridge JSON was fully recognized and valid.</summary>
    public bool IsSuccess => Observation is not null;
}

/// <summary>Immutable native observation of <c>bridge nergal_bridge</c> forward chain and ordered L2 rules.</summary>
public sealed class NftBridgeTableObservation
{
    private NftBridgeTableObservation(
        NftTableIdentity identity,
        ulong tableHandle,
        ulong forwardChainHandle,
        BridgePolicy policy,
        List<(ulong Handle, BridgeFilterRule Rule)> rules)
    {
        Identity = identity;
        TableHandle = tableHandle;
        ForwardChainHandle = forwardChainHandle;
        Policy = policy;

        var projection = new StringBuilder(string.Join('\n',
            "nergal-bridge-observation-v1",
            identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture),
            string.Join(' ',
                forwardChainHandle.ToString(CultureInfo.InvariantCulture),
                "bridge", NftBridgeCompiler.TableName, "forward", "filter", "forward", "-200",
                policy.DefaultVerdict == FilterVerdict.Accept ? "accept" : "drop")));

        foreach (var (handle, rule) in rules)
        {
            projection.Append('\n')
                .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(' ')
                .Append(rule.InputInterface ?? "-").Append(' ')
                .Append(rule.OutputInterface ?? "-").Append(' ')
                .Append(rule.EtherType).Append(' ')
                .Append(rule.Verdict == FilterVerdict.Accept ? "accept" : "drop");
        }

        StateDigest = CandidateDigest.FromText(projection.ToString());
    }

    /// <summary>Gets the canonical owner/resource marker parsed from the table comment.</summary>
    public NftTableIdentity Identity { get; }

    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }

    /// <summary>Gets the positive native forward chain handle.</summary>
    public ulong ForwardChainHandle { get; }

    /// <summary>Gets the reconstructed typed bridge policy.</summary>
    public BridgePolicy Policy { get; }

    /// <summary>Gets the SHA-256 fingerprint over all recognized bridge objects, handles, and rules.</summary>
    public CandidateDigest StateDigest { get; }

    /// <summary>Parses a full native <c>nft --json list table bridge nergal_bridge</c> snapshot.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    public static NftBridgeObservationResult Parse(string json) => ParseNative(json, isEcho: false);

    /// <summary>Parses handle-bearing <c>nft --echo --handle --json</c> output for <c>bridge nergal_bridge</c>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    public static NftBridgeObservationResult ParseReplacementEcho(string json) => ParseNative(json, isEcho: true);

    private static NftBridgeObservationResult ParseNative(string json, bool isEcho)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(json) > 65536)
            {
                return Deny("observation.tooLarge");
            }

            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (NftJsonHelpers.HasDuplicateProperties(document.RootElement))
            {
                return Deny("observation.duplicateProperty");
            }

            var root = document.RootElement;
            if (!NftJsonHelpers.Properties(root, "nftables") || root.GetProperty("nftables").ValueKind != JsonValueKind.Array)
            {
                return Deny("observation.shape");
            }

            var items = root.GetProperty("nftables").EnumerateArray().ToArray();
            JsonElement table, chain;
            int ruleStartIndex;
            if (isEcho)
            {
                if (items.Length < 2 ||
                    !NftJsonHelpers.Properties(items[0], "create") || !NftJsonHelpers.Properties(items[0].GetProperty("create"), "table") ||
                    !NftJsonHelpers.Properties(items[1], "add") || !NftJsonHelpers.Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.replacementEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
                ruleStartIndex = 2;
            }
            else
            {
                if (items.Length < 3 || !NftJsonHelpers.Properties(items[0], "metainfo"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                if (!NftJsonHelpers.TryReadMetaHeader(items))
                {
                    return Deny("observation.schema");
                }

                if (!NftJsonHelpers.Properties(items[1], "table") || !NftJsonHelpers.Properties(items[2], "chain"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                table = items[1].GetProperty("table");
                chain = items[2].GetProperty("chain");
                ruleStartIndex = 3;
            }

            if (!NftJsonHelpers.Properties(table, "family", "name", "handle", "comment") ||
                !NftJsonHelpers.Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
            {
                return Deny("observation.fields");
            }

            if (table.GetProperty("family").GetString() != "bridge" || table.GetProperty("name").GetString() != NftBridgeCompiler.TableName ||
                chain.GetProperty("family").GetString() != "bridge" || chain.GetProperty("table").GetString() != NftBridgeCompiler.TableName ||
                chain.GetProperty("name").GetString() != "forward" || chain.GetProperty("type").GetString() != "filter" ||
                chain.GetProperty("hook").GetString() != "forward" || chain.GetProperty("prio").ValueKind != JsonValueKind.Number ||
                !chain.GetProperty("prio").TryGetInt32(out var priority) || priority != -200)
            {
                return Deny("observation.scope");
            }

            if (table.GetProperty("handle").ValueKind != JsonValueKind.Number || !table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0 ||
                chain.GetProperty("handle").ValueKind != JsonValueKind.Number || !chain.GetProperty("handle").TryGetUInt64(out var chainHandle) || chainHandle == 0)
            {
                return Deny("observation.handle");
            }

            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null)
            {
                return Deny("observation.identity");
            }

            var policyToken = chain.GetProperty("policy").GetString();
            if (policyToken is not ("accept" or "drop"))
            {
                return Deny("observation.policy");
            }

            var defaultVerdict = policyToken == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop;
            var handles = new HashSet<ulong> { chainHandle };
            var rules = new List<(ulong Handle, BridgeFilterRule Rule)>();

            for (var index = ruleStartIndex; index < items.Length; index++)
            {
                JsonElement rule;
                if (isEcho)
                {
                    if (!NftJsonHelpers.Properties(items[index], "add") || !NftJsonHelpers.Properties(items[index].GetProperty("add"), "rule"))
                    {
                        return Deny("observation.replacementEcho");
                    }

                    rule = items[index].GetProperty("add").GetProperty("rule");
                }
                else
                {
                    if (!NftJsonHelpers.Properties(items[index], "rule"))
                    {
                        return Deny("observation.unsupportedObjects");
                    }

                    rule = items[index].GetProperty("rule");
                }

                if (!NftJsonHelpers.Properties(rule, "family", "table", "chain", "handle", "expr"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                if (rule.GetProperty("family").GetString() != "bridge" ||
                    rule.GetProperty("table").GetString() != NftBridgeCompiler.TableName ||
                    rule.GetProperty("chain").GetString() != "forward")
                {
                    return Deny("observation.scope");
                }

                if (!rule.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle))
                {
                    return Deny("observation.handle");
                }

                var parsed = ParseBridgeRule(rule.GetProperty("expr"));
                if (parsed is null)
                {
                    return Deny("observation.rule");
                }

                rules.Add((handle, parsed));
            }

            var policy = new BridgePolicy(BridgePolicy.CurrentSchemaVersion, defaultVerdict, rules.Select(entry => entry.Rule));
            return new(new(identity, tableHandle, chainHandle, policy, rules), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static BridgeFilterRule? ParseBridgeRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 1 or > 4)
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        var accept = NftJsonHelpers.Properties(terminal, "accept");
        if ((!accept && !NftJsonHelpers.Properties(terminal, "drop")) ||
            terminal.GetProperty(accept ? "accept" : "drop").ValueKind != JsonValueKind.Null)
        {
            return null;
        }

        string? inputInterface = null;
        string? outputInterface = null;
        var etherType = BridgeEtherType.Any;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (!NftJsonHelpers.Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!NftJsonHelpers.Properties(match, "op", "left", "right") ||
                match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() != "==")
            {
                return null;
            }

            var left = match.GetProperty("left");
            var right = match.GetProperty("right");
            if (NftJsonHelpers.Properties(left, "meta") && NftJsonHelpers.Properties(left.GetProperty("meta"), "key"))
            {
                var key = left.GetProperty("meta").GetProperty("key");
                if (key.ValueKind != JsonValueKind.String || right.ValueKind != JsonValueKind.String) { return null; }
                var keyName = key.GetString();
                var iface = right.GetString();
                if (!FilterPolicyValidation.IsValidInterfaceName(iface)) { return null; }

                if (keyName == "iifname" && stage < 0)
                {
                    inputInterface = iface;
                    stage = 0;
                    continue;
                }

                if (keyName == "oifname" && stage < 1)
                {
                    outputInterface = iface;
                    stage = 1;
                    continue;
                }

                return null;
            }

            if (NftJsonHelpers.Properties(left, "payload") && NftJsonHelpers.Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                if (stage >= 2 ||
                    payload.GetProperty("protocol").GetString() != "ether" ||
                    payload.GetProperty("field").GetString() != "type" ||
                    right.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                BridgeEtherType? parsedEther = right.GetString() switch
                {
                    "ip" => BridgeEtherType.IPv4,
                    "ip6" => BridgeEtherType.IPv6,
                    "arp" => BridgeEtherType.Arp,
                    _ => null,
                };
                if (parsedEther is null) { return null; }
                etherType = parsedEther.Value;
                stage = 2;
                continue;
            }

            return null;
        }

        return new(etherType, accept ? FilterVerdict.Accept : FilterVerdict.Drop, inputInterface, outputInterface);
    }

    private static NftBridgeObservationResult Deny(string code) => new(null, code);
}
