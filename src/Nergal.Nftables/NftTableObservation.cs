using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Observed presence and ownership state of managed auxiliary tables (<c>inet nergal_nat</c> and <c>bridge nergal_bridge</c>).</summary>
public sealed record AuxiliaryTablePresence(bool NatExists, bool NatOwned, bool BridgeExists, bool BridgeOwned, bool AuxiliaryExists = false, bool AuxiliaryOwned = false);

/// <summary>Immutable native observation of one tagged table and supported ordered rules; never a claim of authority.</summary>
public sealed partial class NftTableObservation
{
    private sealed record ObservedRateLimitSet(string Name, ulong Handle, IpFamily Family);

    private NftTableObservation(
        NftTableIdentity identity,
        ulong tableHandle,
        ulong inputChainHandle,
        ulong forwardChainHandle,
        ulong outputChainHandle,
        FilterPolicy policy,
        List<(ulong Handle, FilterRule Rule)> rules,
        List<ObservedRateLimitSet> sets,
        ulong rpHandle = 0,
        IReadOnlyList<ulong>? rpRuleHandles = null,
        ulong mssHandle = 0)
    {
        Identity = identity;
        TableHandle = tableHandle;
        ChainHandle = inputChainHandle;
        ForwardChainHandle = forwardChainHandle;
        OutputChainHandle = outputChainHandle;
        Policy = policy;

        if (policy.SchemaVersion == 1)
        {
            var isFamilyOnly = rules.All(entry => entry.Rule.Protocol == FilterProtocol.Any &&
                entry.Rule.Source is null && entry.Rule.Destination is null && !entry.Rule.DestinationPort.HasValue);
            var version = rules.Count == 0 ? "nergal-observation-v1" : isFamilyOnly ? "nergal-observation-v2" : "nergal-observation-v3";
            var projection = new StringBuilder(string.Join('\n', version, identity.Comment,
                tableHandle.ToString(CultureInfo.InvariantCulture), inputChainHandle.ToString(CultureInfo.InvariantCulture),
                "inet", NftFilterCompiler.TableName, "input", "filter", "input", "0",
                VerdictToken(policy.InputDefaultVerdict)));
            foreach (var (handle, rule) in rules)
            {
                if (isFamilyOnly)
                {
                    projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture))
                        .Append(rule.Family == IpFamily.IPv4 ? " ipv4 " : " ipv6 ")
                        .Append(VerdictToken(rule.Verdict));
                }
                else
                {
                    projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture))
                        .Append(rule.Family == IpFamily.IPv4 ? " ipv4 " : " ipv6 ")
                        .Append(rule.Source?.Value ?? "-").Append(' ')
                        .Append(rule.Destination?.Value ?? "-").Append(' ')
                        .Append(ProtocolToken(rule.Protocol)).Append(' ')
                        .Append(rule.DestinationPort?.ToString(CultureInfo.InvariantCulture) ?? "-").Append(' ')
                        .Append(VerdictToken(rule.Verdict));
                }
            }

            StateDigest = CandidateDigest.FromText(projection.ToString());
        }
        else
        {
            var hasSets = sets.Count > 0;
            var hasDnatStatus = rules.Any(entry => entry.Rule.MatchOriginalDestinationDnat);
            var hasRouter = policy.RpFilter is not null || policy.ForwardTcpMssClamp is not null || rules.Any(e => HasRouterMatchers(e.Rule));
            var version = hasRouter ? "nergal-observation-v7" : hasDnatStatus ? "nergal-observation-v6" : hasSets ? "nergal-observation-v5" : "nergal-observation-v4";
            var projection = new StringBuilder(string.Join('\n',
                version,
                identity.Comment,
                tableHandle.ToString(CultureInfo.InvariantCulture),
                string.Join(' ', inputChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftFilterCompiler.TableName, "input", "filter", "input", "0", VerdictToken(policy.InputDefaultVerdict)),
                string.Join(' ', forwardChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftFilterCompiler.TableName, "forward", "filter", "forward", "0", VerdictToken(policy.ForwardDefaultVerdict)),
                string.Join(' ', outputChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftFilterCompiler.TableName, "output", "filter", "output", "0", VerdictToken(policy.OutputDefaultVerdict))));
            foreach (var set in sets)
            {
                projection.Append('\n')
                    .Append(set.Handle.ToString(CultureInfo.InvariantCulture)).Append(' ')
                    .Append(set.Name).Append(' ')
                    .Append(set.Family == IpFamily.IPv4 ? "ipv4_addr" : "ipv6_addr").Append(" 65535");
            }

            foreach (var (handle, rule) in rules)
            {
                projection.Append('\n')
                    .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(' ')
                    .Append(ChainToken(rule.Chain)).Append(' ')
                    .Append(rule.Family == IpFamily.IPv4 ? "ipv4" : "ipv6").Append(' ')
                    .Append(rule.InputInterface ?? "-").Append(' ')
                    .Append(rule.OutputInterface ?? "-").Append(' ')
                    .Append(PrefixOrSetProjection(rule.Source, rule.SourcePrefixes)).Append(' ')
                    .Append(PrefixOrSetProjection(rule.Destination, rule.DestinationPrefixes)).Append(' ');
                if (hasDnatStatus)
                {
                    projection.Append(rule.MatchOriginalDestinationDnat ? "dnat" : "-").Append(' ');
                }

                projection.Append(ConnectionStateProjection(rule.ConnectionStates)).Append(' ')
                    .Append(ProtocolToken(rule.Protocol)).Append(' ')
                    .Append(PortOrSetProjection(rule.DestinationPort, rule.DestinationPorts)).Append(' ')
                    .Append(rule.IcmpType ?? "-").Append(' ');
                if (hasSets || hasDnatStatus)
                {
                    projection.Append(RateLimitProjection(rule.RateLimit)).Append(' ');
                }

                if (hasRouter) { projection.Append(RouterProjection(rule)).Append(' '); }
                projection.Append(VerdictToken(rule.Verdict));
            }

            if (hasRouter)
            {
                projection.Append("\nrp ").Append(rpHandle.ToString(CultureInfo.InvariantCulture));
                if (policy.RpFilter is { } rp)
                {
                    projection.Append(' ').Append(VerdictToken(rp.DefaultVerdict));
                    for (var i = 0; i < rp.Rules.Count; i++)
                    {
                        var r = rp.Rules[i]!;
                        projection.Append('\n').Append(rpRuleHandles![i].ToString(CultureInfo.InvariantCulture)).Append(' ');
                        RouterFilterValidation.AppendRpFilterRule(projection, r);
                    }
                }
                projection.Append("\nmss ").Append(mssHandle.ToString(CultureInfo.InvariantCulture)).Append(' ')
                    .Append(policy.ForwardTcpMssClamp?.ToString(CultureInfo.InvariantCulture) ?? "-");
            }

            StateDigest = CandidateDigest.FromText(projection.ToString());
        }
    }

    /// <summary>Gets the observed canonical marker; it must agree with protected expected enrollment.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the positive native input chain handle, included in the complete state fingerprint.</summary>
    public ulong ChainHandle { get; }
    /// <summary>Gets the forward chain handle for schema-2 observations, or 0 for schema-1 observations.</summary>
    public ulong ForwardChainHandle { get; }
    /// <summary>Gets the output chain handle for schema-2 observations, or 0 for schema-1 observations.</summary>
    public ulong OutputChainHandle { get; }
    /// <summary>Gets the observed unmatched-input decision.</summary>
    public FilterVerdict DefaultVerdict => Policy.DefaultVerdict;
    /// <summary>Gets the immutable policy reconstructed from every recognized rule in native order.</summary>
    public FilterPolicy Policy { get; }
    /// <summary>Gets the deterministic fingerprint of all recognized enforcement/identity fields.</summary>
    public CandidateDigest StateDigest { get; }

    /// <summary>Parses bounded native JSON without host access, accepting empty chains and canonical schema-1 input-filter rules.</summary>
    /// <remarks>Unknown objects, fields, duplicate keys and unsupported rule expressions fail closed. The trusted collector must supply a full table snapshot; omitted kernel objects cannot be detected from JSON alone.</remarks>
    /// <exception cref="ArgumentNullException">JSON is null.</exception>
    public static NftObservationResult Parse(string json) => ParseNative(json, EchoMode.None);

    /// <summary>Reads the handle-bearing echo of a successful local exclusive create of an empty accept baseline.</summary>
    /// <remarks>Caller must establish successful transaction exit and independently compare a complete listing before binding.</remarks>
    public static NftObservationResult ParseEnrollmentEcho(string json) => ParseNative(json, EchoMode.Enrollment);

    /// <summary>Reads the handle-bearing echo of a successful atomic table delete-and-recreate or rule-bearing create batch.</summary>
    /// <remarks>Caller must establish successful transaction exit and independently compare a complete listing before recording receipts.</remarks>
    public static NftObservationResult ParseReplacementEcho(string json) => ParseNative(json, EchoMode.Replacement);

    /// <summary>Inspects <c>nft --terse --json list tables</c> output for auxiliary <c>nergal_nat</c> and <c>nergal_bridge</c> table presence and ownership.</summary>
    public static bool TryInspectAuxiliaryTables(
        string listTablesJson,
        NftTableIdentity expectedIdentity,
        out AuxiliaryTablePresence? presence,
        out string? errorCode)
    {
        ArgumentNullException.ThrowIfNull(listTablesJson);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        presence = null;

        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(listTablesJson) > 65536)
            {
                errorCode = "observation.tooLarge";
                return false;
            }

            using var document = JsonDocument.Parse(listTablesJson, new JsonDocumentOptions { MaxDepth = 16 });
            if (HasDuplicateProperties(document.RootElement))
            {
                errorCode = "observation.duplicateProperty";
                return false;
            }

            var root = document.RootElement;
            if (!Properties(root, "nftables") || root.GetProperty("nftables").ValueKind != JsonValueKind.Array)
            {
                errorCode = "observation.shape";
                return false;
            }

            bool natExists = false, natOwned = false, bridgeExists = false, bridgeOwned = false, auxiliaryExists = false, auxiliaryOwned = false;
            var first = true;
            foreach (var item in root.GetProperty("nftables").EnumerateArray())
            {
                if (first)
                {
                    first = false;
                    if (!Properties(item, "metainfo"))
                    {
                        errorCode = "observation.unsupportedObjects";
                        return false;
                    }

                    continue;
                }

                if (!Properties(item, "table"))
                {
                    errorCode = "observation.unsupportedObjects";
                    return false;
                }

                var tbl = item.GetProperty("table");
                if (tbl.ValueKind != JsonValueKind.Object ||
                    !tbl.TryGetProperty("family", out var famEl) || famEl.ValueKind != JsonValueKind.String ||
                    !tbl.TryGetProperty("name", out var nameEl) || nameEl.ValueKind != JsonValueKind.String)
                {
                    errorCode = "observation.fields";
                    return false;
                }

                var family = famEl.GetString();
                var name = nameEl.GetString();
                var comment = tbl.TryGetProperty("comment", out var cEl) && cEl.ValueKind == JsonValueKind.String
                    ? cEl.GetString()
                    : null;

                if (family == "inet" && name == NftNatCompiler.TableName)
                {
                    if (natExists)
                    {
                        errorCode = "observation.duplicateTable";
                        return false;
                    }

                    natExists = true;
                    natOwned = string.Equals(comment, expectedIdentity.Comment, StringComparison.Ordinal);
                }
                else if (family == "inet" && name == NftAuxiliaryTableObservation.TableName)
                {
                    if (auxiliaryExists) { errorCode = "observation.duplicateTable"; return false; }
                    auxiliaryExists = true;
                    auxiliaryOwned = string.Equals(comment, expectedIdentity.Comment, StringComparison.Ordinal);
                }
                else if (family == "bridge" && name == NftBridgeCompiler.TableName)
                {
                    if (bridgeExists)
                    {
                        errorCode = "observation.duplicateTable";
                        return false;
                    }

                    bridgeExists = true;
                    bridgeOwned = string.Equals(comment, expectedIdentity.Comment, StringComparison.Ordinal);
                }
            }

            presence = new AuxiliaryTablePresence(natExists, natOwned, bridgeExists, bridgeOwned, auxiliaryExists, auxiliaryOwned);
            errorCode = null;
            return true;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            errorCode = "observation.invalidJson";
            return false;
        }
    }

    /// <summary>Reads a complete coordinated replacement echo, binding every expected table's recognized semantics and native handles.</summary>
    public static NftObservationResult ParseBundleReplacementEcho(
        string json, NftTableIdentity expectedIdentity, bool expectNat, bool expectBridge, bool expectAuxiliary = false)
    {
        ArgumentNullException.ThrowIfNull(json);
        ArgumentNullException.ThrowIfNull(expectedIdentity);
        try
        {
            if (Encoding.UTF8.GetByteCount(json) > 65536) { return Deny("observation.tooLarge"); }
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (HasDuplicateProperties(doc.RootElement)) { return Deny("observation.duplicateProperty"); }
            if (!Properties(doc.RootElement, "nftables") || doc.RootElement.GetProperty("nftables").ValueKind != JsonValueKind.Array) { return Deny("observation.shape"); }
            var groups = new Dictionary<string, JsonArray>(StringComparer.Ordinal);
            JsonArray? active = null;
            var rank = -1;
            foreach (var item in doc.RootElement.GetProperty("nftables").EnumerateArray())
            {
                if (Properties(item, "create") && Properties(item.GetProperty("create"), "table"))
                {
                    var table = item.GetProperty("create").GetProperty("table");
                    if (!Properties(table, "family", "name", "handle", "comment")) { return Deny("observation.fields"); }
                    var key = table.GetProperty("family").GetString() + " " + table.GetProperty("name").GetString();
                    var next = key switch
                    {
                        "inet nergal_filter" => 0,
                        "inet nergal_nat" when expectNat => 1,
                        "bridge nergal_bridge" when expectBridge => 2,
                        "inet nergal_aux" when expectAuxiliary => 3,
                        _ => -1,
                    };
                    if (next < 0 || next <= rank || (rank == -1 && next != 0) || groups.ContainsKey(key)) { return Deny("observation.scope"); }
                    rank = next; active = new JsonArray(); groups.Add(key, active);
                }
                if (active is null) { return Deny("observation.replacementEcho"); }
                active.Add(JsonNode.Parse(item.GetRawText()));
            }
            if (!groups.ContainsKey("inet nergal_filter") || groups.ContainsKey("inet nergal_nat") != expectNat ||
                groups.ContainsKey("bridge nergal_bridge") != expectBridge || groups.ContainsKey("inet nergal_aux") != expectAuxiliary) { return Deny("observation.scope"); }
            string Snapshot(string key) => new JsonObject { ["nftables"] = groups[key] }.ToJsonString();
            var primary = ParseReplacementEcho(Snapshot("inet nergal_filter"));
            if (!primary.IsSuccess || primary.Observation!.Identity != expectedIdentity) { return Deny("observation.identity"); }
            var nat = expectNat ? NftNatTableObservation.ParseReplacementEcho(Snapshot("inet nergal_nat")).Observation : null;
            var bridge = expectBridge ? NftBridgeTableObservation.ParseReplacementEcho(Snapshot("bridge nergal_bridge")).Observation : null;
            var auxiliary = expectAuxiliary ? NftAuxiliaryTableObservation.ParseReplacementEcho(Snapshot("inet nergal_aux")) : null;
            if ((expectNat && nat is null) || (expectBridge && bridge is null) || (expectAuxiliary && auxiliary is null)) { return Deny("observation.auxiliary"); }
            return new(Combine(primary.Observation, nat, bridge, auxiliary), null);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException)
        { return Deny("observation.invalidJson"); }
    }

    private enum EchoMode { None, Enrollment, Replacement }

    private static NftObservationResult ParseNative(string json, EchoMode mode)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(json) > 65536)
            {
                return Deny("observation.tooLarge");
            }

            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (HasDuplicateProperties(document.RootElement))
            {
                return Deny("observation.duplicateProperty");
            }

            var root = document.RootElement;
            if (!Properties(root, "nftables") || root.GetProperty("nftables").ValueKind != JsonValueKind.Array)
            {
                return Deny("observation.shape");
            }

            var items = root.GetProperty("nftables").EnumerateArray().ToArray();
            JsonElement table, chain;
            int chainStartIndex;
            if (mode == EchoMode.Enrollment)
            {
                if (items.Length != 2 || !Properties(items[0], "create") || !Properties(items[1], "add") ||
                    !Properties(items[0].GetProperty("create"), "table") || !Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.createEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
                chainStartIndex = 1;
            }
            else if (mode == EchoMode.Replacement)
            {
                if (items.Length < 2 || !Properties(items[0], "create") || !Properties(items[1], "add") ||
                    !Properties(items[0].GetProperty("create"), "table") || !Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.replacementEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
                chainStartIndex = 1;
            }
            else
            {
                if (items.Length < 3 || !Properties(items[0], "metainfo") || !Properties(items[1], "table") || !Properties(items[2], "chain"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                var meta = items[0].GetProperty("metainfo");
                if (!Properties(meta, "version", "release_name", "json_schema_version") ||
                    meta.GetProperty("version").ValueKind != JsonValueKind.String || meta.GetProperty("release_name").ValueKind != JsonValueKind.String ||
                    meta.GetProperty("json_schema_version").ValueKind != JsonValueKind.Number ||
                    !meta.GetProperty("json_schema_version").TryGetInt32(out var version) || version != 1)
                {
                    return Deny("observation.schema");
                }

                table = items[1].GetProperty("table");
                chain = items[2].GetProperty("chain");
                chainStartIndex = 2;
            }

            if (!Properties(table, "family", "name", "handle", "comment") ||
                !Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
            {
                return Deny("observation.fields");
            }

            if (table.GetProperty("family").GetString() != "inet" || table.GetProperty("name").GetString() != NftFilterCompiler.TableName ||
                chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
                chain.GetProperty("name").GetString() != "input" || chain.GetProperty("type").GetString() != "filter" ||
                chain.GetProperty("hook").GetString() != "input" || chain.GetProperty("prio").ValueKind != JsonValueKind.Number ||
                !chain.GetProperty("prio").TryGetInt32(out var priority) || priority != 0)
            {
                return Deny("observation.scope");
            }

            if (table.GetProperty("handle").ValueKind != JsonValueKind.Number || !table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0 ||
                chain.GetProperty("handle").ValueKind != JsonValueKind.Number || !chain.GetProperty("handle").TryGetUInt64(out var inputHandle) || inputHandle == 0)
            {
                return Deny("observation.handle");
            }

            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null)
            {
                return Deny("observation.identity");
            }

            if (!TryParseVerdict(chain.GetProperty("policy").GetString(), out var inputVerdict) ||
                (mode == EchoMode.Enrollment && inputVerdict != FilterVerdict.Accept))
            {
                return Deny("observation.policy");
            }

            var handles = new HashSet<ulong> { inputHandle };
            ulong forwardHandle = 0;
            ulong outputHandle = 0;
            var forwardVerdict = FilterVerdict.Drop;
            var outputVerdict = FilterVerdict.Drop;
            var isSchema2 = false;
            var ruleStartIndex = chainStartIndex + 1;

            if (mode != EchoMode.Enrollment && ruleStartIndex < items.Length && IsChainItem(items[ruleStartIndex], mode, out _))
            {
                if (ruleStartIndex + 1 >= items.Length)
                {
                    return Deny("observation.unsupportedObjects");
                }

                if (!TryParseAdditionalChain(items[ruleStartIndex], "forward", mode, handles, out forwardHandle, out forwardVerdict, out var fwdError))
                {
                    return Deny(fwdError!);
                }

                if (!TryParseAdditionalChain(items[ruleStartIndex + 1], "output", mode, handles, out outputHandle, out outputVerdict, out var outError))
                {
                    return Deny(outError!);
                }

                isSchema2 = true;
                ruleStartIndex += 2;
            }

            ulong rpHandle = 0;
            var rpVerdict = FilterVerdict.Accept;
            if (isSchema2 && ruleStartIndex < items.Length && IsChainItem(items[ruleStartIndex], mode, out var rawChain))
            {
                if (!TryParseRawChain(rawChain, handles, out rpHandle, out rpVerdict)) { return Deny("observation.rpfilter"); }
                ruleStartIndex++;
            }
            var rpRules = new List<RpFilterRule?>();
            var rpRuleHandles = new List<ulong>();
            int? mss = null;
            ulong mssHandle = 0;
            var sawRpRules = false;
            var sets = new List<ObservedRateLimitSet>();
            if (isSchema2)
            {
                while (ruleStartIndex < items.Length && IsSetItem(items[ruleStartIndex], mode, out var setElement))
                {
                    if (!TryParseRateLimitSet(setElement, sets.Count, mode, handles, out var parsedSet, out var setError))
                    {
                        return Deny(setError!);
                    }

                    sets.Add(parsedSet!);
                    ruleStartIndex++;
                }
            }

            var rules = new List<(ulong Handle, FilterRule Rule)>();
            var lastChain = FilterChainKind.Input;
            var nextSetIndex = 0;
            for (var index = ruleStartIndex; index < items.Length; index++)
            {
                JsonElement rule;
                if (mode == EchoMode.Replacement)
                {
                    if (!Properties(items[index], "add") || !Properties(items[index].GetProperty("add"), "rule"))
                    {
                        return Deny("observation.replacementEcho");
                    }

                    rule = items[index].GetProperty("add").GetProperty("rule");
                }
                else
                {
                    if (!Properties(items[index], "rule")) { return Deny("observation.unsupportedObjects"); }
                    rule = items[index].GetProperty("rule");
                }

                if (!Properties(rule, "family", "table", "chain", "handle", "expr")) { return Deny("observation.unsupportedObjects"); }
                if (rule.GetProperty("family").GetString() != "inet" || rule.GetProperty("table").GetString() != NftFilterCompiler.TableName)
                {
                    return Deny("observation.scope");
                }

                var ruleChainName = rule.GetProperty("chain").GetString();
                if (isSchema2 && ruleChainName == "rpfilter")
                {
                    if (rpHandle == 0 || !rule.GetProperty("handle").TryGetUInt64(out var rawHandle) || rawHandle == 0 || !handles.Add(rawHandle))
                    { return Deny("observation.rpfilter"); }
                    var rawRule = ParseRpFilterRule(rule.GetProperty("expr"));
                    if (rawRule is null) { return Deny("observation.rpfilter"); }
                    sawRpRules = true;
                    rpRules.Add(rawRule);
                    rpRuleHandles.Add(rawHandle);
                    continue;
                }
                if (sawRpRules) { return Deny("observation.scope"); }
                if (isSchema2 && ruleChainName == "forward" && TryParseMss(rule.GetProperty("expr"), out var parsedMss))
                {
                    if (mss is not null || lastChain > FilterChainKind.Forward || rules.Any(e => e.Rule.Chain == FilterChainKind.Forward) ||
                        !rule.GetProperty("handle").TryGetUInt64(out mssHandle) || mssHandle == 0 || !handles.Add(mssHandle))
                    { return Deny("observation.mss"); }
                    mss = parsedMss;
                    lastChain = FilterChainKind.Forward;
                    continue;
                }
                if (!isSchema2)
                {
                    if (ruleChainName != "input") { return Deny("observation.scope"); }
                    if (!rule.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle))
                    { return Deny("observation.handle"); }
                    var parsed = ParseSchema1Rule(rule.GetProperty("expr"));
                    if (parsed is null) { return Deny("observation.rule"); }
                    rules.Add((handle, parsed));
                }
                else
                {
                    FilterChainKind? chainKind = ruleChainName switch
                    {
                        "input" => FilterChainKind.Input,
                        "forward" => FilterChainKind.Forward,
                        "output" => FilterChainKind.Output,
                        _ => null,
                    };
                    if (chainKind is null || chainKind.Value < lastChain) { return Deny("observation.scope"); }
                    lastChain = chainKind.Value;
                    if (!rule.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle))
                    { return Deny("observation.handle"); }
                    var parsed = ParseSchema2Rule(rule.GetProperty("expr"), chainKind.Value, sets, ref nextSetIndex);
                    if (parsed is null) { return Deny("observation.rule"); }
                    rules.Add((handle, parsed));
                }
            }

            if (nextSetIndex != sets.Count)
            {
                return Deny("observation.unsupportedObjects");
            }

            var policy = isSchema2
                ? new FilterPolicy(2, inputVerdict, forwardVerdict, outputVerdict, rules.Select(entry => entry.Rule), rpHandle == 0 ? null : new(rpVerdict, rpRules), mss)
                : new FilterPolicy(1, inputVerdict, rules.Select(entry => entry.Rule));
            return new(new(identity, tableHandle, inputHandle, forwardHandle, outputHandle, policy, rules, sets, rpHandle, rpRuleHandles, mssHandle), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static bool IsSetItem(JsonElement item, EchoMode mode, out JsonElement set)
    {
        if (mode == EchoMode.Replacement)
        {
            if (Properties(item, "add") && Properties(item.GetProperty("add"), "set"))
            {
                set = item.GetProperty("add").GetProperty("set");
                return true;
            }
        }
        else if (Properties(item, "set"))
        {
            set = item.GetProperty("set");
            return true;
        }

        set = default;
        return false;
    }

    private static bool TryParseRateLimitSet(
        JsonElement set,
        int expectedIndex,
        EchoMode mode,
        HashSet<ulong> handles,
        out ObservedRateLimitSet? parsed,
        out string? errorCode)
    {
        parsed = null;
        if (set.ValueKind != JsonValueKind.Object)
        {
            errorCode = "observation.fields";
            return false;
        }

        var required = new HashSet<string>(["family", "name", "table", "type", "handle", "size", "flags"], StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in set.EnumerateObject())
        {
            if (property.Name is "count" or "elem")
            {
                if (mode != EchoMode.None)
                {
                    errorCode = "observation.fields";
                    return false;
                }

                if (property.Name == "count" && (property.Value.ValueKind != JsonValueKind.Number || !property.Value.TryGetUInt64(out _)))
                {
                    errorCode = "observation.fields";
                    return false;
                }

                if (property.Name == "elem" && property.Value.ValueKind != JsonValueKind.Array)
                {
                    errorCode = "observation.fields";
                    return false;
                }

                continue;
            }

            if (!required.Contains(property.Name) || !seen.Add(property.Name))
            {
                errorCode = "observation.fields";
                return false;
            }
        }

        if (seen.Count != required.Count)
        {
            errorCode = "observation.fields";
            return false;
        }

        var expectedName = "nergal_rl_" + expectedIndex.ToString(CultureInfo.InvariantCulture);
        if (set.GetProperty("family").GetString() != "inet" ||
            set.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
            set.GetProperty("name").GetString() != expectedName ||
            set.GetProperty("size").ValueKind != JsonValueKind.Number ||
            !set.GetProperty("size").TryGetInt32(out var size) ||
            size != 65535)
        {
            errorCode = "observation.scope";
            return false;
        }

        IpFamily? setFamily = set.GetProperty("type").GetString() switch
        {
            "ipv4_addr" => IpFamily.IPv4,
            "ipv6_addr" => IpFamily.IPv6,
            _ => null,
        };
        if (setFamily is null)
        {
            errorCode = "observation.scope";
            return false;
        }

        var flags = set.GetProperty("flags");
        if (flags.ValueKind != JsonValueKind.Array)
        {
            errorCode = "observation.scope";
            return false;
        }

        var flagTokens = flags.EnumerateArray().Select(f => f.ValueKind == JsonValueKind.String ? f.GetString() : null).ToArray();
        if (!flagTokens.SequenceEqual(["timeout", "dynamic"]))
        {
            errorCode = "observation.scope";
            return false;
        }

        if (set.GetProperty("handle").ValueKind != JsonValueKind.Number ||
            !set.GetProperty("handle").TryGetUInt64(out var setHandle) ||
            setHandle == 0 || !handles.Add(setHandle))
        {
            errorCode = "observation.handle";
            return false;
        }

        parsed = new(expectedName, setHandle, setFamily.Value);
        errorCode = null;
        return true;
    }

    private static bool IsChainItem(JsonElement item, EchoMode mode, out JsonElement chain)
    {
        if (mode == EchoMode.Replacement)
        {
            if (Properties(item, "add") && Properties(item.GetProperty("add"), "chain"))
            {
                chain = item.GetProperty("add").GetProperty("chain");
                return true;
            }
        }
        else if (Properties(item, "chain"))
        {
            chain = item.GetProperty("chain");
            return true;
        }

        chain = default;
        return false;
    }

    private static bool TryParseAdditionalChain(
        JsonElement item,
        string expectedName,
        EchoMode mode,
        HashSet<ulong> handles,
        out ulong handle,
        out FilterVerdict verdict,
        out string? errorCode)
    {
        handle = 0;
        verdict = FilterVerdict.Drop;
        if (!IsChainItem(item, mode, out var chain))
        {
            errorCode = mode == EchoMode.Replacement ? "observation.replacementEcho" : "observation.unsupportedObjects";
            return false;
        }

        if (!Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
        {
            errorCode = "observation.fields";
            return false;
        }

        if (chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
            chain.GetProperty("name").GetString() != expectedName || chain.GetProperty("type").GetString() != "filter" ||
            chain.GetProperty("hook").GetString() != expectedName || chain.GetProperty("prio").ValueKind != JsonValueKind.Number ||
            !chain.GetProperty("prio").TryGetInt32(out var priority) || priority != 0)
        {
            errorCode = "observation.scope";
            return false;
        }

        if (chain.GetProperty("handle").ValueKind != JsonValueKind.Number || !chain.GetProperty("handle").TryGetUInt64(out handle) ||
            handle == 0 || !handles.Add(handle))
        {
            errorCode = "observation.handle";
            return false;
        }

        if (!TryParseVerdict(chain.GetProperty("policy").GetString(), out verdict))
        {
            errorCode = "observation.policy";
            return false;
        }

        errorCode = null;
        return true;
    }

    private static bool TryParseVerdict(string? value, out FilterVerdict verdict)
    {
        if (value == "accept")
        {
            verdict = FilterVerdict.Accept;
            return true;
        }

        if (value == "drop")
        {
            verdict = FilterVerdict.Drop;
            return true;
        }

        verdict = FilterVerdict.Drop;
        return false;
    }

    private static FilterRule? ParseSchema1Rule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 5)
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        var accept = Properties(terminal, "accept");
        if ((!accept && !Properties(terminal, "drop")) ||
            terminal.GetProperty(accept ? "accept" : "drop").ValueKind != JsonValueKind.Null)
        {
            return null;
        }

        IpFamily? family = null;
        NetworkPrefix? source = null;
        NetworkPrefix? destination = null;
        var protocol = FilterProtocol.Any;
        int? destinationPort = null;
        var hasNfproto = false;
        var hasL4Proto = false;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (!Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!Properties(match, "op", "left", "right") || match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() != "==") { return null; }
            var left = match.GetProperty("left");
            var right = match.GetProperty("right");

            if (Properties(left, "meta") && Properties(left.GetProperty("meta"), "key"))
            {
                var keyElement = left.GetProperty("meta").GetProperty("key");
                if (keyElement.ValueKind != JsonValueKind.String) { return null; }
                var key = keyElement.GetString();
                if (key == "nfproto")
                {
                    if (stage >= 0 || right.ValueKind != JsonValueKind.String) { return null; }
                    var parsedFamily = right.GetString() switch
                    {
                        "ipv4" => IpFamily.IPv4,
                        "ipv6" => IpFamily.IPv6,
                        _ => (IpFamily?)null,
                    };
                    if (parsedFamily is null) { return null; }
                    family = parsedFamily;
                    hasNfproto = true;
                    stage = 0;
                    continue;
                }

                if (key == "l4proto")
                {
                    if (stage >= 3 || right.ValueKind != JsonValueKind.String) { return null; }
                    (FilterProtocol Parsed, IpFamily? ImpliedFamily)? l4 = right.GetString() switch
                    {
                        "tcp" => (FilterProtocol.Tcp, null),
                        "udp" => (FilterProtocol.Udp, null),
                        "icmp" => (FilterProtocol.Icmp, IpFamily.IPv4),
                        "ipv6-icmp" => (FilterProtocol.IcmpV6, IpFamily.IPv6),
                        _ => null,
                    };
                    if (l4 is null) { return null; }
                    if (l4.Value.ImpliedFamily is { } required)
                    {
                        if (family is { } existing && existing != required) { return null; }
                        family = required;
                    }

                    protocol = l4.Value.Parsed;
                    hasL4Proto = true;
                    stage = 3;
                    continue;
                }

                return null;
            }

            if (Properties(left, "payload") && Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var protocolElement = payload.GetProperty("protocol");
                var fieldElement = payload.GetProperty("field");
                if (protocolElement.ValueKind != JsonValueKind.String || fieldElement.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                var payloadProtocol = protocolElement.GetString();
                var field = fieldElement.GetString();
                if (field is "saddr" or "daddr")
                {
                    var nextStage = field == "saddr" ? 1 : 2;
                    if (stage >= nextStage || payloadProtocol is not ("ip" or "ip6")) { return null; }
                    var exprFamily = payloadProtocol == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                    if (family is { } existing && existing != exprFamily) { return null; }
                    var prefix = ParseNetworkPrefix(right, exprFamily);
                    if (prefix is null) { return null; }
                    family = exprFamily;
                    if (nextStage == 1) { source = prefix; } else { destination = prefix; }
                    stage = nextStage;
                    continue;
                }

                if (field == "dport")
                {
                    if (stage >= 4 || payloadProtocol is not ("tcp" or "udp") ||
                        right.ValueKind != JsonValueKind.Number || !right.TryGetInt32(out var port) ||
                        port is < 1 or > 65535)
                    {
                        return null;
                    }

                    protocol = payloadProtocol == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    destinationPort = port;
                    stage = 4;
                    continue;
                }
            }

            return null;
        }

        if (family is not { } resolvedFamily)
        {
            return null;
        }

        var expectNfproto = source is null && destination is null &&
            protocol is FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp;
        var expectL4Proto = protocol != FilterProtocol.Any && !destinationPort.HasValue;
        if (hasNfproto != expectNfproto || hasL4Proto != expectL4Proto)
        {
            return null;
        }

        if ((protocol == FilterProtocol.Icmp && resolvedFamily != IpFamily.IPv4) ||
            (protocol == FilterProtocol.IcmpV6 && resolvedFamily != IpFamily.IPv6))
        {
            return null;
        }

        return new(resolvedFamily, protocol, accept ? FilterVerdict.Accept : FilterVerdict.Drop, source, destination, destinationPort);
    }

    private static FilterRule? ParseSchema2Rule(
        JsonElement expressions,
        FilterChainKind chain,
        IReadOnlyList<ObservedRateLimitSet> sets,
        ref int nextSetIndex)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 12)
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        var accept = Properties(terminal, "accept") && terminal.GetProperty("accept").ValueKind == JsonValueKind.Null;
        var drop = Properties(terminal, "drop") && terminal.GetProperty("drop").ValueKind == JsonValueKind.Null;
        var reject = Properties(terminal, "reject") && Properties(terminal.GetProperty("reject"), "type", "expr") &&
            terminal.GetProperty("reject").GetProperty("type").GetString() == "icmpx" &&
            terminal.GetProperty("reject").GetProperty("expr").GetString() == "admin-prohibited";
        if (!accept && !drop && !reject) { return null; }
        var negateInput = false;
        var negateOutput = false;
        var negateSource = false;
        var negateDestination = false;
        var negateMac = false;
        MacAddress? sourceMac = null;
        IReadOnlyList<MacAddress>? sourceMacs = null;

        IpFamily? family = null;
        string? inputInterface = null;
        string? outputInterface = null;
        NetworkPrefix? source = null;
        NetworkPrefix? destination = null;
        IReadOnlyList<NetworkPrefix>? sourcePrefixes = null;
        IReadOnlyList<NetworkPrefix>? destinationPrefixes = null;
        var matchOriginalDestinationDnat = false;
        var connectionStates = ConnectionStateFlags.None;
        var protocol = FilterProtocol.Any;
        int? destinationPort = null;
        IReadOnlyList<int>? destinationPorts = null;
        string? icmpType = null;
        PerSourceRateLimit? rateLimit = null;
        var hasNfproto = false;
        var hasL4Proto = false;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (index == count - 2 && Properties(expressions[index], "set"))
            {
                if (stage >= 9 || nextSetIndex >= sets.Count)
                {
                    return null;
                }

                var expectedSet = sets[nextSetIndex];
                var parsedMeter = ParseRateLimitExpression(expressions[index].GetProperty("set"), expectedSet.Name, expectedSet.Family);
                if (parsedMeter is null || (family is { } existingFamily && existingFamily != expectedSet.Family))
                {
                    return null;
                }

                family = expectedSet.Family;
                rateLimit = parsedMeter;
                nextSetIndex++;
                stage = 9;
                continue;
            }

            if (!Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!Properties(match, "op", "left", "right") || match.GetProperty("op").ValueKind != JsonValueKind.String)
            {
                return null;
            }

            var op = match.GetProperty("op").GetString();
            var left = match.GetProperty("left");
            var right = match.GetProperty("right");

            if (op == "in" && Properties(left, "ct") && Properties(left.GetProperty("ct"), "key") &&
                left.GetProperty("ct").GetProperty("key").ValueKind == JsonValueKind.String)
            {
                var ctKey = left.GetProperty("ct").GetProperty("key").GetString();
                if (ctKey == "status")
                {
                    if (stage >= 5 || right.ValueKind != JsonValueKind.String || right.GetString() != "dnat") { return null; }
                    matchOriginalDestinationDnat = true;
                    stage = 5;
                    continue;
                }

                if (ctKey == "state")
                {
                    if (stage >= 6) { return null; }
                    var parsedStates = ParseConnectionStates(right);
                    if (parsedStates == ConnectionStateFlags.None) { return null; }
                    connectionStates = parsedStates;
                    stage = 6;
                    continue;
                }

                return null;
            }

            if (op is not ("==" or "!=")) { return null; }

            if (Properties(left, "meta") && Properties(left.GetProperty("meta"), "key"))
            {
                var keyElement = left.GetProperty("meta").GetProperty("key");
                if (keyElement.ValueKind != JsonValueKind.String) { return null; }
                var key = keyElement.GetString();

                if (key == "nfproto")
                {
                    if (op != "==" || stage >= 0 || right.ValueKind != JsonValueKind.String) { return null; }
                    var parsedFamily = right.GetString() switch
                    {
                        "ipv4" => IpFamily.IPv4,
                        "ipv6" => IpFamily.IPv6,
                        _ => (IpFamily?)null,
                    };
                    if (parsedFamily is null) { return null; }
                    family = parsedFamily;
                    hasNfproto = true;
                    stage = 0;
                    continue;
                }

                if (key == "iifname")
                {
                    if (stage >= 1 || chain == FilterChainKind.Output || right.ValueKind != JsonValueKind.String) { return null; }
                    var iface = right.GetString();
                    if (!FilterPolicyValidation.IsValidInterfaceName(iface)) { return null; }
                    inputInterface = iface;
                    negateInput = op == "!=";
                    stage = 1;
                    continue;
                }

                if (key == "oifname")
                {
                    if (stage >= 2 || chain == FilterChainKind.Input || right.ValueKind != JsonValueKind.String) { return null; }
                    var iface = right.GetString();
                    if (!FilterPolicyValidation.IsValidInterfaceName(iface)) { return null; }
                    outputInterface = iface;
                    negateOutput = op == "!=";
                    stage = 2;
                    continue;
                }

                if (key == "l4proto")
                {
                    if (op != "==" || stage >= 7 || right.ValueKind != JsonValueKind.String) { return null; }
                    (FilterProtocol Parsed, IpFamily? ImpliedFamily)? l4 = right.GetString() switch
                    {
                        "tcp" => (FilterProtocol.Tcp, null),
                        "udp" => (FilterProtocol.Udp, null),
                        "icmp" => (FilterProtocol.Icmp, IpFamily.IPv4),
                        "ipv6-icmp" => (FilterProtocol.IcmpV6, IpFamily.IPv6),
                        _ => null,
                    };
                    if (l4 is null) { return null; }
                    if (l4.Value.ImpliedFamily is { } required)
                    {
                        if (family is { } existing && existing != required) { return null; }
                        family = required;
                    }

                    protocol = l4.Value.Parsed;
                    hasL4Proto = true;
                    stage = 7;
                    continue;
                }

                return null;
            }

            if (Properties(left, "payload") && Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var protocolElement = payload.GetProperty("protocol");
                var fieldElement = payload.GetProperty("field");
                if (protocolElement.ValueKind != JsonValueKind.String || fieldElement.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                var payloadProtocol = protocolElement.GetString();
                var field = fieldElement.GetString();
                if (payloadProtocol == "ether" && field == "saddr")
                {
                    if (stage >= 3 || sourceMac is not null || sourceMacs is not null || chain == FilterChainKind.Output) { return null; }
                    if (right.ValueKind == JsonValueKind.String)
                    { if (!MacAddress.TryParse(right.GetString(), out sourceMac)) { return null; } }
                    else if (Properties(right, "set") && right.GetProperty("set").ValueKind == JsonValueKind.Array)
                    {
                        var macs = new List<MacAddress>();
                        foreach (var entry in right.GetProperty("set").EnumerateArray())
                        {
                            if (entry.ValueKind != JsonValueKind.String || !MacAddress.TryParse(entry.GetString(), out var mac)) { return null; }
                            macs.Add(mac!);
                        }
                        if (macs.Count is < 2 or > 64 || macs.Distinct().Count() != macs.Count) { return null; }
                        sourceMacs = Array.AsReadOnly(macs.OrderBy(m => m.Value, StringComparer.Ordinal).ToArray());
                    }
                    else { return null; }
                    negateMac = op == "!=";
                    stage = 2;
                    continue;
                }
                if (field is "saddr" or "daddr")
                {
                    var nextStage = field == "saddr" ? 3 : 4;
                    if (stage >= nextStage || payloadProtocol is not ("ip" or "ip6")) { return null; }
                    var exprFamily = payloadProtocol == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                    if (family is { } existing && existing != exprFamily) { return null; }
                    if (right.ValueKind == JsonValueKind.Object && Properties(right, "set"))
                    {
                        var prefixSet = ParseNetworkPrefixSet(right.GetProperty("set"), exprFamily);
                        if (prefixSet is null) { return null; }
                        family = exprFamily;
                        if (nextStage == 3) { sourcePrefixes = prefixSet; } else { destinationPrefixes = prefixSet; }
                    }
                    else
                    {
                        var prefix = ParseNetworkPrefix(right, exprFamily);
                        if (prefix is null) { return null; }
                        family = exprFamily;
                        if (nextStage == 3) { source = prefix; } else { destination = prefix; }
                    }

                    if (nextStage == 3) { negateSource = op == "!="; } else { negateDestination = op == "!="; }
                    stage = nextStage;
                    continue;
                }

                if (field == "dport")
                {
                    if (op != "==" || stage >= 7 || payloadProtocol is not ("tcp" or "udp"))
                    {
                        return null;
                    }

                    if (right.ValueKind == JsonValueKind.Object && Properties(right, "set"))
                    {
                        var portSet = ParsePortSet(right.GetProperty("set"));
                        if (portSet is null) { return null; }
                        protocol = payloadProtocol == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                        destinationPorts = portSet;
                        stage = 8;
                        continue;
                    }

                    if (right.ValueKind != JsonValueKind.Number || !right.TryGetInt32(out var port) ||
                        port is < 1 or > 65535)
                    {
                        return null;
                    }

                    protocol = payloadProtocol == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    destinationPort = port;
                    stage = 8;
                    continue;
                }

                if (field == "type" && payloadProtocol is "icmp" or "icmpv6")
                {
                    if (op != "==" || stage >= 7 || right.ValueKind != JsonValueKind.String) { return null; }
                    var exprFamily = payloadProtocol == "icmp" ? IpFamily.IPv4 : IpFamily.IPv6;
                    var exprProtocol = payloadProtocol == "icmp" ? FilterProtocol.Icmp : FilterProtocol.IcmpV6;
                    if (family is { } existing && existing != exprFamily) { return null; }
                    var typeName = right.GetString();
                    if (!FilterIcmpTypes.IsSupported(exprProtocol, typeName)) { return null; }
                    family = exprFamily;
                    protocol = exprProtocol;
                    icmpType = typeName;
                    stage = 8;
                    continue;
                }
            }

            return null;
        }

        if (family is not { } resolvedFamily)
        {
            return null;
        }

        var expectNfproto = source is null && destination is null &&
            sourcePrefixes is null && destinationPrefixes is null &&
            icmpType is null && rateLimit is null &&
            protocol is FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp;
        var expectL4Proto = protocol != FilterProtocol.Any && !destinationPort.HasValue && destinationPorts is null && icmpType is null;
        if (hasNfproto != expectNfproto || hasL4Proto != expectL4Proto)
        {
            return null;
        }

        if ((protocol == FilterProtocol.Icmp && resolvedFamily != IpFamily.IPv4) ||
            (protocol == FilterProtocol.IcmpV6 && resolvedFamily != IpFamily.IPv6))
        {
            return null;
        }

        return new(resolvedFamily, protocol, accept ? FilterVerdict.Accept : reject ? FilterVerdict.Reject : FilterVerdict.Drop,
            source, destination, destinationPort, chain, inputInterface, outputInterface, connectionStates, icmpType, rateLimit,
            matchOriginalDestinationDnat, sourcePrefixes, destinationPrefixes, destinationPorts,
            NegateInputInterface: negateInput, NegateOutputInterface: negateOutput, NegateSource: negateSource,
            NegateDestination: negateDestination, SourceMac: sourceMac, SourceMacs: sourceMacs, NegateSourceMac: negateMac);
    }

    private static IReadOnlyList<NetworkPrefix>? ParseNetworkPrefixSet(JsonElement setArray, IpFamily family)
    {
        if (setArray.ValueKind != JsonValueKind.Array || setArray.GetArrayLength() is < 2 or > 64)
        {
            return null;
        }

        var items = new List<NetworkPrefix>(setArray.GetArrayLength());
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in setArray.EnumerateArray())
        {
            var parsed = ParseNetworkPrefix(entry, family);
            if (parsed is null || !seen.Add(parsed.Value))
            {
                return null;
            }

            items.Add(parsed);
        }

        items.Sort((a, b) => string.CompareOrdinal(a.Value, b.Value));
        return Array.AsReadOnly(items.ToArray());
    }

    private static IReadOnlyList<int>? ParsePortSet(JsonElement setArray)
    {
        if (setArray.ValueKind != JsonValueKind.Array || setArray.GetArrayLength() is < 2 or > 64)
        {
            return null;
        }

        var items = new List<int>(setArray.GetArrayLength());
        var seen = new HashSet<int>();
        foreach (var entry in setArray.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Number || !entry.TryGetInt32(out var port) ||
                port is < 1 or > 65535 || !seen.Add(port))
            {
                return null;
            }

            items.Add(port);
        }

        items.Sort();
        return Array.AsReadOnly(items.ToArray());
    }

    private static string PrefixOrSetProjection(NetworkPrefix? scalar, IReadOnlyList<NetworkPrefix>? set)
    {
        if (scalar is not null)
        {
            return scalar.Value;
        }

        if (set is { Count: > 0 })
        {
            return "{" + string.Join(',', set.Select(p => p.Value).Order(StringComparer.Ordinal)) + "}";
        }

        return "-";
    }

    private static string PortOrSetProjection(int? scalar, IReadOnlyList<int>? set)
    {
        if (scalar.HasValue)
        {
            return scalar.Value.ToString(CultureInfo.InvariantCulture);
        }

        if (set is { Count: > 0 })
        {
            return "{" + string.Join(',', set.Order().Select(p => p.ToString(CultureInfo.InvariantCulture))) + "}";
        }

        return "-";
    }

    private static PerSourceRateLimit? ParseRateLimitExpression(JsonElement setExpr, string expectedSetName, IpFamily expectedFamily)
    {
        if (!Properties(setExpr, "op", "elem", "set", "stmt") ||
            setExpr.GetProperty("op").ValueKind != JsonValueKind.String ||
            setExpr.GetProperty("op").GetString() != "add" ||
            setExpr.GetProperty("set").ValueKind != JsonValueKind.String ||
            setExpr.GetProperty("set").GetString() != "@" + expectedSetName)
        {
            return null;
        }

        var outerElem = setExpr.GetProperty("elem");
        if (!Properties(outerElem, "elem"))
        {
            return null;
        }

        var innerElem = outerElem.GetProperty("elem");
        if (!Properties(innerElem, "val", "timeout") ||
            innerElem.GetProperty("timeout").ValueKind != JsonValueKind.Number ||
            !innerElem.GetProperty("timeout").TryGetInt32(out var timeout) ||
            timeout is < 1 or > 86_400)
        {
            return null;
        }

        var val = innerElem.GetProperty("val");
        if (!Properties(val, "payload") || !Properties(val.GetProperty("payload"), "protocol", "field"))
        {
            return null;
        }

        var payload = val.GetProperty("payload");
        var expectedPayloadProto = expectedFamily == IpFamily.IPv4 ? "ip" : "ip6";
        if (payload.GetProperty("protocol").ValueKind != JsonValueKind.String ||
            payload.GetProperty("protocol").GetString() != expectedPayloadProto ||
            payload.GetProperty("field").ValueKind != JsonValueKind.String ||
            payload.GetProperty("field").GetString() is not ("saddr" or "daddr"))
        {
            return null;
        }

        var stmt = setExpr.GetProperty("stmt");
        if (stmt.ValueKind != JsonValueKind.Array || stmt.GetArrayLength() != 1 ||
            !Properties(stmt[0], "limit"))
        {
            return null;
        }

        var limit = stmt[0].GetProperty("limit");
        if (!Properties(limit, "rate", "burst", "per") ||
            limit.GetProperty("rate").ValueKind != JsonValueKind.Number ||
            !limit.GetProperty("rate").TryGetInt32(out var rate) ||
            rate is < 1 or > 1_000_000 ||
            limit.GetProperty("burst").ValueKind != JsonValueKind.Number ||
            !limit.GetProperty("burst").TryGetInt32(out var burst) ||
            burst is < 1 or > 10_000 ||
            limit.GetProperty("per").ValueKind != JsonValueKind.String)
        {
            return null;
        }

        RateLimitTimeUnit? unit = limit.GetProperty("per").GetString() switch
        {
            "second" => RateLimitTimeUnit.Second,
            "minute" => RateLimitTimeUnit.Minute,
            _ => null,
        };
        if (unit is null)
        {
            return null;
        }

        return new(rate, unit.Value, burst, timeout, payload.GetProperty("field").GetString() == "daddr" ? RateLimitKeyKind.DestinationAddress : RateLimitKeyKind.SourceAddress);
    }

    private static ConnectionStateFlags ParseConnectionStates(JsonElement right)
    {
        if (right.ValueKind == JsonValueKind.String)
        {
            return ConnectionStateFromToken(right.GetString(), out _) is { } single ? single : ConnectionStateFlags.None;
        }

        if (right.ValueKind != JsonValueKind.Array || right.GetArrayLength() is < 2 or > 4)
        {
            return ConnectionStateFlags.None;
        }

        var result = ConnectionStateFlags.None;
        var previousRank = -1;
        foreach (var item in right.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                return ConnectionStateFlags.None;
            }

            var flag = ConnectionStateFromToken(item.GetString(), out var rank);
            if (flag is null || rank <= previousRank)
            {
                return ConnectionStateFlags.None;
            }

            previousRank = rank;
            result |= flag.Value;
        }

        return result;
    }

    private static ConnectionStateFlags? ConnectionStateFromToken(string? token, out int rank)
    {
        switch (token)
        {
            case "invalid":
                rank = 0;
                return ConnectionStateFlags.Invalid;
            case "established":
                rank = 1;
                return ConnectionStateFlags.Established;
            case "related":
                rank = 2;
                return ConnectionStateFlags.Related;
            case "new":
                rank = 3;
                return ConnectionStateFlags.New;
            default:
                rank = -1;
                return null;
        }
    }

    private static NetworkPrefix? ParseNetworkPrefix(JsonElement right, IpFamily family)
    {
        var maxPrefixLength = family == IpFamily.IPv4 ? 32 : 128;
        string candidate;
        if (right.ValueKind == JsonValueKind.String)
        {
            var address = right.GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + maxPrefixLength.ToString(CultureInfo.InvariantCulture);
        }
        else if (right.ValueKind == JsonValueKind.Object && Properties(right, "prefix"))
        {
            var prefix = right.GetProperty("prefix");
            if (!Properties(prefix, "addr", "len") ||
                prefix.GetProperty("addr").ValueKind != JsonValueKind.String ||
                prefix.GetProperty("len").ValueKind != JsonValueKind.Number ||
                !prefix.GetProperty("len").TryGetInt32(out var length) ||
                length < 0 || length >= maxPrefixLength)
            {
                return null;
            }

            var address = prefix.GetProperty("addr").GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + length.ToString(CultureInfo.InvariantCulture);
        }
        else
        {
            return null;
        }

        try
        {
            var parsed = new NetworkPrefix(candidate);
            return parsed.Family == family && parsed.Value == candidate ? parsed : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string ProtocolToken(FilterProtocol protocol) => protocol switch
    {
        FilterProtocol.Any => "any",
        FilterProtocol.Tcp => "tcp",
        FilterProtocol.Udp => "udp",
        FilterProtocol.Icmp => "icmp",
        FilterProtocol.IcmpV6 => "ipv6-icmp",
        _ => throw new InvalidOperationException("Unvalidated protocol."),
    };

    private static string ChainToken(FilterChainKind chain) => chain switch
    {
        FilterChainKind.Input => "input",
        FilterChainKind.Forward => "forward",
        FilterChainKind.Output => "output",
        _ => throw new InvalidOperationException("Unvalidated chain."),
    };

    private static string VerdictToken(FilterVerdict verdict) => verdict switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        FilterVerdict.Reject => "reject",
        _ => throw new InvalidOperationException("Unvalidated verdict."),
    };

    private static string ConnectionStateProjection(ConnectionStateFlags states)
    {
        if (states == ConnectionStateFlags.None)
        {
            return "-";
        }

        var parts = new List<string>(4);
        if ((states & ConnectionStateFlags.Invalid) != 0)
        {
            parts.Add("invalid");
        }

        if ((states & ConnectionStateFlags.Established) != 0)
        {
            parts.Add("established");
        }

        if ((states & ConnectionStateFlags.Related) != 0)
        {
            parts.Add("related");
        }

        if ((states & ConnectionStateFlags.New) != 0)
        {
            parts.Add("new");
        }

        return string.Join(',', parts);
    }

    private static string RateLimitProjection(PerSourceRateLimit? rateLimit)
    {
        if (rateLimit is null)
        {
            return "-";
        }

        var unit = rateLimit.WindowUnit == RateLimitTimeUnit.Second ? "second" : "minute";
        return string.Concat(
            rateLimit.PacketsPerWindow.ToString(CultureInfo.InvariantCulture),
            "/",
            unit,
            "/",
            rateLimit.Burst.ToString(CultureInfo.InvariantCulture),
            "/",
            rateLimit.EntryTimeoutSeconds.ToString(CultureInfo.InvariantCulture),
            "s");
    }

    private static NftObservationResult Deny(string code) => new(null, code);
    private static bool Properties(JsonElement element, params string[] names) => element.ValueKind == JsonValueKind.Object &&
        element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal));
    private static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
            {
                if (HasDuplicateProperties(value))
                {
                    return true;
                }
            }
        }
        return false;
    }
}

/// <summary>Either a complete immutable observation or a stable denial code, without echoing native input.</summary>
public sealed class NftObservationResult
{
    internal NftObservationResult(NftTableObservation? observation, string? errorCode) { Observation = observation; ErrorCode = errorCode; }
    /// <summary>Gets the complete observation, or null on any validation failure.</summary>
    public NftTableObservation? Observation { get; }
    /// <summary>Gets the stable denial code, or null on success.</summary>
    public string? ErrorCode { get; }
    /// <summary>Gets whether the limited observation contract was fully understood.</summary>
    public bool IsSuccess => Observation is not null;
}
