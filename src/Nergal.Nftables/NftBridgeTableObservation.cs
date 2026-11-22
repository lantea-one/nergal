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

/// <summary>Complete native bridge observation, including regular-chain control flow.</summary>
public sealed partial class NftBridgeTableObservation
{
    private NftBridgeTableObservation(NftTableIdentity identity, ulong tableHandle, ulong chainHandle,
        BridgePolicy policy, IReadOnlyList<(string Name, ulong Handle)> chains, IReadOnlyList<(string Chain, ulong Handle, BridgeFilterRule Rule)> rules)
    {
        Identity = identity; TableHandle = tableHandle; ForwardChainHandle = chainHandle; Policy = policy;
        var projection = new StringBuilder(string.Join('\n',
            policy.HasExtendedRules ? "nergal-bridge-observation-v2" : "nergal-bridge-observation-v1", identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture),
            string.Join(' ', chainHandle.ToString(CultureInfo.InvariantCulture), "bridge", NftBridgeCompiler.TableName,
                "forward", "filter", "forward", policy.Priority.ToString(CultureInfo.InvariantCulture), policy.DefaultVerdict == FilterVerdict.Accept ? "accept" : "drop")));
        if (!policy.HasExtendedRules)
        {
            foreach (var (_, handle, rule) in rules)
            {
                projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture)).Append(' ')
                    .Append(rule.InputInterface ?? "-").Append(' ').Append(rule.OutputInterface ?? "-").Append(' ')
                    .Append(rule.EtherType).Append(' ').Append(rule.Verdict == FilterVerdict.Accept ? "accept" : "drop");
            }
        }
        else
        {
            foreach (var (name, handle) in chains) { projection.Append('\n').Append(name).Append(' ').Append(handle.ToString(CultureInfo.InvariantCulture)); }
            foreach (var (name, handle, _) in rules) { projection.Append('\n').Append(name).Append(' ').Append(handle.ToString(CultureInfo.InvariantCulture)); }
            // The canonical compiler includes every matcher/action and preserves rule/chain order.
            projection.Append('\n').Append(NftBridgeCompiler.Compile(policy, identity).Candidate);
        }
        StateDigest = CandidateDigest.FromText(projection.ToString());
    }
    /// <summary>Gets the native owner/resource marker.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the positive base-chain handle.</summary>
    public ulong ForwardChainHandle { get; }
    /// <summary>Gets the reconstructed complete bridge policy.</summary>
    public BridgePolicy Policy { get; }
    /// <summary>Gets a fingerprint binding every native object handle and semantic field.</summary>
    public CandidateDigest StateDigest { get; }
    /// <summary>Parses a complete native bridge listing, rejecting unknown or partial objects.</summary>
    public static NftBridgeObservationResult Parse(string json) => ParseNative(json, false);
    /// <summary>Parses complete handle-bearing bridge creation echo.</summary>
    public static NftBridgeObservationResult ParseReplacementEcho(string json) => ParseNative(json, true);

    private static NftBridgeObservationResult ParseNative(string json, bool echo)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (Encoding.UTF8.GetByteCount(json) > 65536) { return Deny("observation.tooLarge"); }
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (NftJsonHelpers.HasDuplicateProperties(doc.RootElement)) { return Deny("observation.duplicateProperty"); }
            if (!NftJsonHelpers.Properties(doc.RootElement, "nftables") || doc.RootElement.GetProperty("nftables").ValueKind != JsonValueKind.Array) { return Deny("observation.shape"); }
            var items = doc.RootElement.GetProperty("nftables").EnumerateArray().ToArray();
            if (!echo && !NftJsonHelpers.TryReadMetaHeader(items)) { return Deny("observation.schema"); }
            var offset = echo ? 0 : 1;
            if (items.Length < offset + 2) { return Deny("observation.unsupportedObjects"); }
            var table = Unwrap(items[offset], "table", echo, true);
            var baseChain = Unwrap(items[offset + 1], "chain", echo);
            if (!NftJsonHelpers.Properties(table, "family", "name", "handle", "comment") ||
                !NftJsonHelpers.Properties(baseChain, "family", "table", "name", "handle", "type", "hook", "prio", "policy")) { return Deny("observation.fields"); }
            if (table.GetProperty("family").GetString() != "bridge" || table.GetProperty("name").GetString() != NftBridgeCompiler.TableName ||
                !Scope(baseChain) || baseChain.GetProperty("name").GetString() != "forward" || baseChain.GetProperty("type").GetString() != "filter" ||
                baseChain.GetProperty("hook").GetString() != "forward" || !baseChain.GetProperty("prio").TryGetInt32(out var priority) || priority is < -300 or > 300) { return Deny("observation.scope"); }
            if (!table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0 ||
                !baseChain.GetProperty("handle").TryGetUInt64(out var chainHandle) || chainHandle == 0) { return Deny("observation.handle"); }
            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null) { return Deny("observation.identity"); }
            var token = baseChain.GetProperty("policy").GetString();
            if (token is not ("accept" or "drop")) { return Deny("observation.policy"); }
            var chains = new List<(string Name, ulong Handle)> { ("forward", chainHandle) };
            var names = new HashSet<string>(StringComparer.Ordinal) { "forward" };
            var handles = new HashSet<ulong> { chainHandle };
            var index = offset + 2;
            while (index < items.Length && Unwrap(items[index], "chain", echo).ValueKind != JsonValueKind.Undefined)
            {
                var c = Unwrap(items[index++], "chain", echo);
                if (!NftJsonHelpers.Properties(c, "family", "table", "name", "handle") || !Scope(c)) { return Deny("observation.scope"); }
                var name = c.GetProperty("name").GetString();
                if (name is null || !names.Add(name) || names.Count > 33) { return Deny("observation.scope"); }
                if (!c.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle)) { return Deny("observation.handle"); }
                chains.Add((name, handle));
            }
            var rules = new List<(string Chain, ulong Handle, BridgeFilterRule Rule)>();
            var previous = 0;
            for (; index < items.Length; index++)
            {
                var r = Unwrap(items[index], "rule", echo);
                if (!NftJsonHelpers.Properties(r, "family", "table", "chain", "handle", "expr")) { return Deny("observation.unsupportedObjects"); }
                if (!Scope(r)) { return Deny("observation.scope"); }
                var name = r.GetProperty("chain").GetString();
                var rank = chains.FindIndex(c => c.Name == name);
                if (rank < previous || rank < 0) { return Deny("observation.scope"); }
                previous = rank;
                if (!r.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle)) { return Deny("observation.handle"); }
                var rule = ParseRule(r.GetProperty("expr"));
                if (rule is null) { return Deny("observation.rule"); }
                rules.Add((name!, handle, rule));
            }
            var policy = new BridgePolicy(1, token == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop,
                rules.Where(r => r.Chain == "forward").Select(r => r.Rule), priority,
                chains.Skip(1).Select(c => new BridgeSubChain(c.Name, rules.Where(r => r.Chain == c.Name).Select(r => r.Rule))));
            if (!NftBridgeCompiler.Compile(policy).IsSuccess) { return Deny("observation.rule"); }
            return new(new(identity, tableHandle, chainHandle, policy, chains, rules), null);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        { return Deny("observation.invalidJson"); }
    }
    private static JsonElement Unwrap(JsonElement item, string kind, bool echo, bool create = false)
    {
        if (!echo) { return NftJsonHelpers.Properties(item, kind) ? item.GetProperty(kind) : default; }
        var command = create ? "create" : "add";
        return NftJsonHelpers.Properties(item, command) && NftJsonHelpers.Properties(item.GetProperty(command), kind)
            ? item.GetProperty(command).GetProperty(kind) : default;
    }
    private static bool Scope(JsonElement e) => e.GetProperty("family").GetString() == "bridge" && e.GetProperty("table").GetString() == NftBridgeCompiler.TableName;
    private static NftBridgeObservationResult Deny(string code) => new(null, code);
}
