using System.Globalization;
using System.Text;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Immutable native observation of one tagged table and supported ordered input rules; never a claim of authority.</summary>
public sealed class NftTableObservation
{
    private NftTableObservation(NftTableIdentity identity, ulong tableHandle, ulong chainHandle, FilterVerdict defaultVerdict,
        List<(ulong Handle, FilterRule Rule)> rules)
    {
        Identity = identity;
        TableHandle = tableHandle;
        ChainHandle = chainHandle;
        Policy = new(1, defaultVerdict, rules.Select(entry => entry.Rule));
        var projection = new StringBuilder(string.Join('\n', rules.Count == 0 ? "nergal-observation-v1" : "nergal-observation-v2", identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture), chainHandle.ToString(CultureInfo.InvariantCulture),
            "inet", NftFilterCompiler.TableName, "input", "filter", "input", "0",
            defaultVerdict == FilterVerdict.Accept ? "accept" : "drop"));
        foreach (var (handle, rule) in rules)
        {
            projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture))
                .Append(rule.Family == IpFamily.IPv4 ? " ipv4 " : " ipv6 ")
                .Append(rule.Verdict == FilterVerdict.Accept ? "accept" : "drop");
        }
        StateDigest = CandidateDigest.FromText(projection.ToString());
    }

    /// <summary>Gets the observed canonical marker; it must agree with protected expected enrollment.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the positive native chain handle, included in the complete state fingerprint.</summary>
    public ulong ChainHandle { get; }
    /// <summary>Gets the observed unmatched-input decision.</summary>
    public FilterVerdict DefaultVerdict => Policy.DefaultVerdict;
    /// <summary>Gets the immutable policy reconstructed from every recognized input rule in native order.</summary>
    public FilterPolicy Policy { get; }
    /// <summary>Gets the deterministic fingerprint of all recognized enforcement/identity fields.</summary>
    public CandidateDigest StateDigest { get; }

    /// <summary>Parses bounded native JSON without host access, accepting empty chains and explicit family-wide terminal rules.</summary>
    /// <remarks>Unknown objects, fields, duplicate keys and unsupported rule expressions fail closed. The trusted collector must supply a full table snapshot; omitted kernel objects cannot be detected from JSON alone.</remarks>
    /// <exception cref="ArgumentNullException">JSON is null.</exception>
    public static NftObservationResult Parse(string json) => ParseNative(json, createEcho: false);

    /// <summary>Reads the handle-bearing echo of a successful local exclusive create of an empty accept baseline.</summary>
    /// <remarks>Caller must establish successful transaction exit and independently compare a complete listing before binding.</remarks>
    public static NftObservationResult ParseEnrollmentEcho(string json) => ParseNative(json, createEcho: true);

    private static NftObservationResult ParseNative(string json, bool createEcho)
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
            if (createEcho)
            {
                if (items.Length != 2 || !Properties(items[0], "create") || !Properties(items[1], "add") ||
                    !Properties(items[0].GetProperty("create"), "table") || !Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.createEcho");
                }
                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
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
                chain.GetProperty("handle").ValueKind != JsonValueKind.Number || !chain.GetProperty("handle").TryGetUInt64(out var chainHandle) || chainHandle == 0)
            {
                return Deny("observation.handle");
            }

            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null)
            {
                return Deny("observation.identity");
            }

            var verdict = chain.GetProperty("policy").GetString();
            if (verdict is not ("accept" or "drop") || (createEcho && verdict != "accept"))
            {
                return Deny("observation.policy");
            }

            var rules = new List<(ulong Handle, FilterRule Rule)>();
            var handles = new HashSet<ulong> { chainHandle };
            for (var index = 3; index < items.Length; index++)
            {
                if (!Properties(items[index], "rule")) { return Deny("observation.unsupportedObjects"); }
                var rule = items[index].GetProperty("rule");
                if (!Properties(rule, "family", "table", "chain", "handle", "expr")) { return Deny("observation.unsupportedObjects"); }
                if (rule.GetProperty("family").GetString() != "inet" || rule.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
                    rule.GetProperty("chain").GetString() != "input") { return Deny("observation.scope"); }
                if (!rule.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle))
                { return Deny("observation.handle"); }
                var parsed = ParseFamilyRule(rule.GetProperty("expr"));
                if (parsed is null) { return Deny("observation.rule"); }
                rules.Add((handle, parsed));
            }
            return new(new(identity, tableHandle, chainHandle, verdict == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop, rules), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static FilterRule? ParseFamilyRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() != 2 ||
            !Properties(expressions[0], "match")) { return null; }
        var match = expressions[0].GetProperty("match");
        if (!Properties(match, "op", "left", "right") || match.GetProperty("op").GetString() != "==") { return null; }
        var left = match.GetProperty("left");
        if (!Properties(left, "meta") || !Properties(left.GetProperty("meta"), "key") ||
            left.GetProperty("meta").GetProperty("key").GetString() != "nfproto") { return null; }
        var family = match.GetProperty("right").GetString();
        if (family is not ("ipv4" or "ipv6")) { return null; }
        var terminal = expressions[1];
        var accept = Properties(terminal, "accept");
        if ((!accept && !Properties(terminal, "drop")) ||
            terminal.GetProperty(accept ? "accept" : "drop").ValueKind != JsonValueKind.Null) { return null; }
        return new(family == "ipv4" ? IpFamily.IPv4 : IpFamily.IPv6, FilterProtocol.Any,
            accept ? FilterVerdict.Accept : FilterVerdict.Drop);
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
