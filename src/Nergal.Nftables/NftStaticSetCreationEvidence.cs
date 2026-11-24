using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Completes static element evidence only from matching creation handles and an independently verified exact artifact listing.</summary>
/// <remarks>
/// Some nft userspace versions omit IPv6 interval elements from creation echo. This does not permit inferring contents from intent.
/// Callers must collect the supplied complete listings from the trusted kernel under one transaction generation, retain the original
/// creation echo, and use protected expected artifacts. This pure normalization grants no ownership or apply authority.
/// </remarks>
public static class NftStaticSetCreationEvidence
{
    /// <summary>Retains creation-proven set handles and lookups, verifying complete contents against the exact expected artifact before completing omitted elements.</summary>
    /// <exception cref="ArgumentException">Creation definitions, emitted elements, complete listings or the expected artifact disagree.</exception>
    public static string Complete(string echo, IEnumerable<string> completeListings, string expectedArtifact)
    {
        ArgumentNullException.ThrowIfNull(completeListings);
        ArgumentNullException.ThrowIfNull(expectedArtifact);
        try { return CompleteCore(echo, completeListings, expectedArtifact); }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw NftStaticSetSnapshot.Invalid(); }
    }

    private static string Text(JsonObject obj, string property) => obj[property] is JsonValue value && value.TryGetValue<string>(out var text) ? text : throw NftStaticSetSnapshot.Invalid();

    private static string CompleteCore(string echo, IEnumerable<string> completeListings, string expectedArtifact)
    {
        var root = NftStaticSetSnapshot.ReadRoot(echo);
        var echoed = new Dictionary<(string Family, string Table, string Name), JsonObject>();
        var reportedElements = new Dictionary<(string Family, string Table, string Name), List<JsonNode?>>();
        foreach (var item in root["nftables"]!.AsArray())
        {
            if (item?["add"]?["set"] is not JsonObject set || set["name"]?.GetValue<string>() is not { } name || !name.StartsWith("nergal_obj_", StringComparison.Ordinal)) { continue; }
            NftStaticSetSnapshot.RequireProperties(item!.AsObject(), "add");
            NftStaticSetSnapshot.RequireProperties(item["add"]!.AsObject(), "set");
            var family = Text(set, "family"); var table = Text(set, "table");
            NftStaticSetSnapshot.ValidateDefinition(set, family, table, false);
            if (!echoed.TryAdd((family, table, name), set)) { throw NftStaticSetSnapshot.Invalid(); }
            reportedElements.Add((family, table, name), set["elem"] is JsonArray elements ? elements.Select(e => e?.DeepClone()).ToList() : []);
        }
        if (echoed.Count == 0)
        {
            if (expectedArtifact.Split('\n').Any(line => line.StartsWith("add set ", StringComparison.Ordinal) && line.Contains(" nergal_obj_", StringComparison.Ordinal)))
            { throw NftStaticSetSnapshot.Invalid(); }
            return echo;
        }
        if (echoed.Count > 256) { throw NftStaticSetSnapshot.Invalid(); }
        var listings = completeListings.Take(5).Select(NftStaticSetSnapshot.ReadRoot).ToArray();
        if (listings.Length is < 1 or > 4) { throw NftStaticSetSnapshot.Invalid(); }
        var byTable = new Dictionary<(string, string), JsonObject>();
        var observed = new Dictionary<(string Family, string Table, string Name), JsonObject>();
        foreach (var listing in listings)
        {
            var tables = listing["nftables"]!.AsArray().Where(i => i?["table"] is not null).ToArray();
            if (tables.Length != 1 || tables[0]!["table"] is not JsonObject header) { throw NftStaticSetSnapshot.Invalid(); }
            var family = Text(header, "family"); var table = Text(header, "name");
            if (!byTable.TryAdd((family, table), listing)) { throw NftStaticSetSnapshot.Invalid(); }
            foreach (var item in listing["nftables"]!.AsArray())
            {
                if (item?["set"] is not JsonObject set || set["name"]?.GetValue<string>() is not { } name || !name.StartsWith("nergal_obj_", StringComparison.Ordinal)) { continue; }
                NftStaticSetSnapshot.ValidateDefinition(set, family, table, true);
                if (!observed.TryAdd((family, table, name), set)) { throw NftStaticSetSnapshot.Invalid(); }
            }
        }
        if (!echoed.Keys.ToHashSet().SetEquals(observed.Keys)) { throw NftStaticSetSnapshot.Invalid(); }
        if (!byTable.Remove(("inet", NftFilterCompiler.TableName), out var primaryJson)) { throw NftStaticSetSnapshot.Invalid(); }
        var primary = NftTableObservation.Parse(primaryJson.ToJsonString()).Observation ?? throw NftStaticSetSnapshot.Invalid();
        var nat = byTable.Remove(("inet", NftNatCompiler.TableName), out var natJson) ? NftNatTableObservation.Parse(natJson.ToJsonString()).Observation ?? throw NftStaticSetSnapshot.Invalid() : null;
        var bridge = byTable.Remove(("bridge", NftBridgeCompiler.TableName), out var bridgeJson) ? NftBridgeTableObservation.Parse(bridgeJson.ToJsonString()).Observation ?? throw NftStaticSetSnapshot.Invalid() : null;
        var auxiliary = byTable.Remove(("inet", NftAuxiliaryTableObservation.TableName), out var auxiliaryJson) ? NftAuxiliaryTableObservation.Parse(auxiliaryJson.ToJsonString()) ?? throw NftStaticSetSnapshot.Invalid() : null;
        if (byTable.Count != 0 || NftPolicyBundleCompiler.Compile(NftTableObservation.Combine(primary, nat, bridge, auxiliary).Bundle, primary.Identity).Candidate != expectedArtifact)
        { throw NftStaticSetSnapshot.Invalid(); }
        foreach (var item in root["nftables"]!.AsArray())
        {
            if (item?["add"]?["element"] is not JsonObject element) { continue; }
            NftStaticSetSnapshot.RequireProperties(item!.AsObject(), "add");
            NftStaticSetSnapshot.RequireProperties(item["add"]!.AsObject(), "element");
            NftStaticSetSnapshot.RequireProperties(element, "family", "table", "name", "elem");
            var key = (Text(element, "family"), Text(element, "table"), Text(element, "name"));
            if (!reportedElements.TryGetValue(key, out var values) || element["elem"] is not JsonObject valueSet) { throw NftStaticSetSnapshot.Invalid(); }
            NftStaticSetSnapshot.RequireProperties(valueSet, "set");
            if (valueSet["set"] is not JsonArray elements) { throw NftStaticSetSnapshot.Invalid(); }
            values.AddRange(elements.Select(e => e?.DeepClone()));
            if (values.Count > 64) { throw NftStaticSetSnapshot.Invalid(); }
        }
        foreach (var (key, definition) in echoed)
        {
            var full = observed[key];
            // ValidateDefinition already binds type/flags to the generated identity. Compare every definition field, not just its name.
            var actualDefinition = full.DeepClone().AsObject(); actualDefinition.Remove("elem");
            var echoDefinition = definition.DeepClone().AsObject(); echoDefinition.Remove("elem");
            actualDefinition["flags"] = new JsonArray(full["flags"]!.AsArray().Select(f => JsonValue.Create(f!.GetValue<string>()) as JsonNode).OrderBy(f => f!.GetValue<string>(), StringComparer.Ordinal).ToArray());
            echoDefinition["flags"] = actualDefinition["flags"]!.DeepClone();
            if (!JsonNode.DeepEquals(actualDefinition, echoDefinition)) { throw NftStaticSetSnapshot.Invalid(); }
            if (reportedElements[key].Count > 0)
            {
                var partial = NftStaticSetSnapshot.Reference(key.Name, reportedElements[key]).Content.Entries;
                var complete = NftStaticSetSnapshot.Reference(key.Name, full["elem"]!.AsArray()).Content.Entries;
                if (partial.Except(complete, StringComparer.Ordinal).Any()) { throw NftStaticSetSnapshot.Invalid(); }
            }
        }
        var completed = new JsonArray();
        foreach (var item in root["nftables"]!.AsArray())
        {
            if (item?["add"]?["element"] is not null) { continue; }
            completed.Add(item!.DeepClone());
            if (item?["add"]?["set"] is JsonObject set && set["name"]?.GetValue<string>() is { } name && name.StartsWith("nergal_obj_", StringComparison.Ordinal))
            {
                var key = (Text(set, "family"), Text(set, "table"), name);
                completed.Add(new JsonObject
                {
                    ["add"] = new JsonObject
                    {
                        ["element"] = new JsonObject
                        { ["family"] = key.Item1, ["table"] = key.Item2, ["name"] = name, ["elem"] = new JsonObject { ["set"] = observed[key]["elem"]!.DeepClone() } }
                    }
                });
                // Elements are now represented once, rather than both on a definition and an element record.
                completed[^2]!["add"]!["set"]!.AsObject().Remove("elem");
            }
        }
        root["nftables"] = completed;
        var json = root.ToJsonString();
        if (Encoding.UTF8.GetByteCount(json) > 65536) { throw NftStaticSetSnapshot.Invalid(); }
        return json;
    }
}
