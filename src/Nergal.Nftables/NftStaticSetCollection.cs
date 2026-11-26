using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Nergal.Nftables;

/// <summary>Pure bounded planning and joining of static-set contents omitted from terse owned-table listings.</summary>
/// <remarks>No host access or authority is conferred. The agent must bracket all reads with a stable kernel generation and then parse the complete observation.</remarks>
public static class NftStaticSetCollection
{
    /// <summary>Returns recognized generated static-set names in a fixed owned scope; no policy text becomes a command.</summary>
    /// <exception cref="ArgumentException">The scope, bounds or generated static-set definitions are invalid.</exception>
    public static IReadOnlyList<string> Names(string terse, string family, string table)
    => Read(() => NamesCore(terse, family, table));

    private static IReadOnlyList<string> NamesCore(string terse, string family, string table)
    {
        ValidateScope(family, table);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in NftStaticSetSnapshot.ReadRoot(terse)["nftables"]!.AsArray())
        {
            if (item?["set"] is not JsonObject set || set["name"]?.GetValue<string>() is not { } name || !name.StartsWith("nergal_obj_", StringComparison.Ordinal)) { continue; }
            NftStaticSetSnapshot.RequireProperties(item!.AsObject(), "set");
            NftStaticSetSnapshot.ValidateDefinition(set, family, table, false);
            if (set.ContainsKey("elem") || !names.Add(name) || names.Count > 64) { throw NftStaticSetSnapshot.Invalid(); }
        }
        return Array.AsReadOnly(names.Order(StringComparer.Ordinal).ToArray());
    }

    /// <summary>Joins one complete independent listing per requested set, retaining exact native definition and handle agreement.</summary>
    /// <exception cref="ArgumentException">Listings are missing, extra, inconsistent, malformed or exceed the complete observation bound.</exception>
    public static string Complete(string terse, string family, string table, IEnumerable<string> listings)
    => Read(() => CompleteCore(terse, family, table, listings));

    private static string CompleteCore(string terse, string family, string table, IEnumerable<string> listings)
    {
        ArgumentNullException.ThrowIfNull(listings);
        var expected = Names(terse, family, table).ToHashSet(StringComparer.Ordinal);
        var root = NftStaticSetSnapshot.ReadRoot(terse);
        var definitions = root["nftables"]!.AsArray().Where(i => i?["set"] is JsonObject)
            .Select(i => i!["set"]!.AsObject()).Where(s => expected.Contains(s["name"]!.GetValue<string>()))
            .ToDictionary(s => s["name"]!.GetValue<string>(), StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var listing in listings.Take(65))
        {
            var reply = NftStaticSetSnapshot.ReadRoot(listing);
            var items = reply["nftables"]!.AsArray();
            using var doc = JsonDocument.Parse(listing);
            if (items.Count != 2 || !NftJsonHelpers.TryReadMetaHeader(doc.RootElement.GetProperty("nftables").EnumerateArray().ToArray()) || items[1] is not JsonObject wrapper)
            { throw NftStaticSetSnapshot.Invalid(); }
            NftStaticSetSnapshot.RequireProperties(wrapper, "set");
            if (wrapper["set"] is not JsonObject set) { throw NftStaticSetSnapshot.Invalid(); }
            NftStaticSetSnapshot.ValidateDefinition(set, family, table, true);
            var name = set["name"]!.GetValue<string>();
            if (!expected.Contains(name) || !seen.Add(name) || set["handle"]!.GetValue<ulong>() != definitions[name]["handle"]!.GetValue<ulong>())
            { throw NftStaticSetSnapshot.Invalid(); }
            definitions[name]["elem"] = set["elem"]!.DeepClone();
        }
        if (!expected.SetEquals(seen)) { throw NftStaticSetSnapshot.Invalid(); }
        var json = root.ToJsonString();
        if (Encoding.UTF8.GetByteCount(json) > NftObservationLimits.MaximumDocumentBytes) { throw NftStaticSetSnapshot.Invalid(); }
        return json;
    }
    private static T Read<T>(Func<T> read)
    {
        try { return read(); }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw NftStaticSetSnapshot.Invalid(); }
    }
    private static void ValidateScope(string family, string table)
    {
        if (!(family == "inet" && table is NftFilterCompiler.TableName or NftNatCompiler.TableName or NftAuxiliaryTableObservation.TableName) &&
            !(family == "bridge" && table == NftBridgeCompiler.TableName)) { throw NftStaticSetSnapshot.Invalid(); }
    }
}
