using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using static Nergal.Nftables.NftJsonHelpers;

namespace Nergal.Nftables;

/// <summary>Complete strict observation of the reserved early inet table.</summary>
public sealed class NftAuxiliaryTableObservation
{
    /// <summary>Fixed resource name; never supplied by a policy author.</summary>
    public const string TableName = "nergal_aux";
    private NftAuxiliaryTableObservation(NftTableObservation filter, int priority)
    {
        Identity = filter.Identity;
        TableHandle = filter.TableHandle;
        Policy = new(priority, filter.Policy);
        StateDigest = CandidateDigest.FromText(string.Join('\n', "nergal-aux-observation-v1", TableName,
            priority.ToString(CultureInfo.InvariantCulture), filter.StateDigest.Value));
    }
    /// <summary>Gets the native owner/resource marker; not independent ownership authority.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the native table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the reconstructed early filtering policy.</summary>
    public AuxiliaryFilterPolicy Policy { get; }
    /// <summary>Gets the fingerprint of all table objects, handles, priority, and semantics.</summary>
    public CandidateDigest StateDigest { get; }
    /// <summary>Parses a full native listing, rejecting partial or unknown scope.</summary>
    public static NftAuxiliaryTableObservation? Parse(string json) => ParseCore(json, false);
    /// <summary>Parses complete handle-bearing native creation echo.</summary>
    public static NftAuxiliaryTableObservation? ParseReplacementEcho(string json) => ParseCore(json, true);

    private static NftAuxiliaryTableObservation? ParseCore(string json, bool echo)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (Encoding.UTF8.GetByteCount(json) > NftObservationLimits.MaximumDocumentBytes) { return null; }
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (HasDuplicateProperties(doc.RootElement) || !Properties(doc.RootElement, "nftables") ||
                doc.RootElement.GetProperty("nftables").ValueKind != JsonValueKind.Array) { return null; }
            var items = doc.RootElement.GetProperty("nftables").EnumerateArray().ToArray();
            if (!echo && !TryReadMetaHeader(items)) { return null; }
            var result = new JsonArray();
            int? priority = null;
            var sawTable = false;
            foreach (var item in items)
            {
                if (!echo && Properties(item, "metainfo")) { result.Add(JsonNode.Parse(item.GetRawText())); continue; }
                var inner = echo ? Properties(item, "create") ? item.GetProperty("create") : Properties(item, "add") ? item.GetProperty("add") : default : item;
                if (inner.ValueKind != JsonValueKind.Object || inner.EnumerateObject().Count() != 1) { return null; }
                var property = inner.EnumerateObject().Single();
                var value = property.Value;
                if (property.Name is not ("table" or "chain" or "rule" or "set" or "element") || value.ValueKind != JsonValueKind.Object ||
                    value.GetProperty("family").GetString() != "inet") { return null; }
                var node = JsonNode.Parse(item.GetRawText())!;
                var target = echo ? node[Properties(item, "create") ? "create" : "add"]![property.Name]! : node[property.Name]!;
                if (property.Name == "table")
                {
                    if (sawTable || value.GetProperty("name").GetString() != TableName || (echo && !Properties(item, "create"))) { return null; }
                    sawTable = true;
                    target["name"] = NftFilterCompiler.TableName;
                }
                else
                {
                    if (!sawTable || value.GetProperty("table").GetString() != TableName || (echo && !Properties(item, "add"))) { return null; }
                    target["table"] = NftFilterCompiler.TableName;
                    if (property.Name == "chain" && value.GetProperty("name").GetString() is "input" or "forward" or "output")
                    {
                        if (!value.GetProperty("prio").TryGetInt32(out var p) || p is < -300 or > 300 || (priority.HasValue && priority.Value != p)) { return null; }
                        priority = p;
                        target["prio"] = 0;
                    }
                }
                result.Add(node);
            }
            if (!priority.HasValue) { return null; }
            var normalized = new JsonObject { ["nftables"] = result }.ToJsonString();
            var parsed = echo ? NftTableObservation.ParseReplacementEcho(normalized) : NftTableObservation.Parse(normalized);
            if (!parsed.IsSuccess || parsed.Observation!.Policy.SchemaVersion != 2 || parsed.Observation.Policy.ForwardTcpMssClamp is not null) { return null; }
            return new(parsed.Observation, priority.Value);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        { return null; }
    }
}
