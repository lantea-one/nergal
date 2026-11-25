using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Core.Controller;

/// <summary>A source identity/digest dependency, without embedded private source text.</summary>
public sealed record NativeConversionSource(Guid Id, string Digest);

/// <summary>Validated immutable database plan contents; only server-side recomputation may authorize revision creation.</summary>
public sealed class NativeConversionPlanContent
{
    /// <summary>Validates bounded JSON envelopes, source bindings and optional complete intent.</summary>
    /// <exception cref="ArgumentException">An envelope, dependency or candidate is invalid.</exception>
    public NativeConversionPlanContent(Guid rootSourceId, string requestJson, string reportJson, string? policyJson, string? candidateDigest)
    {
        ArgumentNullException.ThrowIfNull(requestJson);
        ArgumentNullException.ThrowIfNull(reportJson);
        if (rootSourceId == Guid.Empty || requestJson.Length > 65_536 || reportJson.Length > 2_097_152 || policyJson?.Length > 1_048_576) { throw new ArgumentException("conversion.bounds"); }
        try
        {
            using var request = JsonDocument.Parse(requestJson, new() { MaxDepth = 32 });
            using var report = JsonDocument.Parse(reportJson, new() { MaxDepth = 32 });
            RequireProperties(request.RootElement, ["rootSourceId", "tables", "includes", "restrictGlobalOperations"]);
            RequireProperties(report.RootElement, ["schemaVersion", "sourceBindings", "mappings", "gaps"]);
            if (request.RootElement.GetProperty("rootSourceId").GetGuid() != rootSourceId || report.RootElement.GetProperty("schemaVersion").GetInt32() != 1) { throw new ArgumentException("conversion.envelopeInvalid"); }
            var bindings = report.RootElement.GetProperty("sourceBindings"); var result = new List<NativeConversionSource>();
            foreach (var binding in bindings.EnumerateArray())
            {
                RequireProperties(binding, ["id", "digest"]);
                var id = binding.GetProperty("id").GetGuid(); var digest = new CandidateDigest(binding.GetProperty("digest").GetString()!);
                if (id == Guid.Empty || result.Any(s => s.Id == id) || result.Count == 32) { throw new ArgumentException("conversion.sourcesInvalid"); }
                result.Add(new(id, digest.Value));
            }
            if (!result.Any(s => s.Id == rootSourceId)) { throw new ArgumentException("conversion.sourcesInvalid"); }
            foreach (var name in new[] { "mappings", "gaps" })
            {
                var entries = report.RootElement.GetProperty(name);
                if (entries.GetArrayLength() > 65_536) { throw new ArgumentException("conversion.bounds"); }
                foreach (var entry in entries.EnumerateArray())
                {
                    RequireProperties(entry, name == "gaps" ? ["sourceId", "span", "code"] : ["sourceId", "span", "disposition", "target"]);
                    if (!result.Any(s => s.Id == entry.GetProperty("sourceId").GetGuid())) { throw new ArgumentException("conversion.sourcesInvalid"); }
                    var span = entry.GetProperty("span");
                    RequireProperties(span, ["offset", "length", "line", "column"]);
                    if (span.GetProperty("offset").GetInt32() < 0 || span.GetProperty("length").GetInt32() < 0 ||
                        span.GetProperty("line").GetInt32() < 1 || span.GetProperty("column").GetInt32() < 1)
                    { throw new ArgumentException("conversion.envelopeInvalid"); }
                }
            }
            GapCount = report.RootElement.GetProperty("gaps").GetArrayLength();
            if (GapCount > 65_536 || (policyJson is null) != (candidateDigest is null) || (policyJson is not null && (GapCount != 0 || !PolicyBundleJsonCodec.DecodeBundle(policyJson).IsSuccess)))
            { throw new ArgumentException("conversion.candidateInvalid"); }
            if (candidateDigest is not null) { _ = new CandidateDigest(candidateDigest); }
            Sources = result.AsReadOnly();
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { throw new ArgumentException("conversion.envelopeInvalid"); }
        RootSourceId = rootSourceId; RequestJson = requestJson; ReportJson = reportJson; PolicyJson = policyJson; CandidateDigest = candidateDigest;
        Digest = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new[] { rootSourceId.ToString("D"), requestJson, reportJson, policyJson, candidateDigest })));
    }
    private static void RequireProperties(JsonElement element, string[] expected)
    {
        var names = element.EnumerateObject().Select(p => p.Name).ToArray();
        if (names.Length != expected.Length || names.Distinct(StringComparer.Ordinal).Count() != names.Length || names.Any(n => !expected.Contains(n, StringComparer.Ordinal)))
        { throw new ArgumentException("conversion.envelopeInvalid"); }
    }
    /// <summary>Gets the root immutable snapshot identity.</summary>
    public Guid RootSourceId { get; }
    /// <summary>Gets private canonical operator choices, never executed as code.</summary>
    public string RequestJson { get; }
    /// <summary>Gets the source-bound mapping/gap envelope.</summary>
    public string ReportJson { get; }
    /// <summary>Gets complete canonical intent, absent for blocked plans.</summary>
    public string? PolicyJson { get; }
    /// <summary>Gets the exact candidate binding, absent for blocked plans.</summary>
    public string? CandidateDigest { get; }
    /// <summary>Gets immutable source dependencies.</summary>
    public IReadOnlyList<NativeConversionSource> Sources { get; }
    /// <summary>Gets the number of blocking gaps.</summary>
    public int GapCount { get; }
    /// <summary>Gets whether complete intent is available; recomputation and authorization remain mandatory.</summary>
    public bool IsReady => PolicyJson is not null && GapCount == 0;
    /// <summary>Gets the digest covering every persisted content field.</summary>
    public string Digest { get; }
    /// <summary>Omits private choices, source values and candidate contents.</summary>
    public override string ToString() => $"Native conversion plan ({GapCount} gaps)";
}

/// <summary>One immutable review and its optional separately committed revision link; timestamps are UTC.</summary>
public sealed record NativeConversionPlanRecord(Guid Id, NativeConversionPlanContent Content, string CreatedByActor, DateTimeOffset CreatedAtUtc, ulong? Revision)
{
    /// <summary>Omits actor identities and private plan contents.</summary>
    public override string ToString() => "Native conversion record";
}
