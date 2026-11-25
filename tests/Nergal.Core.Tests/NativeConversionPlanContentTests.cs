using System.Text.Json.Nodes;
using Nergal.Core.Controller;

namespace Nergal.Core.Tests;

/// <summary>Persisted plan envelopes bind diagnostics to explicit source identities and reject ambiguous history.</summary>
public sealed class NativeConversionPlanContentTests
{
    private static readonly Guid Source = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static string Request => $$"""{"rootSourceId":"{{Source}}","tables":[],"includes":[],"restrictGlobalOperations":false}""";
    private static string Report => $$"""{"schemaVersion":1,"sourceBindings":[{"id":"{{Source}}","digest":"{{new string('a', 64)}}"}],"mappings":[],"gaps":[{"sourceId":"{{Source}}","span":{"offset":0,"length":1,"line":1,"column":1},"code":"import.expressionUnsupported"}]}""";

    /// <summary>Blocked immutable contents survive round-trip without exposing choices through incidental formatting.</summary>
    [Fact]
    public void BlockedPlan_IsImmutableAndHasNoRevisionAuthority()
    {
        var plan = new NativeConversionPlanContent(Source, Request, Report, null, null);
        Assert.False(plan.IsReady); Assert.Equal(1, plan.GapCount);
        Assert.Equal(plan.Digest, new NativeConversionPlanContent(Source, Request, Report, null, null).Digest);
        Assert.Throws<NotSupportedException>(() => ((IList<NativeConversionSource>)plan.Sources).Clear());
        Assert.DoesNotContain(Source.ToString(), plan.ToString());
    }

    /// <summary>Unbound diagnostics, invalid coordinates and unknown report fields cannot become durable trusted history.</summary>
    [Theory]
    [InlineData("foreignSource")]
    [InlineData("invalidPosition")]
    [InlineData("unknownField")]
    [InlineData("duplicateSource")]
    [InlineData("partialCandidate")]
    public void MalformedPlan_IsRejected(string mutation)
    {
        var report = JsonNode.Parse(Report)!;
        switch (mutation)
        {
            case "foreignSource": report["gaps"]![0]!["sourceId"] = Guid.Parse("22222222-2222-4222-8222-222222222222"); break;
            case "invalidPosition": report["gaps"]![0]!["span"]!["line"] = 0; break;
            case "unknownField": report["skipUnknown"] = true; break;
            case "duplicateSource": report["sourceBindings"]!.AsArray().Add(report["sourceBindings"]![0]!.DeepClone()); break;
        }
        Assert.Throws<ArgumentException>(() => new NativeConversionPlanContent(Source, Request, report.ToJsonString(), null, mutation == "partialCandidate" ? new string('a', 64) : null));
    }

    /// <summary>Duplicate JSON fields must fail even when a last-value parser could make them appear valid.</summary>
    [Fact]
    public void DuplicateEnvelopeMember_IsRejected()
    {
        var duplicate = Report.Replace("\"schemaVersion\":1", "\"schemaVersion\":0,\"schemaVersion\":1", StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => new NativeConversionPlanContent(Source, Request, duplicate, null, null));
    }
}
