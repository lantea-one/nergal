using Nergal.Core;

namespace Nergal.Core.Tests;

/// <summary>Verifies fail-closed backend selection and immutable policy boundaries.</summary>
public sealed class BackendCompatibilityEvaluatorTests
{
    /// <summary>Allows a backend only when all requested semantics are supported.</summary>
    [Fact]
    public void Evaluate_AllRequirementsSupported_IsCompatible()
    {
        var required = new[] { FirewallFeature.DualStackFiltering, FirewallFeature.DestinationNat };
        var backend = new BackendCapabilities("example", Enum.GetValues<FirewallFeature>());

        var report = BackendCompatibilityEvaluator.Evaluate(required, backend);

        Assert.True(report.IsCompatible);
        Assert.Empty(report.UnsupportedFeatures);
        Assert.Equal("example", report.BackendId);
    }

    /// <summary>Each missing capability prevents a lossy backend selection.</summary>
    [Theory]
    [InlineData(FirewallFeature.DualStackFiltering)]
    [InlineData(FirewallFeature.DestinationNat)]
    [InlineData(FirewallFeature.ExplicitSourceNat)]
    [InlineData(FirewallFeature.OriginalConnectionTuple)]
    [InlineData(FirewallFeature.PerSourceRateLimiting)]
    [InlineData(FirewallFeature.BridgeFiltering)]
    [InlineData(FirewallFeature.AtomicMultiTableCommit)]
    [InlineData(FirewallFeature.ForeignTablePreservation)]
    public void Evaluate_RequiredCapabilityMissing_IsIncompatible(FirewallFeature feature)
    {
        var backend = new BackendCapabilities("limited", []);

        var report = BackendCompatibilityEvaluator.Evaluate([feature], backend);

        Assert.False(report.IsCompatible);
        Assert.Equal(feature, Assert.Single(report.UnsupportedFeatures));
    }

    /// <summary>A shared rate limit cannot satisfy a per-source-meter requirement.</summary>
    [Fact]
    public void Evaluate_FilteringWithoutPerSourceMeters_DoesNotDowngradeRequirement()
    {
        var backend = new BackendCapabilities("limited", [FirewallFeature.DualStackFiltering]);

        var report = BackendCompatibilityEvaluator.Evaluate(
            [FirewallFeature.DualStackFiltering, FirewallFeature.PerSourceRateLimiting], backend);

        Assert.False(report.IsCompatible);
        Assert.Equal(FirewallFeature.PerSourceRateLimiting, Assert.Single(report.UnsupportedFeatures));
    }

    /// <summary>Duplicate requirements do not produce unstable or duplicate diagnostics.</summary>
    [Fact]
    public void Evaluate_DuplicateUnorderedRequirements_ReturnsStableDistinctDiagnostics()
    {
        var backend = new BackendCapabilities("limited", []);

        var report = BackendCompatibilityEvaluator.Evaluate(
            [FirewallFeature.BridgeFiltering, FirewallFeature.ExplicitSourceNat, FirewallFeature.BridgeFiltering],
            backend);

        Assert.Equal(
            [FirewallFeature.ExplicitSourceNat, FirewallFeature.BridgeFiltering],
            report.UnsupportedFeatures);
    }

    /// <summary>Changing the caller's collection cannot silently expand a backend's authority.</summary>
    [Fact]
    public void Capabilities_CallerCollectionChanges_DoNotChangeSnapshot()
    {
        var source = new HashSet<FirewallFeature> { FirewallFeature.DualStackFiltering };
        var backend = new BackendCapabilities("example", source);

        source.Add(FirewallFeature.ExplicitSourceNat);
        source.Remove(FirewallFeature.DualStackFiltering);

        Assert.Contains(FirewallFeature.DualStackFiltering, backend.Features);
        Assert.DoesNotContain(FirewallFeature.ExplicitSourceNat, backend.Features);
    }

    /// <summary>A completed report cannot change when the caller mutates a draft.</summary>
    [Fact]
    public void Evaluate_CallerChangesRequirements_ReportRemainsUnchanged()
    {
        var required = new List<FirewallFeature> { FirewallFeature.BridgeFiltering };
        var backend = new BackendCapabilities("limited", []);
        var report = BackendCompatibilityEvaluator.Evaluate(required, backend);

        required.Clear();

        Assert.False(report.IsCompatible);
        Assert.Equal(FirewallFeature.BridgeFiltering, Assert.Single(report.UnsupportedFeatures));
    }

    /// <summary>Unknown future capability values must fail rather than disappear during validation.</summary>
    [Fact]
    public void Evaluate_UnknownRequirement_Throws()
    {
        var backend = new BackendCapabilities("limited", []);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BackendCompatibilityEvaluator.Evaluate([(FirewallFeature)int.MaxValue], backend));
    }

    /// <summary>Unsupported enum values cannot enter a capability declaration.</summary>
    [Fact]
    public void Capabilities_UnknownFeature_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new BackendCapabilities("example", [(FirewallFeature)int.MaxValue]));
    }

    /// <summary>A backend identifier must remain explicit for audit attribution.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Capabilities_EmptyIdentifier_Throws(string? identifier)
    {
        Assert.ThrowsAny<ArgumentException>(() => new BackendCapabilities(identifier!, []));
    }

    /// <summary>Missing inputs cannot be interpreted as an empty, valid policy.</summary>
    [Fact]
    public void Evaluate_NullRequirements_Throws()
    {
        var backend = new BackendCapabilities("example", []);

        Assert.Throws<ArgumentNullException>(() => BackendCompatibilityEvaluator.Evaluate(null!, backend));
    }

    /// <summary>A missing backend cannot be interpreted as unrestricted.</summary>
    [Fact]
    public void Evaluate_NullBackend_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => BackendCompatibilityEvaluator.Evaluate([], null!));
    }

    /// <summary>A declaration with no feature collection is invalid rather than unrestricted.</summary>
    [Fact]
    public void Capabilities_NullFeatures_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new BackendCapabilities("example", null!));
    }
}
