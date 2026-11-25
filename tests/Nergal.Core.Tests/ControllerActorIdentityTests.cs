using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Actor framing preserves exact identity tuples instead of merging colon-ambiguous subjects/issuers.</summary>
public sealed class ControllerActorIdentityTests
{
    /// <summary>Two pairs that collide under plain concatenation remain different profile/audit keys.</summary>
    [Fact]
    public void FederatedIdentity_UsesAnUnambiguousLengthFramedPair()
    {
        var first = ControllerActorIdentity.FromFederatedAccount("https://issuer.example/a", "b:c");
        var second = ControllerActorIdentity.FromFederatedAccount("https://issuer.example/a:b", "c");
        Assert.NotEqual(first, second);
        Assert.True(ControllerActorIdentity.IsValid(first));
        Assert.True(ControllerActorIdentity.IsValid(second));
        Assert.NotEqual(first, ControllerActorIdentity.FromFederatedAccount("https://issuer.example/A", "b:c"));
    }

    /// <summary>Malformed Unicode cannot turn into a replacement-character identity when persisted as UTF-8.</summary>
    [Fact]
    public void FederatedIdentity_RejectsMalformedUnicodeBeforePersistence()
    {
        Assert.Throws<ArgumentException>(() => ControllerActorIdentity.FromFederatedAccount("https://issuer.example", "subject" + '\ud800'));
    }

    /// <summary>Unknown, unframed, noncanonical lengths and truncated tuples cannot become valid attribution.</summary>
    [Theory]
    [InlineData("oidc:https://issuer.example:subject")]
    [InlineData("oidc:0::subject")]
    [InlineData("oidc:999999999999:issuer:subject")]
    [InlineData("oidc:3:ab:subject")]
    [InlineData("oidc:03:abc:subject")]
    [InlineData("oidc:3:abc:")]
    [InlineData("oidc:3:abc:subject")]
    public void FederatedIdentity_RejectsAmbiguousOrMalformedKeys(string key) => Assert.False(ControllerActorIdentity.IsValid(key));
}
