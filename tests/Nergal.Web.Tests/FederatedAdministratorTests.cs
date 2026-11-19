using System.Text.Json;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises authorization after signature verification; the HTTPS fixture tests the signed protocol exchange itself.</summary>
public sealed class FederatedAdministratorTests
{
    private const string Issuer = "https://issuer.example";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(10000);

    /// <summary>Only the exact issuer/subject and group grant access. The earlier of group age or token expiry bounds the ticket.</summary>
    [Theory]
    [InlineData(9990, 20000, 10890)]
    [InlineData(9990, 10001, 10001)]
    public void Authorization_PreservesIdentityAndAbsoluteDeadline(long issued, long expires, long deadline)
    {
        string[] groups = ["Admins", "Operators"];
        var policy = new FederatedAdministratorPolicy(Issuer, "controller", "membership", groups);
        groups[0] = "changed";
        using var token = JsonDocument.Parse($$"""{"iss":"https://issuer.example","sub":"actor","aud":["controller"],"azp":"controller","membership":["Other","Admins"],"iat":{{issued}},"exp":{{expires}}}""");
        Assert.Equal(new FederatedAdministrator(Issuer, "actor", DateTimeOffset.FromUnixTimeSeconds(deadline)), policy.AuthorizeVerifiedClaims(token.RootElement, Now));
    }

    /// <summary>Ambiguous, stale, malformed and lookalike entitlements never return an administrator.</summary>
    [Theory]
    [InlineData("iss", "\"https://issuer.example/other\"")]
    [InlineData("aud", "[\"controller\",\"second\"]")]
    [InlineData("azp", "\"other\"")]
    [InlineData("sub", "null")]
    [InlineData("membership", "\"Admins\"")]
    [InlineData("membership", "[\"admins\"]")]
    [InlineData("membership", "[\"AdminsOther\"]")]
    [InlineData("membership", "[\"Admins\",1]")]
    [InlineData("membership", "[]")]
    [InlineData("iat", "9100")]
    [InlineData("iat", "10001")]
    [InlineData("exp", "10000")]
    [InlineData("exp", "\"20000\"")]
    public void Authorization_RejectsInvalidClaims(string field, string replacement)
    {
        var policy = new FederatedAdministratorPolicy(Issuer, "controller", "membership", ["Admins"]);
        var values = new Dictionary<string, object>
        {
            ["iss"] = Issuer,
            ["sub"] = "actor",
            ["aud"] = "controller",
            ["azp"] = "controller",
            ["membership"] = new[] { "Admins" },
            ["iat"] = 9990,
            ["exp"] = 20000
        };
        using var changed = JsonDocument.Parse(replacement);
        values[field] = changed.RootElement;
        Assert.Null(policy.AuthorizeVerifiedClaims(JsonSerializer.SerializeToElement(values), Now));
    }

    /// <summary>A duplicate claim invalidates the complete signed payload even if its last value would grant access.</summary>
    [Fact]
    public void Authorization_RejectsDuplicateGroupClaim()
    {
        using var token = JsonDocument.Parse("""{"iss":"https://issuer.example","sub":"actor","aud":"controller","iat":9990,"exp":20000,"groups":[],"groups":["Admins"]}""");
        var policy = new FederatedAdministratorPolicy(Issuer, "controller", "groups", ["Admins"]);
        Assert.Null(policy.AuthorizeVerifiedClaims(token.RootElement, Now));
    }

    /// <summary>Activity cannot renew a registration, transfer its identity, restore a logged-out ticket or survive a process restart.</summary>
    [Fact]
    public void Registry_BindsIdentityAndExpiresWithoutRenewal()
    {
        var clock = new Clock();
        var registry = new FederatedSessions(clock);
        var actor = new FederatedAdministrator(Issuer, "actor", Now.AddMinutes(15));
        var ticket = registry.Register(actor);
        var other = registry.Register(actor);
        Assert.False(registry.IsCurrent(ticket, Issuer, "other"));
        Assert.False(registry.IsCurrent(ticket, Issuer + "/other", "actor"));
        Assert.False(new FederatedSessions(clock).IsCurrent(ticket, Issuer, "actor"));
        clock.Now = Now.AddMinutes(14);
        Assert.True(registry.IsCurrent(ticket, Issuer, "actor"));
        registry.Revoke(other);
        Assert.False(registry.IsCurrent(other, Issuer, "actor"));
        clock.Now = Now.AddMinutes(15);
        Assert.False(registry.IsCurrent(ticket, Issuer, "actor"));
        Assert.Throws<InvalidOperationException>(() => registry.Register(actor));
    }

    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now { get; set; } = FederatedAdministratorTests.Now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
