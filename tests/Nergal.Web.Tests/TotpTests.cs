using System.Text;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Checks the deployed six-digit TOTP variant against RFC 6238 SHA-1 vectors.</summary>
public sealed class TotpTests
{
    private static readonly byte[] Seed = Encoding.ASCII.GetBytes("12345678901234567890");

    /// <summary>Validates six-digit truncation, leading zeroes, and counters beyond 32-bit Unix time.</summary>
    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1111111111L, "050471")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    [InlineData(20000000000L, "353130")]
    public void Match_UsesRfcCounterAndTruncation(long unixSeconds, string code)
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        Assert.Equal(unixSeconds / 30, Totp.Match(Seed, code, now, -1, enrollment: true));
        Assert.Null(Totp.Match(Seed, code, now, unixSeconds / 30, enrollment: false));
    }

    /// <summary>Allows bounded drift at sign-in and requires the current step for enrollment.</summary>
    [Fact]
    public void Match_BoundsDriftAndInput()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(60);
        Assert.Equal(1L, Totp.Match(Seed, "287082", now, -1, enrollment: false));
        Assert.Null(Totp.Match(Seed, "287082", now, -1, enrollment: true));
        Assert.Null(Totp.Match(Seed, "287082", now.AddSeconds(30), -1, enrollment: false));
        Assert.Null(Totp.Match(Seed, "２８７０８２", now, -1, enrollment: false));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Totp.ManualKey(Seed));
    }
}
