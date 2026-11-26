using System.Text.Json.Nodes;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Filter state restrictions survive policy transport and native compilation.</summary>
public sealed class FilterConnectionStateTests
{
    /// <summary>Named states and numeric masks preserve untracked, alone and alongside every tracked state.</summary>
    [Theory]
    [InlineData("16", ConnectionStateFlags.Untracked, """["untracked"]""", "untracked")]
    [InlineData("""["untracked","new"]""", ConnectionStateFlags.Untracked | ConnectionStateFlags.New, """["new","untracked"]""", "new,untracked")]
    [InlineData("31", FilterPolicyValidation.AllConnectionStates, """["new","established","related","invalid","untracked"]""", "invalid,established,related,new,untracked")]
    public void State_RoundTrips(string input, ConnectionStateFlags states, string canonical, string native)
    {
        var decoded = DecodeStates(input);
        Assert.True(decoded.IsSuccess);
        Assert.Equal(states, Assert.Single(decoded.Value!.Filter.Rules)!.ConnectionStates);
        var encoded = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(decoded.Value))!;
        Assert.Equal(canonical, encoded["filter"]!["rules"]![0]!["connectionStates"]!.ToJsonString());
        var compiled = NftFilterCompiler.Compile(decoded.Value.Filter);
        Assert.Contains($"ct state {native} drop\n", compiled.Candidate);
    }

    /// <summary>A known state beside an undefined bit or name cannot yield a partially decoded rule.</summary>
    [Theory]
    [InlineData("48")]
    [InlineData("-1")]
    [InlineData("""["untracked","notrack"]""")]
    public void Decode_RejectsUnknownStates(string input)
    {
        var decoded = DecodeStates(input);
        Assert.Null(decoded.Value);
        Assert.Equal(new("filter.connectionStates", "filter.rules[0].connectionStates"), Assert.Single(decoded.Diagnostics));
    }

    /// <summary>Serialization cannot hide a bit that would block the original candidate.</summary>
    [Fact]
    public void Encode_RejectsUnknownStateBits()
    {
        var bundle = Bundle(ConnectionStateFlags.Untracked | (ConnectionStateFlags)32);
        Assert.Throws<ArgumentOutOfRangeException>(() => PolicyBundleJsonCodec.EncodeBundle(bundle));
        Assert.Null(NftFilterCompiler.Compile(bundle.Filter).Candidate);
    }

    private static PolicyJsonDecodeResult<FirewallPolicyBundle> DecodeStates(string input)
    {
        var json = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(Bundle(ConnectionStateFlags.None)))!;
        json["filter"]!["rules"]![0]!["connectionStates"] = JsonNode.Parse(input);
        return PolicyBundleJsonCodec.DecodeBundle(json.ToJsonString());
    }

    private static FirewallPolicyBundle Bundle(ConnectionStateFlags states) =>
        new(1, new(2, FilterVerdict.Drop, [new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop, ConnectionStates: states)]));
}
