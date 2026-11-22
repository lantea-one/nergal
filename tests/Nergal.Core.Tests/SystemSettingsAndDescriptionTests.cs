using Nergal.Core;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Xunit;

namespace Nergal.Core.Tests;

/// <summary>Verifies strict validation and serialization of system settings and optional rule descriptions.</summary>
public sealed class SystemSettingsAndDescriptionTests
{
    /// <summary>Default settings pass validation and survive JSON round-trip identically.</summary>
    [Fact]
    public void SystemSettingsCodec_DefaultSnapshot_ValidatesAndRoundTrips()
    {
        var defaults = SystemSettingsSnapshot.Default;
        Assert.Empty(SystemSettingsCodec.Validate(defaults));

        var json = SystemSettingsCodec.Serialize(defaults);
        var roundTripped = SystemSettingsCodec.Deserialize(json);
        Assert.NotNull(roundTripped);
        Assert.Equal(defaults, roundTripped);
    }

    /// <summary>Valid custom Branding, Local, OIDC, LDAP, PostgreSQL, and Firewall settings pass validation.</summary>
    [Fact]
    public void SystemSettingsCodec_CustomValidConfiguration_PassesValidation()
    {
        var custom = new SystemSettingsSnapshot(
            new BrandingSettings("Perimeter Console", "Edge nftables controller", "emerald", "dark", "Authorized admins only"),
            new LocalAuthSettings(true, 60, 5, 15, 14),
            new OidcAuthSettings(true, "https://idp.example.test/realms/net", "nergal-web", "openid profile email groups", "https://fw.example.test/signin-oidc", "groups", "fw-admins", "fw-auditors", 1800),
            new LdapAuthSettings(true, "ldaps://dir.example.test:636", true, "dc=example,dc=test", "cn=svc,dc=example,dc=test", "(uid={0})", "memberOf", "cn=admins,dc=example,dc=test", "cn=auditors,dc=example,dc=test"),
            new DatabaseBackendSettings("postgresql", "db.internal.example.test", 5432, "nergal", "nergal_app", "verify-full"),
            new FirewallDefaultsSettings(45, 2, "drop", "drop", "accept", true));

        Assert.Empty(SystemSettingsCodec.Validate(custom));
        var roundTripped = SystemSettingsCodec.Deserialize(SystemSettingsCodec.Serialize(custom));
        Assert.Equal(custom, roundTripped);
    }

    /// <summary>Invalid settings fields report stable error codes and malformed JSON returns null.</summary>
    [Fact]
    public void SystemSettingsCodec_InvalidInputs_ReportStableErrorCodes()
    {
        var invalid = new SystemSettingsSnapshot(
            new BrandingSettings("", "bad\nline", "magenta", "solarized", "ok"),
            new LocalAuthSettings(true, 1, 1, 0, 4),
            new OidcAuthSettings(true, "http://insecure.example.test", "", "openid", null, "groups", null, null, 10),
            new LdapAuthSettings(true, "https://not-ldap.example.test", true, "", null, "(uid={0})", "memberOf", null, null),
            new DatabaseBackendSettings("postgresql", "", 99999, "", null, "bogus"),
            new FirewallDefaultsSettings(0, 9, "reject", "drop", "accept", false));

        var errors = SystemSettingsCodec.Validate(invalid);
        Assert.Contains("branding.applicationName", errors);
        Assert.Contains("branding.instanceSubtitle", errors);
        Assert.Contains("branding.accentColor", errors);
        Assert.Contains("branding.defaultTheme", errors);
        Assert.Contains("auth.local.sessionIdleTimeoutMinutes", errors);
        Assert.Contains("auth.local.lockoutMaxFailedAttempts", errors);
        Assert.Contains("auth.local.lockoutDurationMinutes", errors);
        Assert.Contains("auth.local.minimumPasswordLength", errors);
        Assert.Contains("auth.oidc.authorityUrl", errors);
        Assert.Contains("auth.oidc.clientId", errors);
        Assert.Contains("auth.oidc.maxAuthAgeSeconds", errors);
        Assert.Contains("auth.ldap.serverUri", errors);
        Assert.Contains("auth.ldap.baseDn", errors);
        Assert.Contains("database.host", errors);
        Assert.Contains("database.port", errors);
        Assert.Contains("database.databaseName", errors);
        Assert.Contains("database.tlsMode", errors);
        Assert.Contains("firewall.defaultConfirmationTimeoutSeconds", errors);
        Assert.Contains("firewall.defaultFilterSchemaVersion", errors);
        Assert.Contains("firewall.defaultVerdict", errors);

        Assert.ThrowsAny<System.Text.Json.JsonException>(() => SystemSettingsCodec.Deserialize("{not valid json"));
    }

    /// <summary>Optional rule descriptions round-trip across Filter, DNAT, SNAT, and Bridge rules and reject control characters.</summary>
    [Fact]
    public void PolicyBundleJsonCodec_RoundTripsOptionalDescriptionsAndRejectsControlChars()
    {
        var bundle = new FirewallPolicyBundle(
            1,
            new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [
                new FilterRule(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, new NetworkPrefix("192.0.2.0/24"), null, 443, Description: "Allow admin HTTPS"),
            ]),
            new NatPolicy(
                1,
                [new DnatRule(IpFamily.IPv4, FilterProtocol.Tcp, new NetworkPrefix("198.51.100.10/32"), "192.0.2.20", 443, 8443, "wan0", null, "Ingress reverse proxy")],
                [new SnatRule(IpFamily.IPv4, new NetworkPrefix("192.0.2.0/24"), "198.51.100.10", null, "wan0", "DMZ egress SNAT")]),
            new BridgePolicy(1, FilterVerdict.Accept,
            [
                new BridgeFilterRule(BridgeEtherType.Arp, FilterVerdict.Accept, "br0", null, "Allow ARP on bridge"),
            ]));

        var encoded = PolicyBundleJsonCodec.EncodeBundle(bundle, indented: false);
        var decoded = PolicyBundleJsonCodec.DecodeBundle(encoded);
        Assert.True(decoded.IsSuccess);
        Assert.Equal("Allow admin HTTPS", decoded.Value!.Filter.Rules[0]!.Description);
        Assert.Equal("Ingress reverse proxy", decoded.Value.Nat!.DnatRules[0]!.Description);
        Assert.Equal("DMZ egress SNAT", decoded.Value.Nat.SnatRules[0]!.Description);
        Assert.Equal("Allow ARP on bridge", decoded.Value.Bridge!.Rules[0]!.Description);

        // Reject control characters in rule description.
        var badJson = encoded.Replace("Allow admin HTTPS", "Bad\\nDescription", StringComparison.Ordinal);
        var failed = PolicyBundleJsonCodec.DecodeBundle(badJson);
        Assert.False(failed.IsSuccess);
        Assert.Contains(failed.Diagnostics, d => d.Code == "filter.description");
    }
}
