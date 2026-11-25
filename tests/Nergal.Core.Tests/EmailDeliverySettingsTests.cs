using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Validates explicit SMTP settings without DNS or SMTP traffic.</summary>
public sealed class EmailDeliverySettingsTests
{
    /// <summary>Allows a conventional relay and an explicit IPv6 endpoint without adding implicit credentials.</summary>
    [Theory]
    [InlineData("smtp.example.test", 587)]
    [InlineData("2001:db8::1", 2525)]
    public void AcceptsSingleEndpoint(string host, int port)
    {
        Assert.True(new EmailDeliverySettings(true, host, port, "sender@example.test", "").IsValid);
    }

    /// <summary>Rejects multiple destinations, URL syntax, invalid ports and header-like sender values.</summary>
    [Theory]
    [InlineData("smtp.example.test smtp2.example.test", 25, "sender@example.test")]
    [InlineData("smtp://smtp.example.test", 587, "sender@example.test")]
    [InlineData("smtp.example.test:587", 587, "sender@example.test")]
    [InlineData("smtp.example.test", 0, "sender@example.test")]
    [InlineData("smtp.example.test", 587, "Sender <sender@example.test>")]
    [InlineData("smtp.example.test", 587, "sender@example.test\r\nBcc:other@example.test")]
    public void RejectsAmbiguousOrMalformedSettings(string host, int port, string sender)
    {
        Assert.False(new EmailDeliverySettings(false, host, port, sender, "").IsValid);
    }
}
