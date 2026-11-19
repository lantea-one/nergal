using System.Text;
using Nergal.Admin;

namespace Nergal.LocalState.Tests;

/// <summary>Checks the offline provisioning input framing independently of the existing Identity password policy.</summary>
public sealed class PasswordInputTests
{
    /// <summary>Only a final line delimiter is removed. Whitespace and Unicode scalar sequences remain exact.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("\r\n")]
    public async Task Pipe_PreservesPasswordExactly(string delimiter)
    {
        const string password = " synthetic e\u0301 fixture phrase ";
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(password + delimiter));
        Assert.Equal(password, await PasswordInput.ReadPipeAsync(input));
    }

    /// <summary>The largest possible 128-scalar UTF-8 password can include CRLF framing.</summary>
    [Fact]
    public async Task Pipe_AcceptsFullUnicodeBoundary()
    {
        var password = string.Concat(Enumerable.Repeat("\U0001F680", 128));
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(password + "\r\n"));
        Assert.Equal(password, await PasswordInput.ReadPipeAsync(input));
    }

    /// <summary>Multiple records, malformed UTF-8 and excess bytes cannot become truncated or normalized credentials.</summary>
    [Fact]
    public async Task Pipe_RejectsAmbiguousMalformedAndOversizedInput()
    {
        using var multiple = new MemoryStream("first\nsecond\n"u8.ToArray());
        using var badEncoding = new MemoryStream([0xc0, 0xaf]);
        using var oversize = new MemoryStream(new byte[515]);
        await Assert.ThrowsAsync<InvalidDataException>(() => PasswordInput.ReadPipeAsync(multiple));
        await Assert.ThrowsAsync<DecoderFallbackException>(() => PasswordInput.ReadPipeAsync(badEncoding));
        await Assert.ThrowsAsync<InvalidDataException>(() => PasswordInput.ReadPipeAsync(oversize));
    }
}
