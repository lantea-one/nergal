using Nergal.Core.Controller;

namespace Nergal.Core.Tests;

/// <summary>Source content is bounded exact UTF-8 and cannot turn a display name into a server path.</summary>
public sealed class NativeSourceContentTests
{
    /// <summary>Invalid display names are rejected before persistence or path interpretation.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("../source")]
    [InlineData("source\\file")]
    [InlineData("source\nname")]
    [InlineData(" padded ")]
    public void InvalidNamesAreRejected(string name) => Assert.Throws<ArgumentException>(() => new NativeSourceContent(name, "accept"));

    /// <summary>UTF-8 byte limits, malformed surrogate input and empty content fail explicitly.</summary>
    [Fact]
    public void InvalidEncodingAndBoundsAreRejected()
    {
        Assert.Throws<ArgumentException>(() => new NativeSourceContent("source", ""));
        Assert.Throws<ArgumentException>(() => new NativeSourceContent("source", "\ud800"));
        Assert.Throws<ArgumentException>(() => new NativeSourceContent("source", new string('é', 262_145)));
        Assert.Equal(524_288, new NativeSourceContent("source", new string('é', 262_144)).ByteLength);
        Assert.Throws<ArgumentNullException>(() => new NativeSourceContent("source", null!));
    }
}
