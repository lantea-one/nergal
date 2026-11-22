using System.Security.Cryptography;
using System.Text;

namespace Nergal.Core.Controller;

/// <summary>Validated immutable native source content; it is never an executable policy or an ownership assertion.</summary>
public sealed record NativeSourceContent
{
    /// <summary>Maximum exact UTF-8 source size in bytes.</summary>
    public const int MaximumBytes = 524_288;
    /// <summary>Creates bounded named content without parsing, normalizing or executing its native syntax.</summary>
    /// <exception cref="ArgumentException">Name, encoding or content size is invalid.</exception>
    /// <exception cref="ArgumentNullException">Text is null.</exception>
    public NativeSourceContent(string name, string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (string.IsNullOrWhiteSpace(name) || name.Length > 120 || name != name.Trim() || name.Any(c => char.IsControl(c) || c is '/' or '\\'))
        { throw new ArgumentException("source.nameInvalid", nameof(name)); }
        if (text.Length is 0 or > MaximumBytes) { throw new ArgumentException("source.sizeInvalid", nameof(text)); }
        byte[] bytes;
        try
        {
            var encoding = new UTF8Encoding(false, true);
            if (encoding.GetByteCount(text) > MaximumBytes) { throw new ArgumentException("source.sizeInvalid", nameof(text)); }
            bytes = encoding.GetBytes(text);
        }
        catch (EncoderFallbackException) { throw new ArgumentException("source.encodingInvalid", nameof(text)); }
        if (bytes.Length is 0 or > MaximumBytes) { throw new ArgumentException("source.sizeInvalid", nameof(text)); }
        Name = name; Text = text; ByteLength = bytes.Length; Digest = Convert.ToHexStringLower(SHA256.HashData(bytes));
    }
    /// <summary>Gets the operator-supplied display name, never a server path.</summary>
    public string Name { get; }
    /// <summary>Gets exact decoded UTF-8, including any BOM and original line endings.</summary>
    public string Text { get; }
    /// <summary>Gets the original UTF-8 byte length.</summary>
    public int ByteLength { get; }
    /// <summary>Gets the SHA-256 of exact UTF-8 bytes.</summary>
    public string Digest { get; }
}

/// <summary>Persisted source metadata returned without loading private source contents.</summary>
public sealed record NativeSourceSummary(Guid Id, string Name, string Digest, int ByteLength, string ImportedByActor, DateTimeOffset ImportedAtUtc);

/// <summary>An immutable database snapshot and its validated exact contents.</summary>
public sealed record NativeSourceSnapshot(NativeSourceSummary Summary, NativeSourceContent Content);
