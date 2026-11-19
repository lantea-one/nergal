using System.Security.Cryptography;
using System.Text;

namespace Nergal.Core.Deployment;

/// <summary>SHA-256 identity of exact UTF-8 artifact bytes; not authorization or validation evidence.</summary>
public sealed record CandidateDigest
{
    /// <summary>Creates a digest from exactly 64 lowercase hexadecimal characters.</summary>
    /// <exception cref="ArgumentException">The supplied digest is not canonical SHA-256 text.</exception>
    public CandidateDigest(string value)
    {
        if (value is null || value.Length != 64 || value.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new ArgumentException("Expected 64 lowercase hexadecimal characters.", nameof(value));
        }

        Value = value;
    }

    /// <summary>Gets the canonical lowercase hexadecimal digest.</summary>
    public string Value { get; }

    /// <summary>Hashes exact UTF-8 text without newline, whitespace or Unicode normalization.</summary>
    /// <exception cref="ArgumentNullException">The text is null.</exception>
    /// <exception cref="EncoderFallbackException">The text contains malformed UTF-16.</exception>
    public static CandidateDigest FromText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var bytes = new UTF8Encoding(false, true).GetBytes(text);
        return new(Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
}
