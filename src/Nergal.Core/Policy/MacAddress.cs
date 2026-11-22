using System.Globalization;

namespace Nergal.Core.Policy;

/// <summary>Strictly validated canonical lowercase 48-bit IEEE 802 MAC address (<c>xx:xx:xx:xx:xx:xx</c>).</summary>
public sealed class MacAddress : IEquatable<MacAddress>
{
    /// <summary>Parses and canonicalizes a colon-delimited 48-bit MAC address.</summary>
    /// <param name="value">Six two-digit hexadecimal octets separated by colons.</param>
    /// <exception cref="ArgumentException">The input is not a valid 48-bit colon-delimited MAC address.</exception>
    public MacAddress(string value)
    {
        if (!TryParseCanonical(value, out var canonical))
        {
            throw new ArgumentException("MAC address must be six colon-delimited hexadecimal octets (xx:xx:xx:xx:xx:xx).", nameof(value));
        }

        Value = canonical;
    }

    /// <summary>Gets the canonical lowercase colon-delimited MAC address.</summary>
    public string Value { get; }

    /// <summary>Attempts to parse and canonicalize a colon-delimited 48-bit MAC address.</summary>
    public static bool TryParse(string? value, out MacAddress? address)
    {
        if (TryParseCanonical(value, out var canonical))
        {
            address = new MacAddress(canonical);
            return true;
        }

        address = null;
        return false;
    }

    /// <inheritdoc />
    public bool Equals(MacAddress? other) => other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is MacAddress other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    /// <inheritdoc />
    public override string ToString() => Value;

    private static bool TryParseCanonical(string? raw, out string canonical)
    {
        canonical = "";
        if (raw is null || raw.Length != 17)
        {
            return false;
        }

        Span<char> buf = stackalloc char[17];
        for (var i = 0; i < 17; i++)
        {
            var c = raw[i];
            if (i % 3 == 2)
            {
                if (c != ':')
                {
                    return false;
                }

                buf[i] = ':';
            }
            else
            {
                if (c is >= '0' and <= '9')
                {
                    buf[i] = c;
                }
                else if (c is >= 'a' and <= 'f')
                {
                    buf[i] = c;
                }
                else if (c is >= 'A' and <= 'F')
                {
                    buf[i] = char.ToLower(c, CultureInfo.InvariantCulture);
                }
                else
                {
                    return false;
                }
            }
        }

        canonical = new string(buf);
        return true;
    }
}
