namespace Nergal.Core.Policy;

/// <summary>One exact Linux interface name or a nonempty name prefix matched by a terminal nftables wildcard.</summary>
public sealed record InterfaceNamePattern
{
    private InterfaceNamePattern(string name, bool isPrefix) => (Name, IsPrefix) = (name, isPrefix);

    /// <summary>The validated literal portion, without quoting or wildcard syntax.</summary>
    public string Name { get; }

    /// <summary>Whether this pattern matches all interfaces beginning with the literal portion.</summary>
    public bool IsPrefix { get; }

    /// <summary>Canonical policy spelling of the match.</summary>
    public string Value => IsPrefix ? Name + "*" : Name;

    /// <summary>Accepts the interface name alphabet and at most one terminal wildcard.</summary>
    public static InterfaceNamePattern? Parse(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 15) { return null; }
        var prefix = value.EndsWith('*');
        var name = prefix ? value[..^1] : value;
        return FilterPolicyValidation.IsValidInterfaceName(name) ? new(name, prefix) : null;
    }
}

/// <summary>A single name predicate with at most 64 nonoverlapping exact names or prefixes.</summary>
public sealed class InterfaceNameSelector : IEquatable<InterfaceNameSelector>
{
    private InterfaceNameSelector(InterfaceNamePattern[] patterns) => Patterns = Array.AsReadOnly(patterns);

    /// <summary>Patterns in ordinal order, snapshotted before publication.</summary>
    public IReadOnlyList<InterfaceNamePattern> Patterns { get; }

    /// <summary>Validates all members and rejects overlaps that nftables could fold or reject.</summary>
    public static InterfaceNameSelector? Create(IEnumerable<string?> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var patterns = new List<InterfaceNamePattern>();
        foreach (var value in values)
        {
            var pattern = InterfaceNamePattern.Parse(value);
            if (pattern is null || patterns.Count == 64 || patterns.Any(other =>
                other == pattern || other.IsPrefix && pattern.Name.StartsWith(other.Name, StringComparison.Ordinal) ||
                pattern.IsPrefix && other.Name.StartsWith(pattern.Name, StringComparison.Ordinal)))
            {
                return null;
            }
            patterns.Add(pattern);
        }
        return patterns.Count == 0 ? null : new(patterns.OrderBy(p => p.Value, StringComparer.Ordinal).ToArray());
    }

    /// <inheritdoc/>
    public bool Equals(InterfaceNameSelector? other) => other is not null && Patterns.SequenceEqual(other.Patterns);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as InterfaceNameSelector);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var pattern in Patterns) { hash.Add(pattern); }
        return hash.ToHashCode();
    }
}
