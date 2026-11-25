namespace Nergal.Core.Controller;

/// <summary>A committed controller settings version and the unique token required to replace it.</summary>
/// <param name="Version">Monotonic settings version in the current database history, starting at zero.</param>
/// <param name="FormToken">Opaque identity of the committed value, unique even across divergent restores.</param>
/// <param name="Settings">The settings snapshot associated with this version.</param>
/// <param name="UpdatedAtUtc">Commit instant in UTC, or null for the initial defaults.</param>
/// <param name="UpdatedByActor">Canonical Administrator identity, or null for the initial defaults.</param>
public sealed record SystemSettingsVersion(long Version, string FormToken, SystemSettingsSnapshot Settings,
    DateTimeOffset? UpdatedAtUtc, string? UpdatedByActor)
{
    /// <summary>Checks a form token without accepting whitespace or alternate representations.</summary>
    public static bool IsValidFormToken(string? token) =>
        Guid.TryParseExact(token, "N", out var value) && value != Guid.Empty && token == value.ToString("N");
}
