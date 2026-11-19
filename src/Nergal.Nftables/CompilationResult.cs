using Nergal.Core.Deployment;

namespace Nergal.Nftables;

/// <summary>A stable machine-readable error code and property path; contains no policy text.</summary>
/// <param name="Code">Stable validation failure identifier.</param>
/// <param name="Path">Property path, using zero-based rule indexes.</param>
public sealed record PolicyDiagnostic(string Code, string Path);

/// <summary>Either a complete candidate or diagnostics, never a partial candidate.</summary>
public sealed class CompilationResult
{
    internal CompilationResult(string? candidate, IEnumerable<PolicyDiagnostic> diagnostics)
    {
        Candidate = candidate;
        Digest = candidate is null ? null : CandidateDigest.FromText(candidate);
        Diagnostics = Array.AsReadOnly(diagnostics.ToArray());
    }

    /// <summary>Gets native text for create-only provisioning; null when validation failed.</summary>
    public string? Candidate { get; }

    /// <summary>Gets the SHA-256 identity of exact candidate UTF-8 bytes, or null on failure.</summary>
    /// <remarks>A digest is not authorization or native kernel validation.</remarks>
    public CandidateDigest? Digest { get; }

    /// <summary>Gets diagnostics in schema/property/rule order.</summary>
    public IReadOnlyList<PolicyDiagnostic> Diagnostics { get; }

    /// <summary>Gets whether a complete candidate exists; this does not establish kernel validity.</summary>
    public bool IsSuccess => Candidate is not null;
}
