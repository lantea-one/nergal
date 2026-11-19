namespace Nergal.Core;

/// <summary>Policy semantics that a backend must preserve without lossy substitution.</summary>
/// <remarks>These are semantic requirements, not a list of command-line switches.</remarks>
public enum FirewallFeature
{
    /// <summary>Filter IPv4 and IPv6 host traffic.</summary>
    DualStackFiltering,
    /// <summary>Translate the destination address or port.</summary>
    DestinationNat,
    /// <summary>Translate the source to an explicitly selected address.</summary>
    ExplicitSourceNat,
    /// <summary>Match the original connection tuple after translation.</summary>
    OriginalConnectionTuple,
    /// <summary>Maintain independent rate-limit state for each source.</summary>
    PerSourceRateLimiting,
    /// <summary>Enforce rules in the bridge family.</summary>
    BridgeFiltering,
    /// <summary>Commit related table changes in one atomic kernel transaction.</summary>
    AtomicMultiTableCommit,
    /// <summary>Leave rules owned by unrelated components unchanged.</summary>
    ForeignTablePreservation,
}
