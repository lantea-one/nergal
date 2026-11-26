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
    /// <summary>Maintain independent rate-limit state for each destination.</summary>
    PerDestinationRateLimiting,
    /// <summary>Raw reverse-path filtering, explicit MAC pinning, negation, rejection, and MSS modification.</summary>
    RouterFiltering,
    /// <summary>Interface-derived source translation and ordered NAT return exemptions.</summary>
    MasqueradeAndNatExemptions,
    /// <summary>Independent early filter tables and extended bridge jump/return control flow.</summary>
    AuxiliaryFiltering,
    /// <summary>Refresh dynamic meter entry expiry on matching packets rather than only on creation.</summary>
    MeterEntryTimeoutRefresh,
    /// <summary>Count packets and bytes inline immediately before a filter verdict.</summary>
    InlineFilterCounters,
    /// <summary>Translate locally generated traffic in the destination NAT output hook.</summary>
    OutputDestinationNat,
}
