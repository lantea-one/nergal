namespace Nergal.Core.Agent;

/// <summary>Read-only local resource classifications; none grants permission to change a firewall.</summary>
public enum AgentStatusOutcome
{
    /// <summary>All protected expected resource bindings matched.</summary>
    Matched,
    /// <summary>Observed state differs from protected expected state.</summary>
    Drift,
    /// <summary>No explicit expected resource receipt is bound.</summary>
    Unbound,
    /// <summary>Trusted status cannot currently be established.</summary>
    Unavailable,
    /// <summary>The local peer is not authorized; no resource metadata is disclosed.</summary>
    Denied,
    /// <summary>The request is unsupported or malformed; no provider was invoked.</summary>
    InvalidRequest,
}

/// <summary>Immutable bounded status response, containing no policy, native text or caller-supplied diagnostics.</summary>
public sealed record AgentStatusReply
{
    /// <summary>Creates a classification with a revision only for matched/drift/unbound resource status.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Outcome is unknown or a required revision is missing/zero.</exception>
    /// <exception cref="ArgumentException">An error/denial reply includes resource metadata.</exception>
    public AgentStatusReply(AgentStatusOutcome outcome, ulong? revision = null)
    {
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        var resourceStatus = outcome is AgentStatusOutcome.Matched or AgentStatusOutcome.Drift or AgentStatusOutcome.Unbound;
        if (resourceStatus && (revision is null or 0))
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (!resourceStatus && revision.HasValue)
        {
            throw new ArgumentException("Non-resource replies cannot disclose a revision.", nameof(revision));
        }

        Outcome = outcome;
        Revision = revision;
    }
    /// <summary>Gets the explicit classification.</summary>
    public AgentStatusOutcome Outcome { get; }
    /// <summary>Gets a nonzero last-confirmed revision for resource status, otherwise null.</summary>
    public ulong? Revision { get; }
}
