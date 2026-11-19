namespace Nergal.Core.Deployment;

/// <summary>Expected durable ownership of the sole managed resource on an enrolled agent.</summary>
/// <remarks>This value is an assertion, not proof of ownership; the future agent must verify its journal and kernel state.</remarks>
public sealed record ResourceOwnership
{
    /// <summary>Creates an explicit ownership/revision assertion.</summary>
    /// <param name="agentId">Nonempty enrolled agent UUID; not a host address.</param>
    /// <param name="ownerId">Nonempty enrolled owner UUID for the agent's sole managed resource.</param>
    /// <param name="revision">Nonzero last-confirmed revision.</param>
    /// <exception cref="ArgumentException">An identity is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The revision is zero.</exception>
    public ResourceOwnership(Guid agentId, Guid ownerId, ulong revision)
    {
        if (agentId == Guid.Empty)
        {
            throw new ArgumentException("Agent identity is required.", nameof(agentId));
        }

        if (ownerId == Guid.Empty)
        {
            throw new ArgumentException("Owner identity is required.", nameof(ownerId));
        }

        if (revision == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        AgentId = agentId;
        OwnerId = ownerId;
        Revision = revision;
    }

    /// <summary>Gets the enrolled agent identity, bound to the resource by a future protected store.</summary>
    public Guid AgentId { get; }
    /// <summary>Gets the enrolled resource owner's identity.</summary>
    public Guid OwnerId { get; }
    /// <summary>Gets the expected last-confirmed revision.</summary>
    public ulong Revision { get; }
}

/// <summary>Immutable content and ownership binding for one proposed confirmed apply.</summary>
public sealed record ApplyPlan
{
    /// <summary>Creates a plan; does not validate kernel state, authorize callers or arm rollback.</summary>
    /// <param name="operationId">Nonempty operation UUID, unique in the future durable journal.</param>
    /// <param name="ownership">Expected ownership and last-confirmed revision.</param>
    /// <param name="candidate">Exact candidate artifact identity.</param>
    /// <param name="rollback">Exact restorable owned-state artifact identity.</param>
    /// <param name="confirmationTimeout">Positive arming-to-deadline duration, at most one hour.</param>
    /// <exception cref="ArgumentNullException">Ownership or a digest is null.</exception>
    /// <exception cref="ArgumentException">The operation is empty or candidate and rollback content are identical.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The revision is exhausted, or timeout is not positive or exceeds one hour.</exception>
    public ApplyPlan(Guid operationId, ResourceOwnership ownership, CandidateDigest candidate,
        CandidateDigest rollback, TimeSpan confirmationTimeout)
    {
        if (operationId == Guid.Empty)
        {
            throw new ArgumentException("Operation identity is required.", nameof(operationId));
        }

        ArgumentNullException.ThrowIfNull(ownership);
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(rollback);
        if (candidate == rollback)
        {
            throw new ArgumentException("Candidate and rollback artifacts must differ.", nameof(candidate));
        }

        if (confirmationTimeout <= TimeSpan.Zero || confirmationTimeout > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(confirmationTimeout));
        }

        if (ownership.Revision == ulong.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(ownership), "Revision exhausted.");
        }

        OperationId = operationId;
        Ownership = ownership;
        Candidate = candidate;
        Rollback = rollback;
        ConfirmationTimeout = confirmationTimeout;
    }

    /// <summary>Gets the unique operation identity; durable replay prevention is a future agent responsibility.</summary>
    public Guid OperationId { get; }
    /// <summary>Gets expected enrolled ownership and last-confirmed revision.</summary>
    public ResourceOwnership Ownership { get; }
    /// <summary>Gets the exact proposed candidate identity.</summary>
    public CandidateDigest Candidate { get; }
    /// <summary>Gets the exact restorable owned-state artifact identity.</summary>
    public CandidateDigest Rollback { get; }
    /// <summary>Gets the duration from watchdog arming to the exclusive confirmation deadline.</summary>
    public TimeSpan ConfirmationTimeout { get; }
    /// <summary>Gets the revision that may be persisted only after durable confirmation.</summary>
    public ulong ConfirmedRevision => Ownership.Revision + 1;
}
