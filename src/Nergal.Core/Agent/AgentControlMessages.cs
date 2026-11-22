using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Core.Agent;

/// <summary>Typed agent control protocol operations; raw shell or nft commands are excluded.</summary>
public enum AgentControlCommand
{
    /// <summary>Query verified resource status and active confirmed-apply state.</summary>
    Status,
    /// <summary>Compile, check, arm independent watchdog, and atomically apply a typed policy candidate.</summary>
    PrepareApply,
    /// <summary>Commit an awaiting-confirmation candidate before its watchdog deadline expires.</summary>
    Confirm,
    /// <summary>Immediately restore the armed rollback baseline before the watchdog deadline expires.</summary>
    Rollback,
}

/// <summary>Typed outcomes returned by an authenticated agent control listener.</summary>
public enum AgentControlOutcome
{
    /// <summary>Verified bound resource state matches protected expectations.</summary>
    Matched,
    /// <summary>Observed native state differs from protected expectations.</summary>
    Drift,
    /// <summary>Journal exists without a bound resource receipt.</summary>
    Unbound,
    /// <summary>Candidate was compiled, validated, armed with a watchdog, and applied pending confirmation.</summary>
    AppliedPendingConfirmation,
    /// <summary>Active operation was confirmed and promoted to the current baseline.</summary>
    Confirmed,
    /// <summary>Rollback baseline was restored and verified against live native state.</summary>
    RolledBack,
    /// <summary>Candidate or transition failed deterministic validation before or during execution.</summary>
    Rejected,
    /// <summary>Another confirmed-apply operation or execution lock holds the resource.</summary>
    Busy,
    /// <summary>Agent state or kernel interface is currently unavailable.</summary>
    Unavailable,
    /// <summary>Peer failed authentication or authorization; no resource metadata is disclosed.</summary>
    Denied,
    /// <summary>Request payload was malformed or violated protocol schema bounds.</summary>
    InvalidRequest,
}

/// <summary>Immutable typed request sent over an authenticated agent control channel.</summary>
public sealed record AgentControlRequest
{
    /// <summary>Creates a validated control request for one protocol operation.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Command or confirmation timeout is outside supported bounds.</exception>
    /// <exception cref="ArgumentException">Fields do not match the selected <paramref name="command"/>.</exception>
    public AgentControlRequest(
        AgentControlCommand command,
        Guid? operationId = null,
        Guid? watchdogId = null,
        int? confirmationTimeoutSeconds = null,
        FilterPolicy? policy = null,
        FirewallPolicyBundle? bundle = null)
    {
        if (!Enum.IsDefined(command))
        {
            throw new ArgumentOutOfRangeException(nameof(command));
        }

        switch (command)
        {
            case AgentControlCommand.Status:
                if (operationId.HasValue || watchdogId.HasValue || confirmationTimeoutSeconds.HasValue || policy is not null || bundle is not null)
                {
                    throw new ArgumentException("Status request takes no operation parameters.");
                }

                break;

            case AgentControlCommand.PrepareApply:
                if (operationId is null || operationId.Value == Guid.Empty)
                {
                    throw new ArgumentException("PrepareApply requires a non-empty operation ID.", nameof(operationId));
                }

                if (watchdogId is { } prepWd && prepWd == Guid.Empty)
                {
                    throw new ArgumentException("Watchdog ID cannot be empty when supplied.", nameof(watchdogId));
                }

                if (confirmationTimeoutSeconds is null or < 1 or > 3600)
                {
                    throw new ArgumentOutOfRangeException(nameof(confirmationTimeoutSeconds));
                }

                if (policy is null && bundle is null)
                {
                    throw new ArgumentNullException(nameof(policy));
                }

                if (policy is not null && bundle is not null && !ReferenceEquals(policy, bundle.Filter))
                {
                    throw new ArgumentException("PrepareApply policy must match the supplied bundle filter.", nameof(policy));
                }

                policy ??= bundle!.Filter;
                break;

            case AgentControlCommand.Confirm:
            case AgentControlCommand.Rollback:
                if (operationId is null || operationId.Value == Guid.Empty)
                {
                    throw new ArgumentException("Operation ID is required.", nameof(operationId));
                }

                if (watchdogId is null || watchdogId.Value == Guid.Empty)
                {
                    throw new ArgumentException("Watchdog ID is required.", nameof(watchdogId));
                }

                if (confirmationTimeoutSeconds.HasValue || policy is not null || bundle is not null)
                {
                    throw new ArgumentException("Confirm/Rollback request cannot carry timeout, policy, or bundle fields.");
                }

                break;
        }

        Command = command;
        OperationId = operationId;
        WatchdogId = watchdogId;
        ConfirmationTimeoutSeconds = confirmationTimeoutSeconds;
        Policy = policy;
        Bundle = bundle;
    }

    /// <summary>Gets the requested control operation.</summary>
    public AgentControlCommand Command { get; }

    /// <summary>Gets the operation identifier for PrepareApply, Confirm, or Rollback.</summary>
    public Guid? OperationId { get; }

    /// <summary>Gets the watchdog identifier (optional on PrepareApply, required on Confirm/Rollback).</summary>
    public Guid? WatchdogId { get; }

    /// <summary>Gets the confirmation window in seconds for PrepareApply.</summary>
    public int? ConfirmationTimeoutSeconds { get; }

    /// <summary>Gets the typed filter policy snapshot for PrepareApply.</summary>
    public FilterPolicy? Policy { get; }

    /// <summary>Gets the optional multi-table policy bundle for PrepareApply (including filter, NAT, and bridge tables).</summary>
    public FirewallPolicyBundle? Bundle { get; }

    /// <summary>Resolves the effective multi-table bundle for <see cref="AgentControlCommand.PrepareApply"/>.</summary>
    public FirewallPolicyBundle ResolveBundle() =>
        Bundle ?? new FirewallPolicyBundle(FirewallPolicyBundle.CurrentSchemaVersion, Policy ?? throw new InvalidOperationException("Request carries no policy."));
}

/// <summary>Immutable typed reply returned by an authenticated agent control listener.</summary>
public sealed record AgentControlReply
{
    /// <summary>Constructs a bounded control reply without exposing raw host text or paths.</summary>
    /// <exception cref="ArgumentOutOfRangeException">Enum or numeric field is out of range.</exception>
    /// <exception cref="ArgumentException">Error code format or field combination is invalid.</exception>
    public AgentControlReply(
        AgentControlOutcome outcome,
        ulong? revision = null,
        Guid? operationId = null,
        Guid? watchdogId = null,
        ApplyPhase? activePhase = null,
        int? remainingSeconds = null,
        string? candidateDigest = null,
        string? errorCode = null)
    {
        if (!Enum.IsDefined(outcome))
        {
            throw new ArgumentOutOfRangeException(nameof(outcome));
        }

        if (activePhase is { } phase && !Enum.IsDefined(phase))
        {
            throw new ArgumentOutOfRangeException(nameof(activePhase));
        }

        if (revision is 0)
        {
            throw new ArgumentOutOfRangeException(nameof(revision));
        }

        if (remainingSeconds is < 0 or > 3600)
        {
            throw new ArgumentOutOfRangeException(nameof(remainingSeconds));
        }

        if (operationId is { } op && op == Guid.Empty)
        {
            throw new ArgumentException("Operation ID cannot be empty.", nameof(operationId));
        }

        if (watchdogId is { } wd && wd == Guid.Empty)
        {
            throw new ArgumentException("Watchdog ID cannot be empty.", nameof(watchdogId));
        }

        if (candidateDigest is not null && !IsHexSha256(candidateDigest))
        {
            throw new ArgumentException("Candidate digest must be 64 lowercase hex characters.", nameof(candidateDigest));
        }

        if (errorCode is not null && !IsSafeCode(errorCode))
        {
            throw new ArgumentException("Error code must be a bounded ASCII identifier.", nameof(errorCode));
        }

        if (outcome is AgentControlOutcome.Denied or AgentControlOutcome.InvalidRequest &&
            (revision.HasValue || operationId.HasValue || watchdogId.HasValue || activePhase.HasValue ||
             remainingSeconds.HasValue || candidateDigest is not null || errorCode is not null))
        {
            throw new ArgumentException("Denied and InvalidRequest replies cannot disclose resource metadata.");
        }

        Outcome = outcome;
        Revision = revision;
        OperationId = operationId;
        WatchdogId = watchdogId;
        ActivePhase = activePhase;
        RemainingSeconds = remainingSeconds;
        CandidateDigest = candidateDigest;
        ErrorCode = errorCode;
    }

    /// <summary>Gets the operation classification.</summary>
    public AgentControlOutcome Outcome { get; }

    /// <summary>Gets the confirmed resource revision when available.</summary>
    public ulong? Revision { get; }

    /// <summary>Gets the active or completed operation identifier when applicable.</summary>
    public Guid? OperationId { get; }

    /// <summary>Gets the independent watchdog identifier when armed or active.</summary>
    public Guid? WatchdogId { get; }

    /// <summary>Gets the active journal phase when an operation is present.</summary>
    public ApplyPhase? ActivePhase { get; }

    /// <summary>Gets remaining confirmation seconds when awaiting confirmation.</summary>
    public int? RemainingSeconds { get; }

    /// <summary>Gets the SHA-256 hex digest of the compiled native candidate when present.</summary>
    public string? CandidateDigest { get; }

    /// <summary>Gets a bounded stable failure identifier without native stderr or host paths.</summary>
    public string? ErrorCode { get; }

    internal static bool IsHexSha256(string value)
    {
        if (value.Length != 64)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (ch is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    internal static bool IsSafeCode(string value)
    {
        if (value.Length is < 1 or > 64)
        {
            return false;
        }

        foreach (var ch in value)
        {
            if (ch is not ((>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-'))
            {
                return false;
            }
        }

        return true;
    }
}
