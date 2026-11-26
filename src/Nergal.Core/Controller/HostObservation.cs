namespace Nergal.Core.Controller;

/// <summary>Controller classification of an authenticated agent status reply.</summary>
public enum HostObservationState
{
    /// <summary>The agent reports a match with its protected baseline.</summary>
    Matched = 1,
    /// <summary>The agent reports observed drift.</summary>
    Drift = 2,
    /// <summary>The agent has no bound baseline receipt.</summary>
    Missing = 3,
    /// <summary>A host change is in progress.</summary>
    Pending = 4,
    /// <summary>The agent replied without one of the other classifications.</summary>
    Online = 5,
}

/// <summary>The latest authenticated status observation retained for one registered host.</summary>
/// <param name="HostId">Controller registration identity.</param>
/// <param name="State">Classification of the authenticated status reply.</param>
/// <param name="ReportedRevision">Revision in the reply, when supplied by the agent.</param>
/// <param name="ObservedAtUtc">When the controller received the reply, in UTC.</param>
public sealed record HostObservation(Guid HostId, HostObservationState State, ulong? ReportedRevision, DateTimeOffset ObservedAtUtc);
