using Nergal.Core.Deployment;

namespace Nergal.LocalState;

/// <summary>Verified immutable operation contents reconstructed from the transactional journal.</summary>
public sealed class JournalEntry
{
    internal JournalEntry(ApplySession session, string candidate, string rollback, JournalTime started)
    {
        Session = session;
        Candidate = candidate;
        Rollback = rollback;
        Started = started;
    }

    /// <summary>Gets the replayed session; evidence remains a trusted assertion, not live kernel proof.</summary>
    public ApplySession Session { get; }
    /// <summary>Gets the exact candidate artifact text whose digest is bound to the plan.</summary>
    public string Candidate { get; }
    /// <summary>Gets the exact rollback artifact text whose digest is bound to the plan.</summary>
    public string Rollback { get; }
    /// <summary>Gets the boot-scoped operation creation instant.</summary>
    public JournalTime Started { get; }
}

/// <summary>A stable local-journal denial or integrity failure without artifact contents.</summary>
public sealed class JournalException : Exception
{
    internal JournalException(string code) : base(code) => Code = code;
    /// <summary>Gets a stable diagnostic identifier; errors never silently repair or reset state.</summary>
    public string Code { get; }
}
