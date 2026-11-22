using Nergal.Core.Controller;
using Nergal.Nftables;

namespace Nergal.Web;

/// <summary>Live health summary for a registered managed host displayed on the overview dashboard.</summary>
public sealed class HostHealthSummary
{
    /// <summary>Gets the registered managed host record.</summary>
    public required ManagedHostRecord Host { get; init; }

    /// <summary>Gets whether the agent control endpoint responded cleanly.</summary>
    public required bool Reachable { get; init; }

    /// <summary>Gets drift or operational status label (e.g., <c>matched</c>, <c>drift</c>, <c>pending</c>, <c>unavailable</c>).</summary>
    public required string StateLabel { get; init; }

    /// <summary>Gets live reported baseline revision when reachable.</summary>
    public ulong? ReportedRevision { get; init; }

    /// <summary>Gets optional non-sensitive error code when unreachable or errored.</summary>
    public string? ErrorCode { get; init; }
}

/// <summary>View model for the controller overview and host fleet dashboard.</summary>
public sealed class FleetDashboardViewModel
{
    /// <summary>Gets canonical authenticated actor identifier.</summary>
    public required string ActorId { get; init; }

    /// <summary>Gets authenticated controller RBAC role.</summary>
    public required string ActorRole { get; init; }

    /// <summary>Gets whether the viewer holds administrative mutation privileges.</summary>
    public required bool CanMutate { get; init; }

    /// <summary>Gets all registered managed hosts.</summary>
    public required IReadOnlyList<ManagedHostRecord> Hosts { get; init; }

    /// <summary>Gets live per-host health summaries when queried.</summary>
    public required IReadOnlyList<HostHealthSummary> HostHealth { get; init; }

    /// <summary>Gets latest saved policy revision when present.</summary>
    public PolicyRevisionRecord? LatestRevision { get; init; }

    /// <summary>Gets decoded latest policy bundle when valid, for rule breakdown KPIs.</summary>
    public Core.Policy.FirewallPolicyBundle? LatestBundle { get; init; }

    /// <summary>Gets total count of persisted policy revisions.</summary>
    public int TotalRevisions { get; init; }

    /// <summary>Gets current persisted system settings snapshot.</summary>
    public required SystemSettingsSnapshot Settings { get; init; }

    /// <summary>Gets recent append-only audit events.</summary>
    public required IReadOnlyList<ControllerAuditEntry> RecentAudit { get; init; }

    /// <summary>Gets an optional non-sensitive validation message.</summary>
    public string? ErrorMessage { get; init; }
}

/// <summary>View model for the Administrator System Settings console.</summary>
public sealed class SystemSettingsViewModel
{
    /// <summary>Gets canonical authenticated actor identifier.</summary>
    public required string ActorId { get; init; }

    /// <summary>Gets authenticated controller RBAC role.</summary>
    public required string ActorRole { get; init; }

    /// <summary>Gets whether the viewer can save system settings.</summary>
    public required bool CanMutate { get; init; }

    /// <summary>Gets the current system settings snapshot.</summary>
    public required SystemSettingsSnapshot Settings { get; init; }

    /// <summary>Gets optional non-sensitive confirmation notice.</summary>
    public string? StatusMessage { get; init; }

    /// <summary>Gets optional non-sensitive error summary.</summary>
    public string? ErrorMessage { get; init; }

    /// <summary>Gets structured validation error codes when save failed.</summary>
    public required IReadOnlyList<string> ValidationErrors { get; init; }
}

/// <summary>View model for the typed policy bundle editor, compatibility report, and diff preview.</summary>
public sealed class PolicyEditorViewModel
{
    /// <summary>Gets authenticated controller RBAC role.</summary>
    public required string ActorRole { get; init; }

    /// <summary>Gets whether the viewer can persist policy revisions.</summary>
    public required bool CanMutate { get; init; }

    /// <summary>Gets selectable current library snapshots; selections are pinned to the displayed version.</summary>
    public IReadOnlyList<ReusableObjectVersion> LibraryObjects { get; init; } = [];

    /// <summary>Gets current draft bundle JSON text displayed in the editor.</summary>
    public required string BundleJson { get; init; }

    /// <summary>Gets optional revision summary note.</summary>
    public string? Summary { get; init; }

    /// <summary>Gets optional baseline revision identifier used for diff comparison.</summary>
    public ulong? CompareToRevision { get; init; }

    /// <summary>Gets optional active saved revision identifier.</summary>
    public ulong? SelectedRevision { get; init; }

    /// <summary>Gets persisted policy revisions ordered newest-first.</summary>
    public required IReadOnlyList<PolicyRevisionRecord> Revisions { get; init; }

    /// <summary>Gets the decoded policy bundle when valid, for structured summary rendering.</summary>
    public Core.Policy.FirewallPolicyBundle? Bundle { get; init; }

    /// <summary>Gets the native backend compatibility result when bundle parsed.</summary>
    public Core.BackendCompatibilityReport? Compatibility { get; init; }

    /// <summary>Gets deterministic compiled nftables candidate text when valid.</summary>
    public string? CandidateText { get; init; }

    /// <summary>Gets SHA-256 hex candidate digest when compiled cleanly.</summary>
    public string? CandidateDigest { get; init; }

    /// <summary>Gets unified diff against <see cref="CompareToRevision"/> or empty baseline.</summary>
    public string? UnifiedDiff { get; init; }

    /// <summary>Gets structured validation/compatibility diagnostics on failure.</summary>
    public required IReadOnlyList<PolicyDiagnostic> Diagnostics { get; init; }
}

/// <summary>View model for the append-only audit and revision history page.</summary>
public sealed class AuditHistoryViewModel
{
    /// <summary>Gets canonical actor identifier of the current viewer.</summary>
    public required string ActorId { get; init; }

    /// <summary>Gets authenticated controller RBAC role.</summary>
    public required string ActorRole { get; init; }

    /// <summary>Gets recorded append-only audit entries newest-first.</summary>
    public required IReadOnlyList<ControllerAuditEntry> Entries { get; init; }

    /// <summary>Gets persisted policy revisions newest-first.</summary>
    public required IReadOnlyList<PolicyRevisionRecord> Revisions { get; init; }
}

/// <summary>View model for two-phase confirmed policy application, live countdown status, and explicit rollback.</summary>
public sealed class ConfirmedApplyViewModel
{
    /// <summary>Gets canonical authenticated actor identifier.</summary>
    public required string ActorId { get; init; }

    /// <summary>Gets authenticated controller RBAC role.</summary>
    public required string ActorRole { get; init; }

    /// <summary>Gets whether the viewer can start, confirm, or roll back policy applies.</summary>
    public required bool CanMutate { get; init; }

    /// <summary>Gets all registered managed hosts.</summary>
    public required IReadOnlyList<ManagedHostRecord> Hosts { get; init; }

    /// <summary>Gets persisted policy revisions ordered newest-first.</summary>
    public required IReadOnlyList<PolicyRevisionRecord> Revisions { get; init; }

    /// <summary>Gets currently selected target host when registered.</summary>
    public ManagedHostRecord? SelectedHost { get; init; }

    /// <summary>Gets currently selected policy revision identifier.</summary>
    public ulong? SelectedRevision { get; init; }

    /// <summary>Gets live reply from querying the selected host agent control listener.</summary>
    public Core.Agent.AgentControlReply? LiveReply { get; init; }

    /// <summary>Gets recent append-only audit entries newest-first.</summary>
    public required IReadOnlyList<ControllerAuditEntry> RecentAudit { get; init; }

    /// <summary>Gets optional non-sensitive operator confirmation notice.</summary>
    public string? StatusMessage { get; init; }

    /// <summary>Gets optional non-sensitive validation or dispatch error message.</summary>
    public string? ErrorMessage { get; init; }
}
