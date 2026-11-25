namespace Nergal.Web;

/// <summary>A read-only destination; choosing guidance never dispatches or confirms an agent operation.</summary>
public enum DashboardDestination
{
    /// <summary>Inspect or author policy intent.</summary>
    Policies,
    /// <summary>Inspect or register host connections.</summary>
    Hosts,
    /// <summary>Inspect the existing confirmed-apply workflow.</summary>
    Apply,
    /// <summary>Inspect attributed history.</summary>
    Audit,
}

/// <summary>Plain-language guidance derived from current state, without persisted wizard flags or apply authority.</summary>
public sealed record DashboardNextAction(string Heading, string Description, string Label, DashboardDestination Destination, Guid? HostId = null);

/// <summary>Prioritizes pending/recovery states and separates saved intent from observed host state.</summary>
public static class DashboardGuidance
{
    /// <summary>Chooses one useful navigation action; unknown or missing observations never imply a healthy firewall.</summary>
    public static DashboardNextAction Describe(bool canMutate, bool controlEnabled, bool hasPolicy, int hostCount, IReadOnlyList<HostHealthSummary> health)
    {
        ArgumentNullException.ThrowIfNull(health);
        var pending = health.FirstOrDefault(h => h.StateLabel == "pending");
        if (pending is not null)
        {
            return new("A change is waiting for confirmation", "Inspect the pending operation and its deadline. The agent's local watchdog decides rollback independently of this page.",
                canMutate ? "Review pending change" : "Inspect pending change", DashboardDestination.Apply, pending.Host.Id);
        }
        var recovery = health.FirstOrDefault(h => h.StateLabel is "drift" or "missing");
        if (recovery is not null)
        {
            return new("A host needs attention", "Observed firewall state differs from its protected baseline, or owned resources are missing. Inspect recovery status before making another change.",
                "Inspect host state", DashboardDestination.Apply, recovery.Host.Id);
        }
        if (!canMutate)
        {
            return new("Read-only administration", "You can inspect policy revisions, host status and audit history. An administrator must save configuration changes and manage connections.",
                hasPolicy ? "Inspect saved policy" : "Inspect activity", hasPolicy ? DashboardDestination.Policies : DashboardDestination.Audit);
        }
        if (!hasPolicy)
        {
            return new("Start with your firewall policy", "Create rules in Firewall, or import an existing nftables.conf. You can prepare and review configuration before connecting a host.",
                "Create a policy", DashboardDestination.Policies);
        }
        if (hostCount == 0)
        {
            return new("Connect a firewall host", "Your policy is saved. Register an already enrolled agent to inspect its state and prepare a reviewed change.", "Connect a host", DashboardDestination.Hosts);
        }
        if (!controlEnabled || health.Count != hostCount || health.Any(h => !h.Reachable || h.StateLabel is not ("matched" or "online")))
        {
            return new("Check host connections", "Live status is unavailable, unqueried or incomplete. This does not establish that a host is offline. Review its connection and agent configuration.", "Inspect connections", DashboardDestination.Hosts);
        }
        return new("Review your saved configuration", "A matching agent baseline does not mean the latest controller policy is applied. Review the selected revision and each host before starting a confirmed change.", "Review policy", DashboardDestination.Policies);
    }
}
