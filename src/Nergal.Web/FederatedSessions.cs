using System.Security.Cryptography;
using Nergal.Identity;
using Nergal.Core.Identity;

namespace Nergal.Web;

// A cookie must match a live registration in this process. Restart or logout
// invalidates replay. Membership and the absolute deadline never renew here.
internal sealed class FederatedSessions(TimeProvider clock)
{
    private readonly Dictionary<string, FederatedAdministrator> active = new(StringComparer.Ordinal);
    private readonly object gate = new();

    internal string Register(FederatedAdministrator administrator)
    {
        if (string.IsNullOrWhiteSpace(administrator.Issuer) || string.IsNullOrWhiteSpace(administrator.Subject) ||
            !NergalRoles.IsDefined(administrator.Role)) { throw new InvalidOperationException("Federated session unavailable."); }
        lock (gate)
        {
            var now = clock.GetUtcNow();
            foreach (var entry in active.Where(entry => entry.Value.Expires <= now).ToArray()) { active.Remove(entry.Key); }
            if (active.Count >= 1024 || administrator.Expires <= now || administrator.Expires - now > TimeSpan.FromMinutes(15))
            { throw new InvalidOperationException("Federated session unavailable."); }
            var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            active.Add(id, administrator);
            return id;
        }
    }

    internal bool IsCurrent(string? id, string? issuer, string? subject, string? role = null)
    {
        lock (gate)
        {
            if (id is null || string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject) ||
                !active.TryGetValue(id, out var identity)) { return false; }
            if (identity.Expires <= clock.GetUtcNow()) { active.Remove(id); return false; }
            return identity.Issuer == issuer &&
                   identity.Subject == subject &&
                   (role is null || string.Equals(identity.Role, role, StringComparison.Ordinal));
        }
    }

    internal void Revoke(string? id)
    {
        lock (gate) { if (id is not null) { active.Remove(id); } }
    }
}
