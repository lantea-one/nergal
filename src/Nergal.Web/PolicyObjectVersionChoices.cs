using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;

namespace Nergal.Web;

/// <summary>Loads one explicitly requested immutable list history, keeping every other list at its current version.</summary>
[SupportedOSPlatform("linux")]
internal static class PolicyObjectVersionChoices
{
    /// <summary>Returns defensive, ordered selector choices without saving versions, revisions or audit events.</summary>
    /// <remarks>Only one bounded history is loaded; compilation and application never call this UI helper.</remarks>
    /// <exception cref="ArgumentException">The list does not exist.</exception>
    internal static IReadOnlyList<ReusableObjectVersion> Load(ControllerStateStore store, Guid objectId)
    {
        ArgumentNullException.ThrowIfNull(store);
        var history = store.ListReusableObjectVersions(objectId);
        if (history.Count == 0) { throw new ArgumentException("object.referenceNotFound", nameof(objectId)); }
        return Array.AsReadOnly(store.ListReusableObjects().Where(o => o.Id != objectId).Concat(history)
            .OrderBy(o => o.Content.Name, StringComparer.Ordinal).ThenByDescending(o => o.Version).ToArray());
    }
}
