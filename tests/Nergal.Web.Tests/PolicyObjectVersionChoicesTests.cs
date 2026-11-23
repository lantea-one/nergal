using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Browsing history loads only the requested list's old snapshots without mutating canonical state.</summary>
[SupportedOSPlatform("linux")]
public sealed class PolicyObjectVersionChoicesTests
{
    /// <summary>One history is expanded; another list retains its latest version only, with immutable choice snapshots.</summary>
    [Fact]
    public void Load_RetainsOtherCurrentVersionsAndCreatesNoState()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-choices-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path));
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
            ReusableObjectVersion Save(Guid? id, int expected, string name, string port) =>
                store.SaveReusableObject(id, expected, new(name, ReusableObjectKind.Port, "Synthetic", [port]), actor, NergalRoles.Administrator);
            var ports = Save(null, 0, "ports", "443"); Save(ports.Id, 1, "ports", "8443");
            var other = Save(null, 0, "other", "80"); Save(other.Id, 1, "other", "8080");
            var audit = store.ListAuditEntries().ToArray();
            var choices = PolicyObjectVersionChoices.Load(store, ports.Id);
            Assert.Equal(new[] { ("other", 2), ("ports", 2), ("ports", 1) }, choices.Select(o => (o.Content.Name, o.Version)));
            Assert.Equal("443", Assert.Single(choices.Single(o => o.Id == ports.Id && o.Version == 1).Content.Entries));
            Assert.Throws<NotSupportedException>(() => ((IList<ReusableObjectVersion>)choices).Clear());
            Save(ports.Id, 2, "ports", "9443");
            Assert.Equal(new[] { 2, 1 }, choices.Where(o => o.Id == ports.Id).Select(o => o.Version));
            Assert.Equal(3, store.ReadReusableObject(ports.Id)!.Version);
            Assert.Equal(audit.Length + 1, store.ListAuditEntries().Count);
            Assert.Empty(store.ListPolicyRevisions());
            Assert.Equal("object.referenceNotFound", Assert.Throws<ArgumentException>(() => PolicyObjectVersionChoices.Load(store, Guid.Empty)).Message.Split(' ')[0]);
            Assert.Throws<ArgumentNullException>(() => PolicyObjectVersionChoices.Load(null!, ports.Id));
        }
        finally { Directory.Delete(path, true); }
    }
}
