using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Real database history prevents silent shared-list changes and lost concurrent edits.</summary>
[SupportedOSPlatform("linux")]
public sealed class ReusableObjectStoreTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static ReusableObjectContent Content(string description = "Synthetic") => new("clients", ReusableObjectKind.Ipv4, description, ["192.0.2.10"]);

    /// <summary>Reopen retains stable identities and every old version without changing policy revisions.</summary>
    [Fact]
    public void Save_PreservesHistoryUtcAndAuditAcrossReopen()
    {
        WithStore((store, path) =>
        {
            var first = store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator);
            var second = store.SaveReusableObject(first.Id, 1, Content("Updated"), Actor, NergalRoles.Administrator);
            var reopened = ControllerStateStore.Open(new(path));
            Assert.Equal(first.Digest, reopened.ReadReusableObject(first.Id, 1)!.Digest);
            Assert.Equal("Synthetic", reopened.ReadReusableObject(first.Id, 1)!.Content.Description);
            Assert.Equal(second.Digest, reopened.ReadReusableObject(first.Id)!.Digest);
            Assert.Equal(new[] { 2, 1 }, reopened.ListReusableObjectVersions(first.Id).Select(v => v.Version));
            Assert.Equal(TimeSpan.Zero, second.UpdatedAtUtc.Offset);
            Assert.Single(reopened.ListReusableObjects()); Assert.Empty(reopened.ListPolicyRevisions());
            Assert.Equal(new[] { "object.version", "object.create" }, reopened.ListAuditEntries().Select(a => a.Action));
            Assert.All(reopened.ListAuditEntries(), a => Assert.Equal(Actor, a.ActorId));
            Assert.Null(reopened.ReadReusableObject(first.Id, 3));
        });
    }

    /// <summary>Stale edits, duplicate names, identity changes and denied roles leave the current version intact.</summary>
    [Fact]
    public void Save_RejectsConflictsAndDeniedActorsAtomically()
    {
        WithStore((store, _) =>
        {
            var first = store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator);
            Assert.Equal("object.staleVersion", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(first.Id, 0, Content("stale"), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal("object.duplicateName", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal("object.identityImmutable", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(first.Id, 1, new("renamed", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal("object.identityImmutable", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(first.Id, 1, new("clients", ReusableObjectKind.Port, "", ["443"]), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal("rbac.denied", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(first.Id, 1, Content(), Actor, NergalRoles.Auditor)).Code);
            Assert.Equal("object.notFound", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(Guid.NewGuid(), 1, Content(), Actor, NergalRoles.Administrator)).Code);
            Assert.Single(store.ListAuditEntries()); Assert.Equal(first.Digest, store.ReadReusableObject(first.Id)!.Digest);
        });
    }

    /// <summary>Audit insertion failure rolls back both a new identity and a new version.</summary>
    [Fact]
    public void Save_AuditFailureRollsBackObjects()
    {
        WithStore((store, path) =>
        {
            Sql(path, "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;");
            Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator));
            Assert.Empty(store.ListReusableObjects()); Assert.Empty(store.ListAuditEntries());
        });
    }

    /// <summary>Immutable table definitions and content digests prevent trusting forged history.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Read_DeniesTamperedProtectionOrContent(bool changeContent)
    {
        WithStore((store, path) =>
        {
            var saved = store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator);
            Assert.Throws<SqliteException>(() => Sql(path, "UPDATE reusable_object_versions SET description='changed';"));
            Assert.Throws<SqliteException>(() => Sql(path, "DELETE FROM reusable_objects;"));
            if (changeContent)
            {
                Sql(path, "DROP TRIGGER reusable_object_versions_no_update; UPDATE reusable_object_versions SET content_sha256='bad'; CREATE TRIGGER reusable_object_versions_no_update BEFORE UPDATE ON reusable_object_versions BEGIN SELECT RAISE(ABORT, 'object history is immutable'); END;");
                Assert.Equal("object.corrupt", Assert.Throws<ControllerStateException>(() => store.ReadReusableObject(saved.Id)).Code);
            }
            else
            {
                Sql(path, "DROP TRIGGER reusable_object_versions_no_update; CREATE TRIGGER reusable_object_versions_no_update BEFORE UPDATE ON reusable_object_versions BEGIN SELECT 1; END;");
                Assert.Equal("object.schemaInvalid", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path))).Code);
            }
        });
    }

    /// <summary>A full history rejects another version without leaving an unmatched audit entry.</summary>
    [Fact]
    public void Save_EnforcesVersionCapacity()
    {
        WithStore((store, _) =>
        {
            var saved = store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator);
            for (var i = 1; i < 64; i++) { store.SaveReusableObject(saved.Id, i, Content(), Actor, NergalRoles.Administrator); }
            Assert.Equal("object.versionCapacityExceeded", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(saved.Id, 64, Content(), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal(64, store.ListReusableObjectVersions(saved.Id).Count); Assert.Equal(64, store.ListAuditEntries().Count);
        });
    }

    /// <summary>Creating a list beyond the controller capacity cannot leave identity or audit rows behind.</summary>
    [Fact]
    public void Save_EnforcesObjectCapacity()
    {
        WithStore((store, _) =>
        {
            for (var i = 0; i < 128; i++) { store.SaveReusableObject(null, 0, new("list_" + i, ReusableObjectKind.Port, "", ["443"]), Actor, NergalRoles.Administrator); }
            Assert.Equal("object.capacityExceeded", Assert.Throws<ControllerStateException>(() => store.SaveReusableObject(null, 0, Content(), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal(128, store.ListReusableObjects().Count); Assert.Equal(128, store.ListAuditEntries(200).Count);
        });
    }

    /// <summary>An explicit schema-2 upgrade preserves source bytes/revisions and refuses colliding object tables.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Upgrade_PreservesSourcesOrRejectsCollision(bool collision)
    {
        WithStore((store, path) =>
        {
            var source = store.ImportNativeSource(new("synthetic", "accept"), Actor, NergalRoles.Administrator);
            Sql(path, "DROP TABLE native_conversion_commits; DROP TABLE native_conversion_plans; DROP TABLE reusable_object_versions; DROP TABLE reusable_objects; PRAGMA user_version=2;");
            Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path)));
            if (collision)
            {
                Sql(path, "CREATE TABLE reusable_objects(foreign_value TEXT); INSERT INTO reusable_objects VALUES('preserve');");
                Assert.Throws<ControllerStateException>(() => ControllerStateStore.Upgrade(new(path)));
                using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open(); using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT foreign_value FROM reusable_objects"; Assert.Equal("preserve", cmd.ExecuteScalar());
                cmd.CommandText = "PRAGMA user_version"; Assert.Equal(2L, cmd.ExecuteScalar());
            }
            else
            {
                var upgraded = ControllerStateStore.Upgrade(new(path));
                Assert.Equal("accept", upgraded.ReadNativeSource(source.Id)!.Content.Text); Assert.Empty(upgraded.ListReusableObjects());
                Assert.Empty(ControllerStateStore.Upgrade(new(path)).ListReusableObjects());
            }
        });
    }

    private static void WithStore(Action<ControllerStateStore, string> action)
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-objects-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { action(ControllerStateStore.Initialize(new(path)), path); } finally { Directory.Delete(path, true); }
    }
    private static void Sql(string path, string sql)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open(); using var cmd = conn.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
    }
}
