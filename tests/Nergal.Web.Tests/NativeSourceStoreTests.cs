using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Real SQLite source snapshots retain exact content, immutable history and atomic actor attribution.</summary>
[SupportedOSPlatform("linux")]
public sealed class NativeSourceStoreTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));

    /// <summary>Separate source identities preserve identical bytes under different display names across reopen.</summary>
    [Fact]
    public void Import_PersistsExactBytesAndIndependentIdentitiesWithAudit()
    {
        WithStore((store, path) =>
        {
            var text = "\ufeff# café\r\ntable inet synthetic { }\r\n";
            var first = store.ImportNativeSource(new("first", text), Actor, NergalRoles.Administrator);
            var second = store.ImportNativeSource(new("second", text), Actor, NergalRoles.Administrator);
            Assert.NotEqual(first.Id, second.Id); Assert.Equal(first.Digest, second.Digest);
            var reopened = ControllerStateStore.Open(new(path));
            Assert.Equal(text, reopened.ReadNativeSource(first.Id)!.Content.Text);
            Assert.Equal("second", reopened.ReadNativeSource(second.Id)!.Summary.Name);
            Assert.Null(reopened.ReadNativeSource(Guid.NewGuid()));
            Assert.Equal(2, reopened.ListNativeSources().Count);
            var audits = reopened.ListAuditEntries(); Assert.Equal(2, audits.Count);
            Assert.All(audits, a => { Assert.Equal(Actor, a.ActorId); Assert.Equal("source.import", a.Action); Assert.DoesNotContain("café", a.Target); });
        });
    }

    /// <summary>A denied actor and a failing audit insertion cannot leave imported content behind.</summary>
    [Fact]
    public void Import_DeniedOrAuditFailureDoesNotPersistSource()
    {
        WithStore((store, path) =>
        {
            var content = new NativeSourceContent("synthetic", "table inet synthetic { }");
            Assert.Equal("rbac.denied", Assert.Throws<ControllerStateException>(() => store.ImportNativeSource(content, Actor, NergalRoles.Auditor)).Code);
            Assert.Throws<ArgumentException>(() => store.ImportNativeSource(content, "untrusted", NergalRoles.Administrator));
            Sql(path, "CREATE TRIGGER reject_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END;");
            Assert.Equal("controller.databaseError", Assert.Throws<ControllerStateException>(() => store.ImportNativeSource(content, Actor, NergalRoles.Administrator)).Code);
            Assert.Empty(store.ListNativeSources()); Assert.Empty(store.ListAuditEntries());
        });
    }

    /// <summary>Stored sources cannot be overwritten or deleted through SQL while required protections remain intact.</summary>
    [Fact]
    public void Source_RejectsMutationAndCopiedNoOpProtection()
    {
        WithStore((store, path) =>
        {
            store.ImportNativeSource(new("synthetic", "counter accept"), Actor, NergalRoles.Administrator);
            Assert.Throws<SqliteException>(() => Sql(path, "UPDATE native_sources SET source_text='changed';"));
            Assert.Throws<SqliteException>(() => Sql(path, "DELETE FROM native_sources;"));
            Sql(path, "DROP TRIGGER native_sources_no_update; CREATE TRIGGER native_sources_no_update BEFORE UPDATE ON native_sources BEGIN SELECT 1; END;");
            Assert.Equal("source.schemaInvalid", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path))).Code);
        });
    }

    /// <summary>Digest tampering never returns source content as trusted original bytes.</summary>
    [Fact]
    public void Source_CorruptDigestIsRejected()
    {
        WithStore((store, path) =>
        {
            var summary = store.ImportNativeSource(new("synthetic", "counter accept"), Actor, NergalRoles.Administrator);
            using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open();
            using var cmd = conn.CreateCommand(); cmd.CommandText = "SELECT sql FROM sqlite_master WHERE name='native_sources_no_update'"; var trigger = (string)cmd.ExecuteScalar()!;
            cmd.CommandText = "DROP TRIGGER native_sources_no_update; UPDATE native_sources SET source_sha256='" + new string('0', 64) + "';" + trigger; cmd.ExecuteNonQuery();
            Assert.Equal("source.corrupt", Assert.Throws<ControllerStateException>(() => store.ReadNativeSource(summary.Id)).Code);
        });
    }

    /// <summary>Retained record capacity rejects another import without appending an audit entry.</summary>
    [Fact]
    public void Import_CountCapacityIsAtomic()
    {
        WithStore((store, _) =>
        {
            for (var i = 0; i < 128; i++) { store.ImportNativeSource(new("synthetic", "accept"), Actor, NergalRoles.Administrator); }
            Assert.Equal("source.capacityExceeded", Assert.Throws<ControllerStateException>(() => store.ImportNativeSource(new("extra", "drop"), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal(128, store.ListNativeSources().Count);
            Assert.Equal(128, store.ListAuditEntries(200).Count);
        });
    }

    /// <summary>Total retained byte capacity cannot be bypassed using fewer maximum-size records.</summary>
    [Fact]
    public void Import_ByteCapacityIsAtomic()
    {
        WithStore((store, _) =>
        {
            var content = new NativeSourceContent("synthetic", new string('a', NativeSourceContent.MaximumBytes));
            for (var i = 0; i < 64; i++) { store.ImportNativeSource(content, Actor, NergalRoles.Administrator); }
            Assert.Equal("source.capacityExceeded", Assert.Throws<ControllerStateException>(() => store.ImportNativeSource(new("extra", "x"), Actor, NergalRoles.Administrator)).Code);
            Assert.Equal(64, store.ListNativeSources().Count); Assert.Equal(64, store.ListAuditEntries().Count);
        });
    }

    /// <summary>Explicit upgrade retains old audit/settings/revisions, is idempotent, and never occurs during ordinary open.</summary>
    [Fact]
    public void Upgrade_PreservesLegacyDataAndRequiresExplicitOperation()
    {
        WithStore((store, path) =>
        {
            var revision = store.SavePolicyRevision("{}", new string('a', 64), Actor, NergalRoles.Administrator, "before upgrade");
            var host = new ManagedHostRecord(Guid.NewGuid(), "synthetic-host", AgentTransportKind.Unix, "/run/nergal/control.sock", expectedServerUserId: 1001);
            store.RegisterHost(host, Actor, NergalRoles.Administrator);
            store.SaveSystemSettings(SystemSettingsSnapshot.Default, Actor, NergalRoles.Administrator);
            var audits = store.ListAuditEntries();
            Sql(path, "DROP TABLE native_conversion_commits; DROP TABLE native_conversion_plans; DROP TABLE reusable_object_versions; DROP TABLE reusable_objects; DROP TABLE native_sources; PRAGMA user_version=1;");
            Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path)));
            var upgraded = ControllerStateStore.Upgrade(new(path));
            Assert.Equal(revision, upgraded.GetPolicyRevision(revision.Revision));
            Assert.Equal(audits, upgraded.ListAuditEntries()); Assert.Empty(upgraded.ListNativeSources());
            Assert.Equal(host, upgraded.GetHost(host.Id)); Assert.Equal(SystemSettingsSnapshot.Default, upgraded.ReadSystemSettings());
            Assert.Empty(ControllerStateStore.Upgrade(new(path)).ListNativeSources());
        });
    }

    /// <summary>An unknown version cannot be upgraded or partially acquire new source tables.</summary>
    [Fact]
    public void Upgrade_UnknownVersionRemainsUnchanged()
    {
        WithStore((_, path) =>
        {
            Sql(path, "DROP TABLE native_conversion_commits; DROP TABLE native_conversion_plans; DROP TABLE reusable_object_versions; DROP TABLE reusable_objects; DROP TABLE native_sources; PRAGMA user_version=99;");
            Assert.Equal("controller.upgradeUnsupported", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Upgrade(new(path))).Code);
            using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open(); using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version"; Assert.Equal(99L, cmd.ExecuteScalar());
            cmd.CommandText = "SELECT count(*) FROM sqlite_master WHERE name='native_sources'"; Assert.Equal(0L, cmd.ExecuteScalar());
        });
    }

    /// <summary>A legacy resource collision or forged audit protection cannot be upgraded or overwritten.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Upgrade_RejectsForeignSourceTableAndForgedLegacyTrigger(bool collision)
    {
        WithStore((_, path) =>
        {
            Sql(path, "DROP TABLE native_conversion_commits; DROP TABLE native_conversion_plans; DROP TABLE reusable_object_versions; DROP TABLE reusable_objects; DROP TABLE native_sources; PRAGMA user_version=1;");
            if (collision) { Sql(path, "CREATE TABLE native_sources(foreign_value TEXT); INSERT INTO native_sources VALUES('preserve');"); }
            else { Sql(path, "DROP TRIGGER audit_no_update; CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT 1; END;"); }
            Assert.Throws<ControllerStateException>(() => ControllerStateStore.Upgrade(new(path)));
            using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open(); using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA user_version"; Assert.Equal(1L, cmd.ExecuteScalar());
            if (collision) { cmd.CommandText = "SELECT foreign_value FROM native_sources"; Assert.Equal("preserve", cmd.ExecuteScalar()); }
            else { cmd.CommandText = "SELECT count(*) FROM sqlite_master WHERE name='native_sources'"; Assert.Equal(0L, cmd.ExecuteScalar()); }
        });
    }

    /// <summary>Copied audit trigger names cannot conceal lost append-only protection in a current controller.</summary>
    [Theory]
    [InlineData("update")]
    [InlineData("delete")]
    public void Open_RejectsForgedCurrentAuditTrigger(string operation)
    {
        WithStore((_, path) =>
        {
            Sql(path, $"DROP TRIGGER audit_no_{operation}; CREATE TRIGGER audit_no_{operation} BEFORE {operation.ToUpperInvariant()} ON audit_log BEGIN SELECT 1; END;");
            Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path))).Code);
        });
    }

    /// <summary>Offset-bearing input and clocks normalize every controller timestamp to UTC before persistence.</summary>
    [Fact]
    public void ControllerTimestamps_AreStoredAsUtcInstants()
    {
        WithStore((_, path) =>
        {
            var input = new DateTimeOffset(2026, 11, 23, 2, 34, 5, TimeSpan.FromMinutes(330));
            var store = ControllerStateStore.Open(new(path), new OffsetClock(input));
            store.RegisterHost(new(Guid.NewGuid(), "synthetic", AgentTransportKind.Unix, "/run/nergal/control.sock", expectedServerUserId: 1001, createdAtUtc: input), Actor, NergalRoles.Administrator);
            store.SavePolicyRevision("{}", new string('a', 64), Actor, NergalRoles.Administrator);
            store.SaveSystemSettings(SystemSettingsSnapshot.Default, Actor, NergalRoles.Administrator);
            store.ImportNativeSource(new("synthetic", "accept"), Actor, NergalRoles.Administrator);
            store.SaveReusableObject(null, 0, new("synthetic", ReusableObjectKind.Port, "", ["443"]), Actor, NergalRoles.Administrator);
            using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open(); using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT created_at_utc FROM hosts UNION ALL SELECT created_at_utc FROM policy_revisions UNION ALL SELECT updated_at_utc FROM system_settings UNION ALL SELECT imported_at_utc FROM native_sources UNION ALL SELECT timestamp_utc FROM audit_log UNION ALL SELECT updated_at_utc FROM reusable_object_versions";
            using var reader = cmd.ExecuteReader(); var timestamps = new List<DateTimeOffset>();
            while (reader.Read()) { timestamps.Add(DateTimeOffset.Parse(reader.GetString(0), System.Globalization.CultureInfo.InvariantCulture)); }
            Assert.NotEmpty(timestamps);
            Assert.All(timestamps, timestamp => { Assert.Equal(TimeSpan.Zero, timestamp.Offset); Assert.Equal(input.ToUniversalTime(), timestamp); });
        });
    }

    private sealed class OffsetClock(DateTimeOffset instant) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => instant;
    }

    private static void WithStore(Action<ControllerStateStore, string> action)
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { action(ControllerStateStore.Initialize(new(path)), path); }
        finally { Directory.Delete(path, true); }
    }
    private static void Sql(string path, string sql)
    {
        using var conn = new SqliteConnection($"Data Source={Path.Combine(path, "controller.db")};Pooling=False"); conn.Open();
        using var cmd = conn.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery();
    }
}
