using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies the settings compare-and-swap and immutable SQLite history.</summary>
[SupportedOSPlatform("linux")]
public sealed class SystemSettingsVersionTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("39fc51b0-6853-4664-9748-740b2bff5ffa"));

    /// <summary>Two writers presenting the same version can commit one update and one audit event.</summary>
    [Fact]
    public async Task OnlyOneConcurrentWriterCanCommitFromTheSameToken()
    {
        using var fixture = new Fixture();
        var original = fixture.Store.ReadSystemSettingsVersion();
        Assert.Equal(0, original.Version);
        Assert.Null(original.UpdatedAtUtc);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var writers = new[] { "First synthetic console", "Second synthetic console" }
            .Select(name => Task.Run(async () =>
            {
                await start.Task;
                try { return Save(fixture.Store, original, name); }
                catch (ControllerStateException error) when (error.Code == "settings.stale") { return null; }
            }, TestContext.Current.CancellationToken))
            .ToArray();
        start.SetResult();
        var winner = Assert.Single((await Task.WhenAll(writers)).OfType<SystemSettingsVersion>());

        Assert.Equal(1, winner.Version);
        Assert.NotEqual(original.FormToken, winner.FormToken);
        Assert.Equal(Actor, winner.UpdatedByActor);
        Assert.Equal(winner, ControllerStateStore.Open(new(fixture.Directory)).ReadSystemSettingsVersion());
        var audit = Assert.Single(fixture.Store.ListAuditEntries());
        var binding = SHA256.HashData(Encoding.UTF8.GetBytes(winner.FormToken + SystemSettingsCodec.Serialize(winner.Settings)));
        Assert.Equal("settings.version:1:" + Convert.ToHexStringLower(binding), audit.DetailCode);
        Assert.Equal(audit.TimestampUtc, winner.UpdatedAtUtc);
        Assert.Equal(2L, fixture.Sql("SELECT count(*) FROM system_settings"));
    }

    /// <summary>Database protections deny rewriting history and a failed version insert rolls back the audit event.</summary>
    [Fact]
    public void VersionsAreImmutableAndAuditRollsBackOnInsertFailure()
    {
        using var fixture = new Fixture();
        var original = fixture.Store.ReadSystemSettingsVersion();
        fixture.Sql("""
            CREATE TRIGGER fixture_fail_version BEFORE INSERT ON system_settings
            BEGIN SELECT RAISE(ABORT, 'synthetic insertion failure'); END;
            """);

        Assert.Equal("controller.databaseError", Assert.Throws<ControllerStateException>(
            () => Save(fixture.Store, original, "Failed update")).Code);
        Assert.Equal(original, fixture.Store.ReadSystemSettingsVersion());
        Assert.Empty(fixture.Store.ListAuditEntries());

        fixture.Sql("DROP TRIGGER fixture_fail_version;");
        var committed = Save(fixture.Store, original, "Saved update");
        Assert.Throws<SqliteException>(() => fixture.Sql("UPDATE system_settings SET settings_json = '{}' WHERE version = 0"));
        Assert.Throws<SqliteException>(() => fixture.Sql("DELETE FROM system_settings WHERE version = 0"));
        Assert.Throws<SqliteException>(() => fixture.Sql("""
            INSERT OR REPLACE INTO system_settings (version, form_token, settings_json, audit_sequence)
            SELECT 2, form_token, settings_json, 999 FROM system_settings WHERE version = 0;
            """));
        Assert.Throws<SqliteException>(() => fixture.Sql("""
            INSERT OR REPLACE INTO system_settings (version, form_token, settings_json, audit_sequence)
            SELECT 2, '00000000000000000000000000000001', settings_json, audit_sequence
            FROM system_settings WHERE version = 1;
            """));
        Assert.Equal(committed, fixture.Store.ReadSystemSettingsVersion());
        Assert.Single(fixture.Store.ListAuditEntries());
        Assert.Equal(2L, fixture.Sql("SELECT count(*) FROM system_settings"));
    }

    /// <summary>A newer saved-settings audit cannot be hidden by restoring only the settings rows.</summary>
    [Fact]
    public void PartialRestoreCannotReopenAnOlderVersionForEditing()
    {
        using var fixture = new Fixture();
        var saved = Save(fixture.Store, fixture.Store.ReadSystemSettingsVersion(), "Initial update");
        _ = Save(fixture.Store, saved, "Newer update");
        var trigger = Assert.IsType<string>(fixture.Sql(
            "SELECT sql FROM sqlite_master WHERE name = 'system_settings_no_delete'"));
        fixture.Sql("DROP TRIGGER system_settings_no_delete; DELETE FROM system_settings WHERE version = 2; " + trigger);

        Assert.Equal("settings.corrupt", Assert.Throws<ControllerStateException>(() => fixture.Store.ReadSystemSettingsVersion()).Code);
        Assert.Equal("settings.corrupt", Assert.Throws<ControllerStateException>(() => Save(fixture.Store, saved, "Stale edit")).Code);
        Assert.Equal(2, fixture.Store.ListAuditEntries().Count);
    }

    /// <summary>Matching version and audit counters cannot link settings to a different history.</summary>
    [Fact]
    public void PartialRestoreCannotBindToDifferentHistoryAtTheSameAuditSequence()
    {
        using var fixture = new Fixture();
        using var alternate = new Fixture();
        var saved = Save(fixture.Store, fixture.Store.ReadSystemSettingsVersion(), "Original history");
        var other = Save(alternate.Store, alternate.Store.ReadSystemSettingsVersion(), "Alternate history");
        Assert.Equal(saved.Version, other.Version);
        Assert.Equal(Assert.Single(fixture.Store.ListAuditEntries()).Sequence,
            Assert.Single(alternate.Store.ListAuditEntries()).Sequence);
        var trigger = Assert.IsType<string>(fixture.Sql(
            "SELECT sql FROM sqlite_master WHERE name = 'system_settings_no_update'"));
        fixture.Sql("""
            ATTACH DATABASE $path AS alternate;
            DROP TRIGGER system_settings_no_update;
            UPDATE system_settings
            SET (form_token, settings_json) = (SELECT form_token, settings_json FROM alternate.system_settings WHERE version = 1)
            WHERE version = 1;
            """ + "\n" + trigger, ("$path", Path.Combine(alternate.Directory, "controller.db")));

        Assert.Equal("settings.corrupt", Assert.Throws<ControllerStateException>(() => fixture.Store.ReadSystemSettingsVersion()).Code);
        Assert.Equal("settings.corrupt", Assert.Throws<ControllerStateException>(() => Save(fixture.Store, other, "Mismatched edit")).Code);
        Assert.Single(fixture.Store.ListAuditEntries());
    }

    /// <summary>Escaped JSON that exceeds the reader's bound cannot become the saved version.</summary>
    [Fact]
    public void OversizedSerializedSettingsDoNotCommit()
    {
        using var fixture = new Fixture();
        var original = fixture.Store.ReadSystemSettingsVersion();
        var text = new string('界', 2048);
        var candidate = original.Settings with
        {
            Oidc = original.Settings.Oidc with { AuthorityUrl = text, RedirectUri = text },
            Ldap = original.Settings.Ldap with { ServerUri = text },
        };
        Assert.Empty(SystemSettingsCodec.Validate(candidate));
        Assert.True(SystemSettingsCodec.Serialize(candidate).Length > SystemSettingsCodec.MaximumJsonLength);

        Assert.Equal("settings.bounds", Assert.Throws<ControllerStateException>(
            () => fixture.Store.SaveSystemSettings(candidate, original.FormToken, Actor, NergalRoles.Administrator)).Code);
        Assert.Equal(original, fixture.Store.ReadSystemSettingsVersion());
        Assert.Empty(fixture.Store.ListAuditEntries());
    }

    private static SystemSettingsVersion Save(ControllerStateStore store, SystemSettingsVersion original, string name)
    {
        var settings = original.Settings with { Branding = original.Settings.Branding with { ApplicationName = name } };
        return store.SaveSystemSettings(settings, original.FormToken, Actor, NergalRoles.Administrator);
    }

    private sealed class Fixture : IDisposable
    {
        internal string Directory { get; } = Path.Combine(Path.GetTempPath(), "ng-settings-version-" + Guid.NewGuid().ToString("N"));
        internal ControllerStateStore Store { get; }

        internal Fixture()
        {
            System.IO.Directory.CreateDirectory(Directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Store = ControllerStateStore.Initialize(new(Directory));
        }

        internal object? Sql(string sql, params (string Name, object Value)[] parameters)
        {
            using var connection = new SqliteConnection($"Data Source={Path.Combine(Directory, "controller.db")};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            foreach (var (name, value) in parameters) { command.Parameters.AddWithValue(name, value); }
            return command.ExecuteScalar();
        }

        public void Dispose() => System.IO.Directory.Delete(Directory, true);
    }
}
