using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Durable conversion reviews cannot bypass source binding, transactional audit or single-revision creation.</summary>
[SupportedOSPlatform("linux")]
public sealed class NativeConversionStoreTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Converters = { new JsonStringEnumConverter() } };
    private const string Input = "table inet sample { set hosts { type ipv4_addr; elements = {192.0.2.1}; } chain input { type filter hook input priority 0; policy drop; ip saddr @hosts accept; } }";

    /// <summary>Review stores only immutable history; committing later atomically creates lists, one revision and its lineage.</summary>
    [Fact]
    public void ReviewAndCommit_PersistAcrossRestartWithoutApplyingAnything()
    {
        WithStore((store, path) =>
        {
            var content = Plan(store, Input);
            var plan = store.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator);
            Assert.True(plan.Content.IsReady); Assert.Empty(store.ListReusableObjects()); Assert.Empty(store.ListPolicyRevisions());
            Assert.Equal(TimeSpan.Zero, plan.CreatedAtUtc.Offset);
            var reopened = ControllerStateStore.Open(new(path));
            Assert.Equal(plan.Content.Digest, reopened.ReadNativeConversionPlan(plan.Id)!.Content.Digest);
            var revision = reopened.CommitNativeConversionPlan(plan.Id, content.Digest, content, Actor, NergalRoles.Administrator);
            Assert.Single(reopened.ListReusableObjects()); Assert.Single(reopened.ListPolicyRevisions());
            Assert.Equal(revision.Revision, reopened.ReadNativeConversionPlan(plan.Id)!.Revision);
            Assert.Equal(content.PolicyJson, revision.PolicyJson); Assert.Equal(content.CandidateDigest, revision.CandidateDigest);
            var actions = reopened.ListAuditEntries().Select(a => a.Action).ToArray();
            Assert.Equal(new[] { "conversion.commit", "policy.save", "object.create", "conversion.plan", "source.import" }, actions);
            var count = actions.Length;
            Assert.Equal("conversion.alreadyCommitted", Assert.Throws<ControllerStateException>(() => reopened.CommitNativeConversionPlan(plan.Id, content.Digest, content, Actor, NergalRoles.Administrator)).Code);
            Assert.Equal(count, reopened.ListAuditEntries().Count); Assert.Single(reopened.ListPolicyRevisions());
        });
    }

    /// <summary>Denied roles, blocked plans and forged bindings cause no partial object/revision/audit writes.</summary>
    [Fact]
    public void DeniedOrStalePlans_DoNotWritePartialState()
    {
        WithStore((store, _) =>
        {
            var content = Plan(store, Input);
            Assert.Throws<ControllerStateException>(() => store.SaveNativeConversionPlan(content, Actor, NergalRoles.Auditor));
            var saved = store.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator);
            var audit = store.ListAuditEntries().Count;
            Assert.Throws<ControllerStateException>(() => store.CommitNativeConversionPlan(saved.Id, content.Digest, content, Actor, NergalRoles.Auditor));
            Assert.Throws<ControllerStateException>(() => store.CommitNativeConversionPlan(saved.Id, new string('a', 64), content, Actor, NergalRoles.Administrator));
            Assert.Equal(audit, store.ListAuditEntries().Count); Assert.Empty(store.ListReusableObjects()); Assert.Empty(store.ListPolicyRevisions());
            var blocked = Plan(store, "table inet sample { chain input { type filter hook input priority 0; counter accept; } }");
            var denied = store.SaveNativeConversionPlan(blocked, Actor, NergalRoles.Administrator);
            Assert.False(blocked.IsReady);
            Assert.Throws<ControllerStateException>(() => store.CommitNativeConversionPlan(denied.Id, blocked.Digest, blocked, Actor, NergalRoles.Administrator));
            Assert.Empty(store.ListReusableObjects()); Assert.Empty(store.ListPolicyRevisions());
        });
    }

    /// <summary>An audit failure after object/revision insertion rolls the entire conversion transaction back.</summary>
    [Fact]
    public void CommitFailure_RollsBackListsRevisionAndLineage()
    {
        WithStore((store, path) =>
        {
            var content = Plan(store, Input); var saved = store.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator);
            Sql(path, "CREATE TRIGGER fail_conversion_commit BEFORE INSERT ON native_conversion_commits BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
            var audit = store.ListAuditEntries().Count;
            Assert.Throws<ControllerStateException>(() => store.CommitNativeConversionPlan(saved.Id, content.Digest, content, Actor, NergalRoles.Administrator));
            Assert.Equal(audit, store.ListAuditEntries().Count); Assert.Empty(store.ListReusableObjects()); Assert.Empty(store.ListPolicyRevisions());
            Assert.Null(store.ReadNativeConversionPlan(saved.Id)!.Revision);
        });
    }

    /// <summary>Concurrent replay must serialize into exactly one revision and one object creation.</summary>
    [Fact]
    public async Task ConcurrentCommit_CreatesExactlyOneRevision()
    {
        var path = Directory.CreateTempSubdirectory("nergal-conversion-concurrency-").FullName;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path)); var content = Plan(store, Input); var saved = store.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator);
            var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => Task.Run(() =>
            {
                try { ControllerStateStore.Open(new(path)).CommitNativeConversionPlan(saved.Id, content.Digest, content, Actor, NergalRoles.Administrator); return "saved"; }
                catch (ControllerStateException error) { return error.Code; }
            })));
            Assert.Single(results, r => r == "saved"); Assert.Single(results, r => r == "conversion.alreadyCommitted");
            Assert.Single(store.ListPolicyRevisions()); Assert.Single(store.ListReusableObjects());
        }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(path, true); }
    }

    /// <summary>Plan and commit rows are immutable, and copied no-op trigger protection is rejected.</summary>
    [Fact]
    public void Integrity_RejectsMutationAndMissingProtection()
    {
        WithStore((store, path) =>
        {
            var content = Plan(store, Input); var saved = store.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator);
            Assert.Throws<SqliteException>(() => Sql(path, "UPDATE native_conversion_plans SET content_sha256='bad';"));
            Assert.Throws<SqliteException>(() => Sql(path, "DELETE FROM native_conversion_plans;"));
            Sql(path, "DROP TRIGGER native_conversion_plans_no_update; CREATE TRIGGER native_conversion_plans_no_update BEFORE UPDATE ON native_conversion_plans BEGIN SELECT 1; END;");
            Assert.Equal("conversion.schemaInvalid", Assert.Throws<ControllerStateException>(() => store.ReadNativeConversionPlan(saved.Id)).Code);
        });
    }

    /// <summary>Schema 3 needs an explicit offline upgrade and preserves prior source/object/revision history.</summary>
    [Fact]
    public void Upgrade_FromSchema3_IsExplicitAndPreservesHistory()
    {
        WithStore((store, path) =>
        {
            var content = Plan(store, Input); var sourceId = content.RootSourceId;
            Sql(path, "DROP TABLE native_conversion_commits; DROP TABLE native_conversion_plans; PRAGMA user_version=3;");
            Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(new(path)));
            var upgraded = ControllerStateStore.Upgrade(new(path));
            Assert.Equal(Input, upgraded.ReadNativeSource(sourceId)!.Content.Text);
            Assert.Empty(upgraded.ListNativeConversionPlans(sourceId));
            Assert.Single(upgraded.ListAuditEntries());
            Assert.True(upgraded.SaveNativeConversionPlan(content, Actor, NergalRoles.Administrator).Content.IsReady);
        });
    }

    private static NativeConversionPlanContent Plan(ControllerStateStore store, string text)
    {
        var source = store.ImportNativeSource(new("synthetic", text), Actor, NergalRoles.Administrator);
        var request = new NativeImportRequest(source.Id, [new("inet", "sample", NativeImportTableRole.Filter)], []);
        var plan = NativeImportPlanner.Plan(request, [store.ReadNativeSource(source.Id)!]);
        return new(source.Id, JsonSerializer.Serialize(request, Json), JsonSerializer.Serialize(new
        { schemaVersion = 1, sourceBindings = plan.Sources.Select(s => new NativeConversionSource(s.SourceId, s.Digest)), plan.Mappings, plan.Gaps }, Json), plan.PolicyJson, plan.CandidateDigest);
    }
    private static void WithStore(Action<ControllerStateStore, string> action)
    {
        var path = Directory.CreateTempSubdirectory("nergal-conversion-").FullName;
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { action(ControllerStateStore.Initialize(new(path)), path); }
        finally { SqliteConnection.ClearAllPools(); Directory.Delete(path, true); }
    }
    private static void Sql(string path, string sql)
    { using var conn = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(path, "controller.db"), Pooling = false }.ToString()); conn.Open(); using var cmd = conn.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
}
