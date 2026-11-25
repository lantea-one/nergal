using System.Globalization;
using System.Text.Json;
using System.Data.Common;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Persists one immutable source-bound review and audit; creates no policy, list or host operation.</summary>
    /// <exception cref="ControllerStateException">Authorization, source binding, capacity or integrity validation fails.</exception>
    public NativeConversionPlanRecord SaveNativeConversionPlan(NativeConversionPlanContent content, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(content); ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator) { throw new ControllerStateException("rbac.denied"); }
        return Write((conn, tx) =>
        {
            ValidateConversionSources(conn, tx, content);
            var requestLength = TextLength(conn, "request_json");
            var reportLength = TextLength(conn, "report_json");
            var policyLength = TextLength(conn, "policy_json");
            if (ScalarLong(conn, tx, "SELECT count(*) FROM native_conversion_plans") >= 128 ||
                ScalarLong(conn, tx, $"SELECT coalesce(sum({requestLength}+{reportLength}+coalesce({policyLength},0)),0) FROM native_conversion_plans") +
                content.RequestJson.Length + content.ReportJson.Length + (content.PolicyJson?.Length ?? 0) > 67_108_864)
            { throw new ControllerStateException("conversion.capacityExceeded"); }
            var id = Guid.NewGuid(); var now = _timeProvider.GetUtcNow().ToUniversalTime();
            ExecuteNonQuery(conn, tx, """
                INSERT INTO native_conversion_plans(id,root_source_id,request_json,report_json,policy_json,candidate_sha256,content_sha256,created_by_actor,created_at_utc)
                VALUES(@id,@source,@request,@report,@policy,@candidate,@digest,@actor,@time)
                """, ("@id", id.ToString("D")), ("@source", content.RootSourceId.ToString("D")), ("@request", content.RequestJson),
                ("@report", content.ReportJson), ("@policy", (object?)content.PolicyJson ?? DBNull.Value), ("@candidate", (object?)content.CandidateDigest ?? DBNull.Value),
                ("@digest", content.Digest), ("@actor", actorId), ("@time", now.ToString("O", CultureInfo.InvariantCulture)));
            InsertAudit(conn, tx, now, actorId, actorRole, "conversion.plan", id.ToString("D"), null, "succeeded", null);
            return new NativeConversionPlanRecord(id, content, actorId, now, null);
        });
    }

    /// <summary>Reads a protected immutable plan, checking its complete digest and current immutable source bindings.</summary>
    public NativeConversionPlanRecord? ReadNativeConversionPlan(Guid id) => Read((conn, tx) => ReadConversionPlan(conn, tx, id));

    /// <summary>Lists bounded immutable plans for one source, newest first; does not infer host application.</summary>
    public IReadOnlyList<NativeConversionPlanRecord> ListNativeConversionPlans(Guid sourceId) => Read((conn, tx) =>
    {
        using var command = conn.CreateCommand(); command.Transaction = tx;
        command.CommandText = LimitRows(conn, "SELECT id FROM native_conversion_plans WHERE root_source_id=@source ORDER BY rowid DESC", "129");
        AddParameter(command, "@source", sourceId.ToString("D")); var ids = new List<Guid>();
        using (var reader = command.ExecuteReader()) { while (reader.Read()) { ids.Add(Guid.ParseExact(reader.GetString(0), "D")); } }
        if (ids.Count > 128) { throw new ControllerStateException("conversion.corrupt"); }
        return Array.AsReadOnly(ids.Select(id => ReadConversionPlan(conn, tx, id) ?? throw new ControllerStateException("conversion.corrupt")).ToArray());
    });

    /// <summary>Creates exactly one linked revision and missing pinned lists atomically after server recomputation.</summary>
    /// <remarks>Caller must re-run the pure planner against database originals and compare the complete request/report before calling.
    /// This method binds the saved digest and canonical intent, rechecks sources, rejects replay, and never invokes an agent.</remarks>
    /// <exception cref="ControllerStateException">Role, replay, binding, object history or transaction integrity fails.</exception>
    public PolicyRevisionRecord CommitNativeConversionPlan(Guid id, string expectedDigest, NativeConversionPlanContent recomputed, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(recomputed); ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator) { throw new ControllerStateException("rbac.denied"); }
        return Write((conn, tx) =>
        {
            var plan = ReadConversionPlan(conn, tx, id) ?? throw new ControllerStateException("conversion.notFound");
            if (plan.Revision is not null) { throw new ControllerStateException("conversion.alreadyCommitted"); }
            if (!plan.Content.IsReady || plan.Content.Digest != expectedDigest || recomputed.Digest != plan.Content.Digest || !recomputed.IsReady)
            { throw new ControllerStateException("conversion.bindingMismatch"); }
            ValidateConversionSources(conn, tx, plan.Content);
            var decoded = PolicyBundleJsonCodec.DecodeBundle(plan.Content.PolicyJson!);
            if (decoded.Value is not { } bundle) { throw new ControllerStateException("conversion.corrupt"); }
            var objects = PolicyObjectReferences.Enumerate(bundle).Select(b => b.Reference).GroupBy(r => r.Id).ToArray();
            var now = _timeProvider.GetUtcNow().ToUniversalTime();
            foreach (var group in objects)
            {
                var reference = group.First();
                if (group.Any(r => !r.Equals(reference)) || reference.Version != 1 || !reference.NativeSet) { throw new ControllerStateException("conversion.objectInvalid"); }
                var existing = ReadObject(conn, tx, reference.Id, 1);
                if (existing is not null)
                {
                    if (existing.Content.Digest != reference.Content.Digest) { throw new ControllerStateException("conversion.objectConflict"); }
                    continue;
                }
                var content = reference.Content;
                if (ScalarLong(conn, tx, "SELECT count(*) FROM reusable_objects") >= 128 || ScalarLong(conn, tx, "SELECT count(*) FROM reusable_objects WHERE id=@id OR name=@name", ("@id", reference.Id.ToString("D")), ("@name", content.Name)) != 0)
                { throw new ControllerStateException("conversion.objectConflictOrCapacity"); }
                ExecuteNonQuery(conn, tx, "INSERT INTO reusable_objects(id,name,kind) VALUES(@id,@name,@kind)",
                    ("@id", reference.Id.ToString("D")), ("@name", content.Name), ("@kind", content.Kind.ToString()));
                ExecuteNonQuery(conn, tx, """
                    INSERT INTO reusable_object_versions(object_id,version,description,entries_json,content_sha256,updated_by_actor,updated_at_utc)
                    VALUES(@id,1,@description,@entries,@digest,@actor,@time)
                    """, ("@id", reference.Id.ToString("D")), ("@description", content.Description), ("@entries", JsonSerializer.Serialize(content.Entries)),
                    ("@digest", content.Digest), ("@actor", actorId), ("@time", now.ToString("O", CultureInfo.InvariantCulture)));
                InsertAudit(conn, tx, now, actorId, actorRole, "object.create", reference.Id.ToString("D"), null, "succeeded", null);
            }
            var revision = InsertPolicyRevision(conn, tx, plan.Content.PolicyJson!, plan.Content.CandidateDigest!, actorId, actorRole, "Converted from reviewed native source plan");
            ExecuteNonQuery(conn, tx, "INSERT INTO native_conversion_commits(plan_id,revision) VALUES(@id,@revision)",
                ("@id", id.ToString("D")), ("@revision", checked((long)revision.Revision)));
            InsertAudit(conn, tx, now, actorId, actorRole, "conversion.commit", id.ToString("D"), revision.Revision, "succeeded", null);
            return revision;
        });
    }

    private static NativeConversionPlanRecord? ReadConversionPlan(DbConnection conn, DbTransaction tx, Guid id)
    {
        using var command = conn.CreateCommand(); command.Transaction = tx;
        command.CommandText = """
            SELECT p.root_source_id,p.request_json,p.report_json,p.policy_json,p.candidate_sha256,p.content_sha256,p.created_by_actor,p.created_at_utc,c.revision
            FROM native_conversion_plans p LEFT JOIN native_conversion_commits c ON p.id=c.plan_id WHERE p.id=@id
            """;
        AddParameter(command, "@id", id.ToString("D")); NativeConversionPlanRecord record;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read()) { return null; }
            try
            {
                var content = new NativeConversionPlanContent(Guid.ParseExact(reader.GetString(0), "D"), reader.GetString(1), reader.GetString(2), reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4));
                if (content.Digest != reader.GetString(5)) { throw new ControllerStateException("conversion.corrupt"); }
                var actor = reader.GetString(6); var time = DateTimeOffset.ParseExact(reader.GetString(7), "O", CultureInfo.InvariantCulture);
                if (!ControllerActorIdentity.IsValid(actor) || time.Offset != TimeSpan.Zero) { throw new ControllerStateException("conversion.corrupt"); }
                record = new(id, content, actor, time, reader.IsDBNull(8) ? null : checked((ulong)reader.GetInt64(8)));
            }
            catch (Exception error) when (error is ArgumentException or FormatException or OverflowException)
            { throw new ControllerStateException("conversion.corrupt"); }
        }
        ValidateConversionSources(conn, tx, record.Content); return record;
    }

    private static void ValidateConversionSources(DbConnection conn, DbTransaction tx, NativeConversionPlanContent content)
    {
        foreach (var source in content.Sources)
        {
            using var command = conn.CreateCommand(); command.Transaction = tx;
            command.CommandText = $"""
                SELECT name, CASE WHEN {NativeSourceByteLength(conn)} = byte_length THEN source_text END, source_sha256, byte_length
                FROM native_sources WHERE id=@id
                """;
            AddParameter(command, "@id", source.Id.ToString("D")); using var reader = command.ExecuteReader();
            if (!reader.Read()) { throw new ControllerStateException("conversion.sourceMissing"); }
            try
            {
                var original = new NativeSourceContent(reader.GetString(0), ReadNativeSourceText(reader, 1));
                if (original.Digest != source.Digest || original.Digest != reader.GetString(2) || original.ByteLength != reader.GetInt32(3)) { throw new ControllerStateException("conversion.sourceMismatch"); }
            }
            catch (ArgumentException) { throw new ControllerStateException("conversion.sourceMismatch"); }
        }
    }

    private static void ValidateConversionPlanSchema(DbConnection conn, DbTransaction tx)
    {
        RequireDefinition(conn, tx, "native_conversion_plans", ConversionPlansTableSql, "conversion.schemaInvalid");
        RequireDefinition(conn, tx, "native_conversion_commits", ConversionCommitsTableSql, "conversion.schemaInvalid");
        foreach (var (table, action) in new[] { ("native_conversion_plans", "update"), ("native_conversion_plans", "delete"), ("native_conversion_commits", "update"), ("native_conversion_commits", "delete") })
        { RequireDefinition(conn, tx, table + "_no_" + action, ConversionTrigger(table, action), "conversion.schemaInvalid"); }
    }
    private const string ConversionPlansTableSql = """
        CREATE TABLE native_conversion_plans (
            id TEXT PRIMARY KEY,
            root_source_id TEXT NOT NULL REFERENCES native_sources(id),
            request_json TEXT NOT NULL,
            report_json TEXT NOT NULL,
            policy_json TEXT,
            candidate_sha256 TEXT,
            content_sha256 TEXT NOT NULL,
            created_by_actor TEXT NOT NULL,
            created_at_utc TEXT NOT NULL
        ) STRICT;
        """;
    private const string ConversionCommitsTableSql = """
        CREATE TABLE native_conversion_commits (
            plan_id TEXT PRIMARY KEY REFERENCES native_conversion_plans(id),
            revision INTEGER NOT NULL UNIQUE REFERENCES policy_revisions(revision)
        ) STRICT;
        """;
    private static string ConversionTrigger(string table, string action) => $"CREATE TRIGGER {table}_no_{action} BEFORE {action.ToUpperInvariant()} ON {table} BEGIN SELECT RAISE(ABORT, 'native conversion history is immutable'); END;";
    private static string ConversionPlansSchemaSql => ConversionPlansTableSql + ConversionCommitsTableSql +
        string.Concat(new[] { "native_conversion_plans", "native_conversion_commits" }.SelectMany(table => new[] { "update", "delete" }.Select(action => ConversionTrigger(table, action))));
}
