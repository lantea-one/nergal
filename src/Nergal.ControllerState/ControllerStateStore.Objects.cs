using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Nergal.Core.Controller;
using Nergal.Core.Identity;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Creates a stable named object or appends a version using optimistic concurrency, atomically with audit.</summary>
    /// <remarks>Supply null identity and expected version zero to create. Edits require the exact current version. No policy or kernel state changes.</remarks>
    /// <exception cref="ControllerStateException">Authorization, identity/type, capacity, concurrency or integrity validation fails.</exception>
    public ReusableObjectVersion SaveReusableObject(Guid? id, int expectedVersion, ReusableObjectContent content, string actorId, string actorRole)
    {
        ArgumentNullException.ThrowIfNull(content); ValidateActor(actorId, actorRole);
        if (actorRole != NergalRoles.Administrator) { throw new ControllerStateException("rbac.denied"); }
        return Write((conn, tx) =>
        {
            var key = id ?? Guid.NewGuid();
            var current = ReadObject(conn, tx, key, null);
            if ((id.HasValue && current is null) || (!id.HasValue && expectedVersion != 0)) { throw new ControllerStateException("object.notFound"); }
            if (current is not null && current.Version != expectedVersion) { throw new ControllerStateException("object.staleVersion"); }
            if (current is not null && (current.Content.Name != content.Name || current.Content.Kind != content.Kind)) { throw new ControllerStateException("object.identityImmutable"); }
            if (current is null)
            {
                if (ScalarLong(conn, tx, "SELECT count(*) FROM reusable_objects WHERE name=$name", ("$name", content.Name)) != 0) { throw new ControllerStateException("object.duplicateName"); }
                if (ScalarLong(conn, tx, "SELECT count(*) FROM reusable_objects") >= 128) { throw new ControllerStateException("object.capacityExceeded"); }
                ExecuteNonQuery(conn, tx, "INSERT INTO reusable_objects(id,name,kind) VALUES($id,$name,$kind)",
                    ("$id", key.ToString("D")), ("$name", content.Name), ("$kind", content.Kind.ToString()));
            }
            if (expectedVersion >= 64) { throw new ControllerStateException("object.versionCapacityExceeded"); }
            var version = expectedVersion + 1; var now = _timeProvider.GetUtcNow().ToUniversalTime();
            var entries = JsonSerializer.Serialize(content.Entries); var digest = ObjectDigest(content);
            ExecuteNonQuery(conn, tx, """
                INSERT INTO reusable_object_versions(object_id,version,description,entries_json,content_sha256,updated_by_actor,updated_at_utc)
                VALUES($id,$version,$description,$entries,$digest,$actor,$time)
                """, ("$id", key.ToString("D")), ("$version", version), ("$description", content.Description), ("$entries", entries),
                ("$digest", digest), ("$actor", actorId), ("$time", now.ToString("O", CultureInfo.InvariantCulture)));
            InsertAudit(conn, tx, now, actorId, actorRole, current is null ? "object.create" : "object.version", key.ToString("D"), null, "succeeded", null);
            return new ReusableObjectVersion(key, version, content, digest, actorId, now);
        });
    }

    /// <summary>Lists current validated snapshots, sorted by stable object name. At most 128 objects are retained.</summary>
    public IReadOnlyList<ReusableObjectVersion> ListReusableObjects() => Read((conn, tx) =>
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "SELECT id FROM reusable_objects ORDER BY name LIMIT 129";
        var ids = new List<Guid>(); using (var reader = cmd.ExecuteReader()) { while (reader.Read()) { ids.Add(Guid.ParseExact(reader.GetString(0), "D")); } }
        if (ids.Count > 128) { throw new ControllerStateException("object.corrupt"); }
        return Array.AsReadOnly(ids.Select(id => ReadObject(conn, tx, id, null) ?? throw new ControllerStateException("object.corrupt")).ToArray());
    });

    /// <summary>Reads an immutable version or the latest snapshot; missing identities/versions return null.</summary>
    public ReusableObjectVersion? ReadReusableObject(Guid id, int? version = null) => Read((conn, tx) => ReadObject(conn, tx, id, version));

    /// <summary>Lists immutable versions of one object, newest first, without changing its current version.</summary>
    public IReadOnlyList<ReusableObjectVersion> ListReusableObjectVersions(Guid id) => Read((conn, tx) =>
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = "SELECT version FROM reusable_object_versions WHERE object_id=$id ORDER BY version DESC LIMIT 65";
        cmd.Parameters.AddWithValue("$id", id.ToString("D")); var versions = new List<int>();
        using (var reader = cmd.ExecuteReader()) { while (reader.Read()) { versions.Add(reader.GetInt32(0)); } }
        if (versions.Count > 64) { throw new ControllerStateException("object.corrupt"); }
        return Array.AsReadOnly(versions.Select(v => ReadObject(conn, tx, id, v) ?? throw new ControllerStateException("object.corrupt")).ToArray());
    });

    private static ReusableObjectVersion? ReadObject(SqliteConnection conn, SqliteTransaction tx, Guid id, int? version)
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT o.name,o.kind,v.version,v.description,v.entries_json,v.content_sha256,v.updated_by_actor,v.updated_at_utc
            FROM reusable_objects o JOIN reusable_object_versions v ON o.id=v.object_id
            WHERE o.id=$id AND ($version IS NULL OR v.version=$version) ORDER BY v.version DESC LIMIT 1
            """;
        cmd.Parameters.AddWithValue("$id", id.ToString("D")); cmd.Parameters.AddWithValue("$version", (object?)version ?? DBNull.Value);
        using var reader = cmd.ExecuteReader(); if (!reader.Read()) { return null; }
        try
        {
            var kindText = reader.GetString(1);
            if (!Enum.TryParse<ReusableObjectKind>(kindText, out var kind) || !Enum.IsDefined(kind) || kind.ToString() != kindText) { throw new ArgumentException(); }
            var entriesJson = reader.GetString(4);
            if (entriesJson.Length > 8192) { throw new ArgumentException(); }
            var entries = JsonSerializer.Deserialize<string[]>(entriesJson) ?? throw new ArgumentException();
            var content = new ReusableObjectContent(reader.GetString(0), kind, reader.GetString(3), entries);
            var number = reader.GetInt32(2); var digest = reader.GetString(5); var actor = reader.GetString(6);
            var time = DateTimeOffset.ParseExact(reader.GetString(7), "O", CultureInfo.InvariantCulture);
            if (id == Guid.Empty || number is < 1 or > 64 || !ControllerActorIdentity.IsValid(actor) || time.Offset != TimeSpan.Zero ||
                JsonSerializer.Serialize(content.Entries) != entriesJson || ObjectDigest(content) != digest) { throw new ArgumentException(); }
            return new(id, number, content, digest, actor, time);
        }
        catch (Exception ex) when (ex is ArgumentException or JsonException or FormatException or OverflowException) { throw new ControllerStateException("object.corrupt", ex); }
    }

    private static string ObjectDigest(ReusableObjectContent content) => content.Digest;

    private static void ValidateObjectSchema(SqliteConnection conn, SqliteTransaction tx)
    {
        RequireDefinition(conn, tx, "reusable_objects", ObjectsTableSql, "object.schemaInvalid");
        RequireDefinition(conn, tx, "reusable_object_versions", ObjectVersionsTableSql, "object.schemaInvalid");
        foreach (var table in new[] { "reusable_objects", "reusable_object_versions" })
        {
            foreach (var op in new[] { "update", "delete" }) { RequireDefinition(conn, tx, table + "_no_" + op, ObjectTrigger(table, op), "object.schemaInvalid"); }
        }
    }
    private const string ObjectsTableSql = """
        CREATE TABLE reusable_objects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK(kind IN ('Ipv4','Ipv6','Port'))
        ) STRICT;
        """;
    private const string ObjectVersionsTableSql = """
        CREATE TABLE reusable_object_versions (
            object_id TEXT NOT NULL REFERENCES reusable_objects(id),
            version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 64),
            description TEXT NOT NULL CHECK(length(description)<=500),
            entries_json TEXT NOT NULL CHECK(length(entries_json)<=8192),
            content_sha256 TEXT NOT NULL,
            updated_by_actor TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            PRIMARY KEY(object_id,version)
        ) STRICT;
        """;
    private static string ObjectTrigger(string table, string op) => $"CREATE TRIGGER {table}_no_{op} BEFORE {op.ToUpperInvariant()} ON {table} BEGIN SELECT RAISE(ABORT, 'object history is immutable'); END;";
    private static string ObjectsSchemaSql => ObjectsTableSql + ObjectVersionsTableSql + string.Concat(new[] { "reusable_objects", "reusable_object_versions" }.SelectMany(t => new[] { "update", "delete" }.Select(op => ObjectTrigger(t, op))));
}
