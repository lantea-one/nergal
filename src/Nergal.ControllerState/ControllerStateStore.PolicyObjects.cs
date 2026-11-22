using System.Globalization;
using Microsoft.Data.Sqlite;
using Nergal.Core.Policy;
using Nergal.Core.Controller;

namespace Nergal.ControllerState;

public sealed partial class ControllerStateStore
{
    /// <summary>Validates every embedded reference against authoritative immutable database history.</summary>
    public IReadOnlyList<PolicyObjectDiagnostic> ValidatePolicyObjects(FirewallPolicyBundle bundle) => Read((conn, tx) => ValidatePolicyObjects(conn, tx, bundle));

    private static IReadOnlyList<PolicyObjectDiagnostic> ValidatePolicyObjects(SqliteConnection conn, SqliteTransaction tx, FirewallPolicyBundle bundle)
    {
        var errors = new List<PolicyObjectDiagnostic>();
        foreach (var binding in PolicyObjectReferences.Enumerate(bundle))
        {
            var reference = binding.Reference;
            var stored = ReadObject(conn, tx, reference.Id, reference.Version);
            if (stored is null) { errors.Add(new("object.referenceNotFound", binding.Path)); }
            else if (stored.Digest != reference.Content.Digest) { errors.Add(new("object.referenceMismatch", binding.Path)); }
        }
        return errors.AsReadOnly();
    }

    /// <summary>Lists saved valid revision references to an object, including older versions; it does not infer host application.</summary>
    public IReadOnlyList<PolicyObjectUsage> ListPolicyObjectUsage(Guid id) => Read((conn, tx) =>
    {
        using var cmd = conn.CreateCommand(); cmd.Transaction = tx;
        // json_tree selects only candidate rows; strict domain decoding below verifies actual matcher references.
        cmd.CommandText = """
            SELECT revision,policy_json FROM policy_revisions p
            WHERE EXISTS(SELECT 1 FROM json_tree(CASE WHEN json_valid(p.policy_json) THEN p.policy_json ELSE '{}' END)
                         WHERE key='id' AND value=$id) ORDER BY revision DESC
            """;
        cmd.Parameters.AddWithValue("$id", id.ToString("D"));
        using var reader = cmd.ExecuteReader(); var result = new List<PolicyObjectUsage>();
        while (reader.Read())
        {
            var parsed = PolicyBundleJsonCodec.DecodeBundle(reader.GetString(1));
            if (parsed.Value is not { } bundle) { throw new ControllerStateException("object.revisionCorrupt"); }
            var revision = ulong.Parse(reader.GetValue(0).ToString()!, CultureInfo.InvariantCulture);
            foreach (var binding in PolicyObjectReferences.Enumerate(bundle).Where(b => b.Reference.Id == id)) { result.Add(new(revision, binding.Path, binding.Reference.Version)); }
        }
        return result.AsReadOnly();
    });
}
