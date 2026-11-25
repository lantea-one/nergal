using System.Data.Common;

namespace Nergal.Identity;

// Storage entities never leave the credential boundary.
internal sealed class LocalAccountState
{
    public string UserId { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public long Version { get; set; } = 1;
    public string CreatedUtc { get; set; } = "";
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class LocalProfile
{
    public string ActorId { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string GivenName { get; set; } = "";
    public string FamilyName { get; set; } = "";
    public string Email { get; set; } = "";
    public long Version { get; set; }
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class IdentityAudit
{
    public long Sequence { get; set; }
    public string TimestampUtc { get; set; } = "";
    public string ActorId { get; set; } = "";
    public string ActorRole { get; set; } = "";
    public string Action { get; set; } = "";
    public string Target { get; set; } = "";
}

internal static class AccountSchema
{
    internal const int Version = 8;
    internal const string OidcAssuranceCheck = "typeof(\"MfaAssuranceMode\") = 'integer' AND \"MfaAssuranceMode\" IN (0, 1, 2)";
    internal static IReadOnlyList<(string Name, string Predicate)> LdapConnectionChecks { get; } = Array.AsReadOnly(
        new (string, string)[]
        {
            ("ldap_connection_singleton", "\"Id\" = 1"),
            ("ldap_connection_enabled", "typeof(\"Enabled\") = 'integer' AND \"Enabled\" IN (0, 1)"),
            ("ldap_connection_generation", "typeof(\"Version\") = 'integer' AND \"Version\" >= 1 AND \"Version\" < 9223372036854775807")
        });
    internal const string NoUpdate = "CREATE TRIGGER identity_audit_no_update BEFORE UPDATE ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'identity audit is append-only'); END";
    internal const string NoDelete = "CREATE TRIGGER identity_audit_no_delete BEFORE DELETE ON IdentityAudit BEGIN SELECT RAISE(ABORT, 'identity audit is append-only'); END";

    internal static void RequireAudit(DbConnection connection, DbTransaction? transaction)
    {
        foreach (var definition in new[] { ("identity_audit_no_update", NoUpdate), ("identity_audit_no_delete", NoDelete) })
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=@name";
            var parameter = command.CreateParameter();
            parameter.ParameterName = "@name"; parameter.Value = definition.Item1;
            command.Parameters.Add(parameter);
            if (command.ExecuteScalar() as string != definition.Item2)
            { throw new AccountStoreException("account.schemaOrIntegrity"); }
        }
    }
}

internal sealed class OidcProfileMap
{
    public string Issuer { get; set; } = "";
    public long Version { get; set; }
    public bool Enabled { get; set; }
    public string DisplayNameClaim { get; set; } = "";
    public string GivenNameClaim { get; set; } = "";
    public string FamilyNameClaim { get; set; } = "";
    public string EmailClaim { get; set; } = "";
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class OidcProfileObservation
{
    public string ActorId { get; set; } = "";
    public string Issuer { get; set; } = "";
    public long MappingVersion { get; set; }
    public string DisplayName { get; set; } = "";
    public string GivenName { get; set; } = "";
    public string FamilyName { get; set; } = "";
    public string Email { get; set; } = "";
    public string ObservedUtc { get; set; } = "";
    public string Diagnostics { get; set; } = "";
}

internal sealed class OidcConnection
{
    public int Id { get; set; } = 1;
    public long Version { get; set; }
    public bool Enabled { get; set; }
    public string Issuer { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string CallbackUri { get; set; } = "";
    public string GroupClaim { get; set; } = "";
    public string AdministratorGroups { get; set; } = "";
    public string AuditorGroups { get; set; } = "";
    public string ProtectedSecret { get; set; } = "";
    public int MfaAssuranceMode { get; set; }
    public string MfaAssuranceClaim { get; set; } = "";
    public string MfaAssuranceValue { get; set; } = "";
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class LdapConnection
{
    public int Id { get; set; } = 1;
    public long Version { get; set; }
    public string DirectoryId { get; set; } = "";
    public bool Enabled { get; set; }
    public string ServerUri { get; set; } = "";
    public string DialIp { get; set; } = "";
    public string UserBaseDn { get; set; } = "";
    public string SearchBindDn { get; set; } = "";
    public string LoginAttribute { get; set; } = "";
    public string AdministratorGroupDn { get; set; } = "";
    public string AuditorGroupDn { get; set; } = "";
    public string DisplayNameAttribute { get; set; } = "";
    public string GivenNameAttribute { get; set; } = "";
    public string FamilyNameAttribute { get; set; } = "";
    public string EmailAttribute { get; set; } = "";
    public string ProtectedSecret { get; set; } = "";
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class LdapSession
{
    public string ActorId { get; set; } = "";
    public long ConnectionGeneration { get; set; }
    public long PolicyVersion { get; set; }
    public string Role { get; set; } = "";
    public string Name { get; set; } = "";
    public string TokenDigest { get; set; } = "";
    public string ProofUtc { get; set; } = "";
    public string ExpiresUtc { get; set; } = "";
}

internal sealed class LdapProfileObservation
{
    public string ActorId { get; set; } = "";
    public Guid DirectoryId { get; set; }
    public long ConnectionGeneration { get; set; }
    public string DisplayName { get; set; } = "";
    public string GivenName { get; set; } = "";
    public string FamilyName { get; set; } = "";
    public string Email { get; set; } = "";
    public string ObservedUtc { get; set; } = "";
    public string Diagnostics { get; set; } = "";
}
