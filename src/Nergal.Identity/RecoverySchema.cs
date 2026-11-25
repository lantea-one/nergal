using Microsoft.EntityFrameworkCore;

namespace Nergal.Identity;

internal static class RecoverySchema
{
    internal static void Configure(ModelBuilder builder)
    {
        builder.Entity<RecoveryGrant>(entity =>
        {
            entity.HasKey(row => row.ActorId);
            entity.HasOne<MfaActorState>().WithOne().HasForeignKey<RecoveryGrant>(row => row.ActorId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasIndex(row => row.Digest).IsUnique();
            entity.ToTable("RecoveryGrant", table => table.HasCheckConstraint("recovery_grant_values", """
                length("Digest") = 64 AND "PolicyVersion" >= 1 AND "TrustVersion" >= 1
                AND "IssuedUtcTicks" > 0 AND "ExpiresUtcTicks" > "IssuedUtcTicks"
                AND "Attempts" BETWEEN 0 AND 3 AND "Watermark" >= 0
                AND (("Issuer" = 'operator:offline' AND "IssuerVersion" = 0) OR "IssuerVersion" >= 1)
                AND (("EnrollmentId" = '' AND length("ProtectedSeed") = 0 AND "Role" = '')
                  OR (length("EnrollmentId") = 32 AND length("ProtectedSeed") BETWEEN 1 AND 4096
                    AND "Role" IN ('nergal:administrator','nergal:auditor')))
                """));
        });
    }
}

// A single row stages a replacement without touching the current authenticator.
// Its digest rotates from the issued authorization to a confirmation-only browser bearer.
internal sealed class RecoveryGrant
{
    public string ActorId { get; set; } = "";
    public string Issuer { get; set; } = "";
    public long IssuerVersion { get; set; }
    public long PolicyVersion { get; set; }
    public long TrustVersion { get; set; }
    public string LocalStamp { get; set; } = "";
    public long Watermark { get; set; }
    public string Digest { get; set; } = "";
    public long IssuedUtcTicks { get; set; }
    public long ExpiresUtcTicks { get; set; }
    public int Attempts { get; set; }
    public string Role { get; set; } = "";
    public string EnrollmentId { get; set; } = "";
    public byte[] ProtectedSeed { get; set; } = [];
}

/// <summary>One-time recovery authorization for delivery to its identified recipient.</summary>
public sealed record RecoveryAuthorization(string Authorization, DateTimeOffset ExpiresUtc)
{
    /// <summary>Suppresses the authorization in diagnostic text.</summary>
    public override string ToString() => nameof(RecoveryAuthorization);
}

/// <summary>One-time manual setup key and its separate confirmation-only browser cookie.</summary>
public sealed record RecoverySetup(string ManualKey, string Continuation, DateTimeOffset ExpiresUtc)
{
    /// <summary>Suppresses the seed and bearer in diagnostic text.</summary>
    public override string ToString() => nameof(RecoverySetup);
}
