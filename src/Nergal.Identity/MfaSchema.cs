using Microsoft.EntityFrameworkCore;

namespace Nergal.Identity;

internal static class MfaSchema
{
    internal static void Configure(ModelBuilder builder)
    {
        builder.Entity<MfaPolicy>(entity =>
        {
            entity.HasKey(row => row.Id);
            entity.Property(row => row.Id).ValueGeneratedNever();
            entity.ToTable("MfaPolicy", table => table.HasCheckConstraint("mfa_policy_values",
                """
                "Id" = 1 AND typeof("Version") = 'integer' AND "Version" BETWEEN 1 AND 9223372036854775806
                AND typeof("Requirement") = 'integer' AND "Requirement" IN (0, 1, 2)
                """));
        });
        builder.Entity<MfaActorState>(entity =>
        {
            entity.HasKey(row => row.ActorId);
            entity.ToTable("MfaActorState", table =>
            {
                table.HasCheckConstraint("mfa_actor_attempts", """
                    typeof("FailedAttempts") = 'integer' AND "FailedAttempts" BETWEEN 0 AND 5
                    AND typeof("AttemptWindowEndsUtcTicks") = 'integer' AND "AttemptWindowEndsUtcTicks" >= 0
                    """);
                table.HasCheckConstraint("mfa_actor_steps", """
                    typeof("LastAcceptedStep") = 'integer' AND "LastAcceptedStep" >= -1
                    AND typeof("LatestProofUtcTicks") = 'integer' AND "LatestProofUtcTicks" >= 0
                    """);
                table.HasCheckConstraint("mfa_actor_enrollment_time", """
                    typeof("EnrollmentPolicyVersion") = 'integer' AND "EnrollmentPolicyVersion" >= 0
                    AND typeof("EnrollmentEndsUtcTicks") = 'integer' AND "EnrollmentEndsUtcTicks" >= 0
                    """);
                table.HasCheckConstraint("mfa_actor_enrollment", """
                    ("EnrollmentId" = '' AND length("ProtectedSeed") = 0 AND "LastAcceptedStep" = -1 AND "EnrollmentPolicyVersion" = 0)
                    OR (length("EnrollmentId") = 32 AND length("ProtectedSeed") BETWEEN 1 AND 4096 AND "EnrollmentPolicyVersion" >= 1)
                    """);
            });
        });
        builder.Entity<MfaPendingProof>(entity =>
        {
            entity.HasKey(row => row.ActorId);
            entity.HasOne<MfaActorState>().WithOne().HasForeignKey<MfaPendingProof>(row => row.ActorId);
            entity.HasIndex(row => row.Id).IsUnique();
            entity.ToTable("MfaPendingProof", table => table.HasCheckConstraint("mfa_pending_values", """
                typeof("PolicyVersion") = 'integer' AND "PolicyVersion" >= 1
                AND typeof("FailedAttempts") = 'integer' AND "FailedAttempts" BETWEEN 0 AND 2
                AND typeof("UsesEmail") = 'integer' AND "UsesEmail" IN (0, 1)
                AND length("Id") = 32 AND length("ProtectedProof") BETWEEN 1 AND 32768
                """));
        });
    }

    // Explicit fresh-store initialization only. A missing singleton is never recreated on access.
    internal static async Task InitializeAsync(LocalAccountContext context, CancellationToken token)
    {
        context.Add(new MfaPolicy());
        await context.SaveChangesAsync(token);
    }
}

internal sealed class MfaPolicy
{
    public int Id { get; set; } = 1;
    public long Version { get; set; } = 1;
    public MfaRequirement Requirement { get; set; } = MfaRequirement.Optional;
}

internal sealed class MfaActorState
{
    public string ActorId { get; set; } = "";
    public long LatestProofUtcTicks { get; set; }
    public int FailedAttempts { get; set; }
    public long AttemptWindowEndsUtcTicks { get; set; }
    public string EnrollmentId { get; set; } = "";
    public byte[] ProtectedSeed { get; set; } = [];
    public long EnrollmentPolicyVersion { get; set; }
    public string EnrollmentAuthority { get; set; } = "";
    public long EnrollmentEndsUtcTicks { get; set; }
    public long LastAcceptedStep { get; set; } = -1;
}

internal sealed class MfaPendingProof
{
    public string ActorId { get; set; } = "";
    public string Id { get; set; } = "";
    public long PolicyVersion { get; set; }
    public int FailedAttempts { get; set; }
    public bool UsesEmail { get; set; }
    public string ProtectedProof { get; set; } = "";
}
