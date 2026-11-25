using Microsoft.EntityFrameworkCore;

namespace Nergal.Identity;

internal static class EmailMfaSchema
{
    internal static void Configure(ModelBuilder builder)
    {
        builder.Entity<EmailMfaActorState>(entity =>
        {
            entity.HasKey(row => row.ActorId);
            entity.HasOne<MfaActorState>().WithOne().HasForeignKey<EmailMfaActorState>(row => row.ActorId);
            entity.ToTable("EmailMfaActorState", table =>
            {
                table.HasCheckConstraint("email_mfa_address", """
                    ("AddressId" = '' AND "ProtectedAddress" = '')
                    OR (length("AddressId") = 32 AND length("ProtectedAddress") BETWEEN 1 AND 4096)
                    """);
                table.HasCheckConstraint("email_mfa_sends", """
                    typeof("Sends") = 'integer' AND "Sends" BETWEEN 0 AND 3
                    AND typeof("SendWindowEndsUtcTicks") = 'integer' AND "SendWindowEndsUtcTicks" >= 0
                    """);
            });
        });
        builder.Entity<EmailMfaCode>(entity =>
        {
            entity.HasKey(row => new { row.ActorId, row.Stage });
            entity.HasOne<EmailMfaActorState>().WithMany().HasForeignKey(row => row.ActorId);
            entity.ToTable("EmailMfaCode", table =>
            {
                table.HasCheckConstraint("email_mfa_code_values", """
                    typeof("Stage") = 'integer' AND "Stage" IN (1, 2)
                    AND length("Id") = 32 AND length("ProtectedCode") BETWEEN 1 AND 4096
                    AND typeof("PolicyVersion") = 'integer' AND "PolicyVersion" >= 1
                    AND typeof("DeliveryGeneration") = 'integer' AND "DeliveryGeneration" >= 1
                    AND typeof("EndsUtcTicks") = 'integer' AND "EndsUtcTicks" > 0
                    """);
                table.HasCheckConstraint("email_mfa_code_stage", """
                    ("Stage" = 1 AND length("Binding") BETWEEN 1 AND 4096 AND length("ProtectedAddress") BETWEEN 1 AND 4096)
                    OR ("Stage" = 2 AND length("Binding") = 32 AND "ProtectedAddress" = '')
                    """);
                table.HasCheckConstraint("email_mfa_code_attempts", """
                    typeof("FailedAttempts") = 'integer' AND "FailedAttempts" BETWEEN 0 AND 2
                    AND ("Stage" = 1 OR "FailedAttempts" = 0)
                    """);
            });
        });
    }
}

internal enum EmailMfaStage { Enrollment = 1, SignIn = 2 }

internal sealed class EmailMfaActorState
{
    public string ActorId { get; set; } = "";
    public string AddressId { get; set; } = "";
    public string ProtectedAddress { get; set; } = "";
    public int Sends { get; set; }
    public long SendWindowEndsUtcTicks { get; set; }
}

internal sealed class EmailMfaCode
{
    public string ActorId { get; set; } = "";
    public EmailMfaStage Stage { get; set; }
    public string Id { get; set; } = "";
    public string Binding { get; set; } = "";
    public long PolicyVersion { get; set; }
    public long DeliveryGeneration { get; set; }
    public long EndsUtcTicks { get; set; }
    public string ProtectedCode { get; set; } = "";
    public string ProtectedAddress { get; set; } = "";
    public int FailedAttempts { get; set; }
}
