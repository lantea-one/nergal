using Microsoft.EntityFrameworkCore;

namespace Nergal.Identity;

internal static class OAuthSchema
{
    internal const string ConnectionCheck = """
        "Id" = 1 AND typeof("Version") = 'integer' AND "Version" >= 1 AND length("ConnectionId") = 36
        """;

    internal static void Configure(ModelBuilder builder)
    {
        builder.Entity<OAuthConnection>(entity =>
        {
            entity.HasKey(row => row.Id);
            entity.Property(row => row.Id).ValueGeneratedNever();
            entity.ToTable(table => table.HasCheckConstraint("oauth_connection", ConnectionCheck));
        });
        builder.Entity<OAuthProfileObservation>().HasKey(row => row.ActorId);
    }
}

internal sealed class OAuthConnection
{
    public int Id { get; set; } = 1;
    public long Version { get; set; }
    public string ConnectionId { get; set; } = "";
    public string Settings { get; set; } = "";
    public string ProtectedSecret { get; set; } = "";
    public string UpdatedUtc { get; set; } = "";
}

internal sealed class OAuthProfileObservation
{
    public string ActorId { get; set; } = "";
    public string Endpoint { get; set; } = "";
    public long Generation { get; set; }
    public string DisplayName { get; set; } = "";
    public string GivenName { get; set; } = "";
    public string FamilyName { get; set; } = "";
    public string Email { get; set; } = "";
    public string ObservedUtc { get; set; } = "";
    public string Diagnostics { get; set; } = "";
}
