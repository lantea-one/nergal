namespace Nergal.Nftables;

/// <summary>Typed table marker; a marker alone never establishes ownership or authorization.</summary>
public sealed record NftTableIdentity
{
    private const string Prefix = "nergal:v1:";

    /// <summary>Creates an identity from trusted enrolled owner and unique resource-birth UUIDs.</summary>
    /// <exception cref="ArgumentException">An identity is empty.</exception>
    public NftTableIdentity(Guid ownerId, Guid resourceId)
    {
        if (ownerId == Guid.Empty)
        {
            throw new ArgumentException("Owner identity is required.", nameof(ownerId));
        }

        if (resourceId == Guid.Empty)
        {
            throw new ArgumentException("Resource identity is required.", nameof(resourceId));
        }

        OwnerId = ownerId;
        ResourceId = resourceId;
    }

    /// <summary>Gets the enrolled owner identity, not a browser-supplied authority claim.</summary>
    public Guid OwnerId { get; }
    /// <summary>Gets the unique identity for this resource birth, not a table name.</summary>
    public Guid ResourceId { get; }
    /// <summary>Gets a fixed canonical native comment containing only a prefix and lowercase UUIDs.</summary>
    public string Comment => Prefix + OwnerId.ToString("N") + ":" + ResourceId.ToString("N");

    internal static NftTableIdentity? Parse(string comment)
    {
        if (comment.Length != Prefix.Length + 65 || !comment.StartsWith(Prefix, StringComparison.Ordinal) ||
            comment[Prefix.Length + 32] != ':' ||
            !Guid.TryParseExact(comment.AsSpan(Prefix.Length, 32), "N", out var owner) || owner == Guid.Empty ||
            !Guid.TryParseExact(comment.AsSpan(Prefix.Length + 33, 32), "N", out var resource) || resource == Guid.Empty)
        {
            return null;
        }

        var identity = new NftTableIdentity(owner, resource);
        return identity.Comment == comment ? identity : null;
    }
}
