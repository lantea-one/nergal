namespace Nergal.Nftables;

/// <summary>Byte bounds shared by native evidence capture, admission and verification.</summary>
public static class NftObservationLimits
{
    /// <summary>Maximum size of a complete table listing or atomic creation echo.</summary>
    public const int MaximumDocumentBytes = 256 * 1024;

    /// <summary>Maximum size of a table inventory or a standalone named-set response.</summary>
    public const int MaximumInventoryBytes = 64 * 1024;
}
