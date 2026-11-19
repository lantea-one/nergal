using Nergal.Core.Deployment;

namespace Nergal.Nftables;

/// <summary>Expected native resource binding that must originate in protected enrollment, never request data.</summary>
/// <remarks>This POCO is not an authorization token, and no protected persistence/enrollment API is implemented here.</remarks>
public sealed record NftTableReceipt
{
    /// <summary>Creates a fully bound expected receipt for later unprivileged comparison.</summary>
    /// <exception cref="ArgumentException">Boot identity is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Namespace or table handle is zero.</exception>
    /// <exception cref="ArgumentNullException">Identity or digest is null.</exception>
    public NftTableReceipt(Guid bootId, ulong networkNamespace, NftTableIdentity identity, ulong tableHandle, CandidateDigest stateDigest)
    {
        if (bootId == Guid.Empty)
        {
            throw new ArgumentException("Boot identity is required.", nameof(bootId));
        }

        if (networkNamespace == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(networkNamespace));
        }

        if (tableHandle == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tableHandle));
        }

        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(stateDigest);
        BootId = bootId;
        NetworkNamespace = networkNamespace;
        Identity = identity;
        TableHandle = tableHandle;
        StateDigest = stateDigest;
    }
    /// <summary>Gets the expected boot identity, preventing cross-reboot handle reuse.</summary>
    public Guid BootId { get; }
    /// <summary>Gets the expected Linux network namespace inode identity.</summary>
    public ulong NetworkNamespace { get; }
    /// <summary>Gets the protected expected owner/resource-birth marker.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the expected positive kernel table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the expected complete native observation fingerprint.</summary>
    public CandidateDigest StateDigest { get; }
}

/// <summary>Compares trusted expected bindings with a complete observation without reading or modifying a host.</summary>
public static class NftReceiptVerifier
{
    /// <summary>Reports every binding mismatch in stable context/identity/handle/state order.</summary>
    /// <param name="expected">Expected receipt from protected enrollment; never promote the current observation to expected state automatically.</param>
    /// <param name="actual">Complete parsed native observation.</param>
    /// <param name="currentBoot">Trusted current boot identity supplied by the agent, not request data.</param>
    /// <param name="currentNamespace">Trusted current namespace identity supplied by the agent.</param>
    /// <exception cref="ArgumentNullException">Expected receipt or observation is null.</exception>
    public static NftReceiptCheck Verify(NftTableReceipt expected, NftTableObservation actual, Guid currentBoot, ulong currentNamespace)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(actual);
        var errors = new List<string>();
        if (currentBoot == Guid.Empty || currentNamespace == 0)
        {
            errors.Add("context.invalid");
        }

        if (currentBoot != expected.BootId)
        {
            errors.Add("context.bootChanged");
        }

        if (currentNamespace != expected.NetworkNamespace)
        {
            errors.Add("context.namespaceChanged");
        }

        if (actual.Identity != expected.Identity)
        {
            errors.Add("identity.mismatch");
        }

        if (actual.TableHandle != expected.TableHandle)
        {
            errors.Add("handle.mismatch");
        }

        if (actual.StateDigest != expected.StateDigest)
        {
            errors.Add("state.drift");
        }

        return new(errors);
    }
}

/// <summary>An immutable comparison result, not authority to perform a native operation.</summary>
public sealed class NftReceiptCheck
{
    internal NftReceiptCheck(IEnumerable<string> errors) => ErrorCodes = Array.AsReadOnly(errors.ToArray());
    /// <summary>Gets mismatch codes in stable order without native input contents.</summary>
    public IReadOnlyList<string> ErrorCodes { get; }
    /// <summary>Gets whether every binding matched; authorization and serialized native mutation remain separate obligations.</summary>
    public bool IsMatch => ErrorCodes.Count == 0;
}
