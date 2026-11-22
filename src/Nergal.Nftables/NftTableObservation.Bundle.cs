using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

public sealed partial class NftTableObservation
{
    private NftTableObservation(NftTableObservation primary, NftNatTableObservation? nat,
        NftBridgeTableObservation? bridge, NftAuxiliaryTableObservation? auxiliary)
    {
        Identity = primary.Identity; TableHandle = primary.TableHandle; ChainHandle = primary.ChainHandle;
        ForwardChainHandle = primary.ForwardChainHandle; OutputChainHandle = primary.OutputChainHandle; Policy = primary.Policy;
        Nat = nat; Bridge = bridge; Auxiliary = auxiliary;
        if (primary.Nat is not null || primary.Bridge is not null || primary.Auxiliary is not null)
        { throw new ArgumentException("A complete observation cannot be nested.", nameof(primary)); }
        if ((nat is not null && nat.Identity != Identity) || (bridge is not null && bridge.Identity != Identity) || (auxiliary is not null && auxiliary.Identity != Identity))
        { throw new ArgumentException("Bundle component identities disagree."); }
        StateDigest = nat is null && bridge is null && auxiliary is null ? primary.StateDigest : CandidateDigest.FromText(string.Join('\n',
            "nergal-bundle-observation-v1", primary.StateDigest.Value,
            nat?.StateDigest.Value ?? "-", bridge?.StateDigest.Value ?? "-", auxiliary?.StateDigest.Value ?? "-"));
    }
    /// <summary>Gets the complete optional NAT snapshot, including its native handles.</summary>
    public NftNatTableObservation? Nat { get; }
    /// <summary>Gets the complete optional bridge snapshot, including regular chains and native handles.</summary>
    public NftBridgeTableObservation? Bridge { get; }
    /// <summary>Gets the complete optional early inet snapshot.</summary>
    public NftAuxiliaryTableObservation? Auxiliary { get; }
    /// <summary>Gets a bundle reconstructed from every recognized owned table.</summary>
    public FirewallPolicyBundle Bundle => new(1, Policy, Nat?.Policy, Bridge?.Policy, Auxiliary?.Policy);
    /// <summary>Combines complete locally collected component snapshots; identities must agree.</summary>
    /// <remarks>The caller must collect every present owned table under its execution lock. This does not confer ownership authority.</remarks>
    public static NftTableObservation Combine(NftTableObservation primary, NftNatTableObservation? nat = null,
        NftBridgeTableObservation? bridge = null, NftAuxiliaryTableObservation? auxiliary = null)
    {
        ArgumentNullException.ThrowIfNull(primary);
        return new(primary, nat, bridge, auxiliary);
    }
}
