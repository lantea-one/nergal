namespace Nergal.Core.Policy;

/// <summary>Independent early inet filter table for additional input/forward restrictions.</summary>
/// <remarks>This is a compiler-preview contract. Agent apply is denied until independent ownership,
/// complete observation, and rollback of the additional table are implemented.</remarks>
/// <param name="Priority">Base-chain priority in -300..300, usually -5.</param>
/// <param name="Filter">Schema-2 filtering rules. Raw prerouting and MSS clamping belong to the primary table.</param>
public sealed record AuxiliaryFilterPolicy(int Priority, FilterPolicy Filter);
