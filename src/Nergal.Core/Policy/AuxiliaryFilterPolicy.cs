namespace Nergal.Core.Policy;

/// <summary>Independent early inet filter table for additional input/forward restrictions.</summary>
/// <remarks>Agent apply requires complete owned-table observation, native receipts, atomic replacement,
/// and independent rollback covering the additional table. Unknown or drifted state is not adopted.</remarks>
/// <param name="Priority">Base-chain priority in -300..300, usually -5.</param>
/// <param name="Filter">Schema-2 filtering rules. Raw prerouting and MSS clamping belong to the primary table.</param>
public sealed record AuxiliaryFilterPolicy(int Priority, FilterPolicy Filter);
