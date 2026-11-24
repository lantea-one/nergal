using System.Globalization;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

internal static class RouterNatValidation
{
    internal static void Validate(NatPolicy policy, List<PolicyDiagnostic> errors)
    {
        for (var i = 0; i < policy.DnatRules.Count; i++)
        {
            if (policy.DnatRules[i] is not { } r) { continue; }
            var path = $"dnatRules[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (r.OriginalPorts is { } ports)
            {
                if (r.OriginalPort.HasValue) { errors.Add(new("set.conflictsWithScalar", path + ".originalPorts")); }
                if (ports.Count is < 2 or > 64 || ports.Any(p => p is < 1 or > 65535) || ports.Distinct().Count() != ports.Count)
                { errors.Add(new("nat.portSetInvalid", path + ".originalPorts")); }
                if (r.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp)) { errors.Add(new("port.requiresTransport", path + ".originalPorts")); }
            }
            RouterFilterValidation.Require(r.NegateSource, r.Source is not null, path + ".negateSource", errors);
            RouterFilterValidation.Require(r.NegateInputInterface, r.InputInterface is not null, path + ".negateInputInterface", errors);
        }
        for (var i = 0; i < policy.SnatRules.Count; i++)
        {
            if (policy.SnatRules[i] is not { } r) { continue; }
            var path = $"snatRules[{i.ToString(CultureInfo.InvariantCulture)}]";
            if (r.Source is not null && r.SourcePrefixes is not null) { errors.Add(new("set.conflictsWithScalar", path + ".sourcePrefixes")); }
            if (r.Destination is not null && r.DestinationPrefixes is not null) { errors.Add(new("set.conflictsWithScalar", path + ".destinationPrefixes")); }
            NftFilterCompiler.ValidatePrefixSet(r.SourcePrefixes, r.Family, path + ".sourcePrefixes", errors);
            NftFilterCompiler.ValidatePrefixSet(r.DestinationPrefixes, r.Family, path + ".destinationPrefixes", errors);
            if (!Enum.IsDefined(r.Action)) { errors.Add(new("nat.actionUnknown", path + ".action")); }
            if (r.Action != NatPostroutingAction.Snat && r.TranslatedAddress is not null)
            { errors.Add(new("nat.actionConflictsWithAddress", path + ".translatedAddress")); }
            if (r.InputInterface is not null && !FilterPolicyValidation.IsValidInterfaceName(r.InputInterface))
            { errors.Add(new("interface.invalid", path + ".inputInterface")); }
            if (r.Protocol is not (FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp))
            { errors.Add(new("nat.protocolUnsupported", path + ".protocol")); }
            if (r.DestinationPort is < 1 or > 65535) { errors.Add(new("port.outOfRange", path + ".destinationPort")); }
            if ((r.DestinationPort.HasValue || r.DestinationPorts is not null) && r.Protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp))
            { errors.Add(new("port.requiresTransport", path + ".destinationPort")); }
            if (r.DestinationPorts is { } ports)
            {
                if (r.DestinationPort.HasValue) { errors.Add(new("set.conflictsWithScalar", path + ".destinationPorts")); }
                if (ports.Count is < 2 or > 64 || ports.Any(p => p is < 1 or > 65535) || ports.Distinct().Count() != ports.Count)
                { errors.Add(new("nat.portSetInvalid", path + ".destinationPorts")); }
            }
            RouterFilterValidation.Require(r.NegateSource, r.Source is not null || r.SourcePrefixes is not null, path + ".negateSource", errors);
            RouterFilterValidation.Require(r.NegateDestination, r.Destination is not null || r.DestinationPrefixes is not null, path + ".negateDestination", errors);
            RouterFilterValidation.Require(r.NegateInputInterface, r.InputInterface is not null, path + ".negateInputInterface", errors);
            RouterFilterValidation.Require(r.NegateOutputInterface, r.OutputInterface is not null, path + ".negateOutputInterface", errors);
        }
    }
}
