namespace Nergal.Web;

/// <summary>A supported destination-port matcher choice, addressed by its stable index in the submitted draft.</summary>
public sealed record TransportReferenceRuleOption(int Index, string Label);

/// <summary>Explicit table/chain-scoped immutable port-list selector; scope is postrouting, bridge or bridgeChain.</summary>
public sealed record TransportReferenceFormModel(PolicyEditorViewModel Editor, string Scope, string? Chain, IReadOnlyList<TransportReferenceRuleOption> Rules);
