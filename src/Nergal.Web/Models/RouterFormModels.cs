namespace Nergal.Web;

/// <summary>Locates a primary filter rule's separate matcher form without duplicating policy intent.</summary>
public sealed record FilterConditionsFormModel(PolicyEditorViewModel Editor, int Index);

/// <summary>Null index adds a postrouting rule; a non-null index edits the complete existing rule.</summary>
public sealed record PostroutingFormModel(PolicyEditorViewModel Editor, int? Index);

/// <summary>Locates a complete raw prerouting editor; null index appends a rule.</summary>
public sealed record RawRuleFormModel(PolicyEditorViewModel Editor, int? Index);

/// <summary>One-step ordered NAT movement controls; kind is dnat or postrouting.</summary>
public sealed record NatRuleMoveModel(PolicyEditorViewModel Editor, string Kind, int Index, int Count);
