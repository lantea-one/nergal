namespace Nergal.Web;

/// <summary>Locates a primary filter rule's separate matcher form without duplicating policy intent.</summary>
public sealed record FilterConditionsFormModel(PolicyEditorViewModel Editor, int Index);

/// <summary>Null index adds a postrouting rule; a non-null index edits the complete existing rule.</summary>
public sealed record PostroutingFormModel(PolicyEditorViewModel Editor, int? Index);
