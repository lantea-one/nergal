using Nergal.Core.Policy;

namespace Nergal.Web;

/// <summary>One inline state control bound to the exact submitted immutable draft and rule location.</summary>
public sealed record RuleStateControlModel(PolicyEditorViewModel Editor, PolicyRuleState State);
