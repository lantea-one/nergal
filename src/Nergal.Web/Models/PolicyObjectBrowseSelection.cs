namespace Nergal.Web;

/// <summary>Retained UI selection for one history browse; it carries no policy mutation or apply authority.</summary>
public sealed record PolicyObjectBrowseSelection(string Scope, int RuleIndex, string Slot, string? Chain, Guid ObjectId, int Version);
