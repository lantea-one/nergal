using Nergal.Core.Controller;

namespace Nergal.Web;

/// <summary>Validated library snapshots and retained form input; no firewall apply authority is represented.</summary>
public sealed record ObjectLibraryPageModel(
    IReadOnlyList<ReusableObjectVersion> Objects,
    IReadOnlyList<ReusableObjectVersion> History,
    ReusableObjectVersion? Selected,
    bool CanMutate,
    string? Query = null,
    ObjectLibraryInput? Input = null,
    string? Error = null);

/// <summary>Untrusted bounded form values retained verbatim on validation failure.</summary>
public sealed record ObjectLibraryInput(Guid? Id, int ExpectedVersion, string Name, string Kind, string Description, string Entries);
