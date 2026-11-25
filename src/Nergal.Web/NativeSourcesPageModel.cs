using Nergal.Core.Controller;

namespace Nergal.Web;

/// <summary>Private database source metadata, selected source detail and optional operator staging snapshots.</summary>
public sealed record NativeSourcesPageModel(IReadOnlyList<NativeSourceSummary> Sources,
    NativeSourceSnapshot? Selected, IReadOnlyList<NativePolicySource> Staged, string? Error = null, NativeConversionPage? Conversion = null);
