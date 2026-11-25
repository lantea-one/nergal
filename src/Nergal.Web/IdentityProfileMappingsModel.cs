using Nergal.Core.Identity;

namespace Nergal.Web;

/// <summary>Credential-free administrator mapping view. Mappings are descriptive and cannot activate authentication.</summary>
public sealed record IdentityProfileMappingsModel(IReadOnlyList<OidcProfileMapping> Mappings, string? Error = null);
