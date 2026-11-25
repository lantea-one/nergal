using Nergal.Core.Identity;

namespace Nergal.Web;

/// <summary>Credential-free view model. Never attach submitted or decrypted secrets.</summary>
public sealed record OidcConnectionPageModel(OidcConnectionSnapshot? Connection, string? Error = null);
