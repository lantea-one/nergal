namespace Nergal.Core.Identity;

/// <summary>Validates the inputs to the directory's single equality assertion for locating a user.</summary>
public static class LdapUserLookup
{
    private static readonly HashSet<string> LoginAttributes = new(StringComparer.OrdinalIgnoreCase) { "uid", "cn", "mail" };

    /// <summary>Checks whether the login selector is a supported LDAP user attribute.</summary>
    public static bool IsValidAttribute(string? attribute) => attribute is not null && LoginAttributes.Contains(attribute);

    /// <summary>Checks that a submitted sign-in name can be encoded as one bounded LDAP assertion value.</summary>
    public static bool IsValidUsername(string? username) =>
        !string.IsNullOrWhiteSpace(username) && ProfileMetadata.ValidText(username, 128);
}
