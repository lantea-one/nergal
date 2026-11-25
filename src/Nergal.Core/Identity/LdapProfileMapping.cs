using System.Text;

namespace Nergal.Core.Identity;

/// <summary>Literal LDAP attribute selectors for descriptive profile defaults. Empty selectors disable fields.</summary>
public sealed record LdapProfileMapping(string DisplayNameAttribute = "", string GivenNameAttribute = "",
    string FamilyNameAttribute = "", string EmailAttribute = "")
{
    private static readonly HashSet<string> ProfileAttributes = new(StringComparer.OrdinalIgnoreCase)
    { "cn", "displayName", "givenName", "sn", "mail" };

    /// <summary>Checks that all selectors are empty or approved descriptive LDAP attributes.</summary>
    public bool IsValid => Selectors.All(attribute => attribute == "" || attribute is not null && ProfileAttributes.Contains(attribute));

    /// <summary>Returns the distinct optional attributes to add to an explicit LDAP selection that includes <c>entryUUID</c>.</summary>
    /// <remarks>An empty LDAP search selection fetches all user attributes. This property contains only the optional portion.</remarks>
    /// <exception cref="InvalidOperationException">A selector is malformed.</exception>
    public IReadOnlyList<string> SelectedAttributes => Array.AsReadOnly(IsValid
        ? Selectors.Where(attribute => attribute.Length != 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
        : throw new InvalidOperationException("LDAP profile selectors are invalid."));

    /// <summary>Projects optional values supplied by an already verified directory lookup into descriptive metadata.</summary>
    /// <exception cref="ArgumentException">A selector is malformed or the lookup contains duplicate attribute names.</exception>
    /// <exception cref="ArgumentNullException">The verified attributes collection is null.</exception>
    public (ProfileMetadata Metadata, IReadOnlyList<string> Diagnostics) Project(
        IEnumerable<KeyValuePair<string, IReadOnlyList<byte[]>>> verifiedAttributes)
    {
        ArgumentNullException.ThrowIfNull(verifiedAttributes);
        if (!IsValid) { throw new ArgumentException("LDAP profile selectors are invalid."); }
        var requested = SelectedAttributes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var values = new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        foreach (var attribute in verifiedAttributes)
        {
            if (requested.Contains(attribute.Key) && !values.TryAdd(attribute.Key, attribute.Value))
            { throw new ArgumentException("LDAP profile attributes are ambiguous.", nameof(verifiedAttributes)); }
        }

        var diagnostics = new List<string>();
        var metadata = new ProfileMetadata(
            Read(DisplayNameAttribute, "displayName", text => ProfileMetadata.ValidText(text, 80)),
            Read(GivenNameAttribute, "givenName", text => ProfileMetadata.ValidText(text, 80)),
            Read(FamilyNameAttribute, "familyName", text => ProfileMetadata.ValidText(text, 80)),
            Read(EmailAttribute, "email", ProfileMetadata.ValidEmail));
        return (metadata, diagnostics.AsReadOnly());

        string Read(string selector, string field, Func<string, bool> valid)
        {
            if (selector.Length == 0) { return ""; }
            if (!values.TryGetValue(selector, out var entries) || entries is { Count: 0 })
            { diagnostics.Add(field + ".missing"); return ""; }
            if (entries is { Count: 1 } && entries[0] is { Length: <= 1024 } bytes)
            {
                try
                {
                    var text = new UTF8Encoding(false, true).GetString(bytes);
                    if (string.IsNullOrWhiteSpace(text)) { diagnostics.Add(field + ".missing"); return ""; }
                    if (valid(text)) { return text; }
                }
                catch (DecoderFallbackException) { /* Trailing or malformed UTF-8 is not usable profile text. */ }
            }
            diagnostics.Add(field + ".invalid");
            return "";
        }
    }

    private string[] Selectors => [DisplayNameAttribute, GivenNameAttribute, FamilyNameAttribute, EmailAttribute];
}
