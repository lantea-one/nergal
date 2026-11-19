namespace Nergal.Identity;

/// <summary>Explicit private session-key directory and stable application isolation discriminator; creates nothing.</summary>
public sealed class ProtectedSessionKeyOptions
{
    /// <summary>Defines a separately provisioned key directory and application scope.</summary>
    /// <param name="directory">Absolute NUL-free service-owned 0700 local directory.</param>
    /// <param name="applicationName">Stable 1–128 ASCII letters/digits/dot/dash/underscore discriminator; must stay unchanged across restarts.</param>
    /// <exception cref="ArgumentException">Directory or discriminator is invalid.</exception>
    public ProtectedSessionKeyOptions(string directory, string applicationName = "nergal.local-administrator")
    {
        Directory = new LocalAccountOptions(directory).Directory;
        ArgumentException.ThrowIfNullOrWhiteSpace(applicationName);
        if (applicationName.Length > 128 || !applicationName.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_'))
        { throw new ArgumentException("A bounded ASCII application discriminator is required.", nameof(applicationName)); }
        ApplicationName = applicationName;
    }
    /// <summary>Gets the explicit private key directory, distinct from account/journal storage.</summary>
    public string Directory { get; }
    /// <summary>Gets the stable application discriminator.</summary>
    public string ApplicationName { get; }
}

/// <summary>Stable protected-key failure containing no key, certificate, plaintext, payload or path contents.</summary>
public sealed class SessionKeyStoreException : IOException
{
    internal SessionKeyStoreException(string code) : base(code) => Code = code;
    /// <summary>Gets the stable diagnostic identifier.</summary>
    public string Code { get; }
}
