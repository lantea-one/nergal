namespace Nergal.Identity;

/// <summary>Explicit private local application-account storage; unrelated to Linux users or firewall enrollment.</summary>
public sealed class LocalAccountOptions
{
    /// <summary>Creates an account-store location without creating directories, files or accounts.</summary>
    /// <exception cref="ArgumentException">Directory is missing, relative or contains a NUL.</exception>
    public LocalAccountOptions(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory) || directory.Contains('\0'))
        {
            throw new ArgumentException("An absolute NUL-free account directory is required.", nameof(directory));
        }
        Directory = Path.GetFullPath(directory);
    }
    /// <summary>Gets the explicitly provisioned service-owned private directory.</summary>
    public string Directory { get; }
}

/// <summary>Stable private-store failure without paths, credentials, hashes or raw database diagnostics.</summary>
public sealed class AccountStoreException : Exception
{
    internal AccountStoreException(string code) : base(code) => Code = code;
    /// <summary>Gets the stable diagnostic identifier.</summary>
    public string Code { get; }
}

/// <summary>Complete credential-verification result; unknown, incorrect and locked-out accounts are indistinguishable.</summary>
public sealed class LocalCredentialResult
{
    internal LocalCredentialResult(Guid? administratorId) => AdministratorId = administratorId;
    /// <summary>Gets whether the password and current account state permitted sign-in. No browser session is issued.</summary>
    public bool Succeeded => AdministratorId.HasValue;
    /// <summary>Gets the verified administrator identifier only on success; contains no credential or hash.</summary>
    public Guid? AdministratorId { get; }
}

/// <summary>Explicit provisioning outcome containing only stable validation codes, never supplied secrets.</summary>
public sealed class LocalProvisionResult
{
    internal LocalProvisionResult(IEnumerable<string> codes) => ErrorCodes = Array.AsReadOnly(codes.ToArray());
    /// <summary>Gets whether the sole administrator was created.</summary>
    public bool Succeeded => ErrorCodes.Count == 0;
    /// <summary>Gets immutable validation codes; descriptions and caller input are not retained.</summary>
    public IReadOnlyList<string> ErrorCodes { get; }
}
