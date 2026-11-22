namespace Nergal.ControllerState;

/// <summary>Explicit private storage directory options for the controller SQLite database.</summary>
public sealed class ControllerStateOptions
{
    /// <summary>Validates an absolute NUL-free directory path for controller state persistence.</summary>
    /// <exception cref="ArgumentException">Directory is empty, relative, or contains a NUL character.</exception>
    public ControllerStateOptions(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (!Path.IsPathFullyQualified(directory) || directory.Contains('\0'))
        {
            throw new ArgumentException("An absolute NUL-free controller state directory is required.", nameof(directory));
        }

        Directory = Path.GetFullPath(directory);
    }

    /// <summary>Gets the canonical absolute state directory path.</summary>
    public string Directory { get; }
}

/// <summary>Stable diagnostic failure thrown when controller persistence validation or integrity fails.</summary>
public sealed class ControllerStateException : Exception
{
    internal ControllerStateException(string code) : base(code) => Code = code;

    internal ControllerStateException(string code, Exception innerException) : base(code, innerException) => Code = code;

    /// <summary>Gets the stable error identifier.</summary>
    public string Code { get; }
}
