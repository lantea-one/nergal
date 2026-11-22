namespace Nergal.RemoteTransport;

/// <summary>Stable TLS 1.3 control transport failure containing no request, policy, or secret material.</summary>
public sealed class RemoteTransportException : Exception
{
    internal RemoteTransportException(string code) : base(code) => Code = code;

    internal RemoteTransportException(string code, Exception innerException) : base(code, innerException) => Code = code;

    /// <summary>Gets the stable diagnostic error identifier.</summary>
    public string Code { get; }
}
