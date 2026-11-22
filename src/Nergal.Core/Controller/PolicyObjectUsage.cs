namespace Nergal.Core.Controller;

/// <summary>A saved revision's immutable reference to one library version, never an active-kernel usage claim.</summary>
public sealed record PolicyObjectUsage(ulong Revision, string Path, int ObjectVersion);

