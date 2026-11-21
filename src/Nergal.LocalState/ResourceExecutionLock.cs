using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.Versioning;

namespace Nergal.LocalState;

/// <summary>Per-resource exclusive OS lock protecting local native observation, creation, and journal decisions.</summary>
/// <remarks>Requires a trusted service-owned 0700 parent directory; not a defense against a malicious same-account or root actor.</remarks>
[SupportedOSPlatform("linux")]
public sealed class ResourceExecutionLock : IDisposable
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> ProcessGates = new(StringComparer.Ordinal);
    private readonly FileStream stream;
    private readonly SemaphoreSlim processGate;
    private int disposed;

    private ResourceExecutionLock(FileStream stream, SemaphoreSlim processGate)
    {
        this.stream = stream;
        this.processGate = processGate;
    }

    /// <summary>Validates the private state directory and acquires an exclusive process and OS lock on <c>resource.lock</c>.</summary>
    /// <param name="directory">Existing absolute nonsymlink 0700 directory owned by the effective Linux UID.</param>
    /// <param name="timeout">Positive bounded wait limit up to five minutes.</param>
    /// <param name="cancellation">Cancellation token checked before and during lock acquisition.</param>
    /// <returns>An owned lock handle that releases the OS and process lock upon disposal.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Timeout is non-positive or exceeds five minutes.</exception>
    /// <exception cref="JournalException">Directory or lock file protection fails, or lock acquisition times out.</exception>
    public static async Task<ResourceExecutionLock> AcquireAsync(string directory, TimeSpan timeout, CancellationToken cancellation = default)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("The resource execution lock requires Linux.");
        }

        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "Lock timeout must be positive and at most five minutes.");
        }

        cancellation.ThrowIfCancellationRequested();
        _ = PrivateJournalPath.Validate(directory, databaseRequired: false);
        var fullDirectory = Path.GetFullPath(directory);
        var gate = ProcessGates.GetOrAdd(fullDirectory, _ => new SemaphoreSlim(1, 1));
        var started = Stopwatch.GetTimestamp();
        if (!await gate.WaitAsync(timeout, cancellation).ConfigureAwait(false))
        {
            throw new JournalException("resource.lockTimeout");
        }

        FileStream? stream = null;
        try
        {
            var lockPath = Path.Combine(fullDirectory, "resource.lock");
            var existing = LinuxFileMetadata.Read(lockPath);
            if (existing is not null)
            {
                LinuxFileMetadata.Validate(existing.Value, directory: false);
            }

            stream = new FileStream(lockPath, new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.ReadWrite,
                UnixCreateMode = PrivateJournalPath.FileMode,
            });
            var current = LinuxFileMetadata.Read(lockPath) ?? throw new JournalException("path.metadataUnavailable");
            LinuxFileMetadata.Validate(current, directory: false);

            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                try
                {
                    stream.Lock(0, 1);
                    return new(stream, gate);
                }
                catch (IOException)
                {
                    if (Stopwatch.GetElapsedTime(started) >= timeout)
                    {
                        throw new JournalException("resource.lockTimeout");
                    }

                    await Task.Delay(10, cancellation).ConfigureAwait(false);
                }
            }
        }
        catch
        {
            stream?.Dispose();
            gate.Release();
            throw;
        }
    }

    /// <summary>Releases the OS byte-range lock, closes the lock descriptor, and releases the in-process gate.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        try { stream.Unlock(0, 1); }
        catch (IOException) { }
        stream.Dispose();
        processGate.Release();
    }
}
