using Nergal.Core.Deployment;
using Nergal.LocalState;
using Nergal.Identity;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// Storage probe only: no process execution, firewall library or network operations.
if (args.Length != 2 || args[0] is not ("initialize" or "read" or "account-initialize" or "account-read" or "keys-initialize" or "keys-read"))
{
    return 2;
}

try
{
    if (args[0].StartsWith("keys-", StringComparison.Ordinal))
    {
        if (!OperatingSystem.IsLinux()) { return 2; }
        var options = new ProtectedSessionKeyOptions(args[1]);
        var parent = Path.GetDirectoryName(options.Directory)!;
        var certificatePath = Path.Combine(parent, "synthetic-wrapping.pfx");
        var payloadPath = Path.Combine(parent, "synthetic-protected-payload.bin");
        if (args[0] == "keys-initialize")
        {
            using var rsa = RSA.Create(3072);
            var request = new CertificateRequest("CN=nergal-synthetic-isolation-fixture", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            WritePrivate(certificatePath, generated.Export(X509ContentType.Pfx));
        }
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, null, X509KeyStorageFlags.EphemeralKeySet);
        using var ring = ProtectedSessionKeyRing.Open(options, certificate);
        var protector = ring.CreateProtector("synthetic-isolation-fixture");
        var expected = Encoding.UTF8.GetBytes("synthetic protected state");
        if (args[0] == "keys-initialize") { WritePrivate(payloadPath, protector.Protect(expected)); }
        else if (!protector.Unprotect(File.ReadAllBytes(payloadPath)).SequenceEqual(expected)) { return 1; }
        Console.WriteLine("OK");
        return 0;
    }
    if (args[0].StartsWith("account-", StringComparison.Ordinal))
    {
        if (!OperatingSystem.IsLinux()) { return 2; }
        var options = new LocalAccountOptions(args[1]);
        if (args[0] == "account-initialize") { await LocalAccountDatabase.InitializeAsync(options); }
        await using var services = new ServiceCollection().AddLocalAdministratorAccounts(options).BuildServiceProvider();
        using var scope = services.CreateScope();
        var accounts = scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>();
        const string name = "fixture-admin";
        const string password = "synthetic account fixture password 0001";
        if (args[0] == "account-initialize")
        {
            if (!(await accounts.ProvisionAsync(name, password)).Succeeded) { return 1; }
        }
        else if (!(await accounts.VerifyAsync(name, password)).Succeeded) { return 1; }
        Console.WriteLine("OK");
        return 0;
    }
    if (args[0] == "initialize")
    {
        ApplyJournal.Initialize(args[1], new ResourceOwnership(
            Guid.Parse("00000000-0000-0000-0000-000000000001"), Guid.Parse("00000000-0000-0000-0000-000000000002"), 1), "synthetic private artifact\n");
    }
    else if (ApplyJournal.Open(args[1]).ReadEnrollment().Artifact != "synthetic private artifact\n")
    {
        return 1;
    }

    Console.WriteLine("OK");
    return 0;
}
catch (JournalException error) { Console.Error.WriteLine(error.Code); return 1; }
catch (AccountStoreException error) { Console.Error.WriteLine(error.Code); return 1; }
catch (SessionKeyStoreException error) { Console.Error.WriteLine(error.Code); return 1; }
catch (UnauthorizedAccessException) { Console.Error.WriteLine("path.accessDenied"); return 1; }

static void WritePrivate(string path, byte[] content)
{
    using var file = new FileStream(path, new FileStreamOptions
    { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
    file.Write(content);
    file.Flush(true);
}
