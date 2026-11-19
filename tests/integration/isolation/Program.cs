using Nergal.Core.Deployment;
using Nergal.LocalState;
using Nergal.Identity;
using Microsoft.Extensions.DependencyInjection;

// Storage probe only: no process execution, firewall library or network operations.
if (args.Length != 2 || args[0] is not ("initialize" or "read" or "account-initialize" or "account-read"))
{
    return 2;
}

try
{
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
catch (UnauthorizedAccessException) { Console.Error.WriteLine("path.accessDenied"); return 1; }
