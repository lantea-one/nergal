using Microsoft.Extensions.DependencyInjection;
using Nergal.Identity;
using Nergal.Admin;

const string usage = """
    Usage:
      nergal-admin account init <absolute-directory>
      nergal-admin account provision <absolute-directory> <username> [--password-stdin]
    Provisioning without --password-stdin prompts twice without echo on a terminal.
    The explicit stdin mode reads one UTF-8 password line to EOF (optional final LF or CRLF).
    """;
if (args is ["--help"]) { Console.WriteLine(usage); return 0; }
if (!OperatingSystem.IsLinux()) { Console.Error.WriteLine("platform.unsupported"); return 1; }
var initialize = args is ["account", "init", _];
var interactive = args is ["account", "provision", _, _];
var pipe = args is ["account", "provision", _, _, "--password-stdin"];
if (!initialize && !interactive && !pipe) { Console.Error.WriteLine(usage); return 2; }
try
{
    var options = new LocalAccountOptions(args[2]);
    if (initialize)
    {
        await LocalAccountDatabase.InitializeAsync(options);
        Console.WriteLine("Account database initialized.");
        return 0;
    }
    if (Console.IsInputRedirected != pipe) { Console.Error.WriteLine("password.inputMode"); return 2; }
    var password = pipe ? await PasswordInput.ReadPipeAsync(Console.OpenStandardInput()) : PasswordInput.ReadConfirmed();
    using var services = new ServiceCollection().AddLocalAdministratorAccounts(options).BuildServiceProvider();
    using var scope = services.CreateScope();
    var result = await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().ProvisionAsync(args[3], password);
    if (!result.Succeeded)
    {
        foreach (var code in result.ErrorCodes) { Console.Error.WriteLine(code); }
        return 1;
    }
    Console.WriteLine("Local administrator provisioned.");
    return 0;
}
catch (AccountStoreException error) { Console.Error.WriteLine(error.Code); }
catch (Exception error) when (error is InvalidDataException or System.Text.DecoderFallbackException) { Console.Error.WriteLine("password.invalidInput"); }
catch (ArgumentException) { Console.Error.WriteLine("account.invalidInput"); }
catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
{ Console.Error.WriteLine("account.unavailable"); }
return 1;
