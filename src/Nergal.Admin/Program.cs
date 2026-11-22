using Microsoft.Extensions.DependencyInjection;
using Nergal.Admin;
using Nergal.ControllerState;
using Nergal.Core.Identity;
using Nergal.Identity;

const string usage = """
    Usage:
      nergal-admin account init <absolute-directory>
      nergal-admin account provision <absolute-directory> <username> [--role <administrator|auditor>] [--password-stdin]
      nergal-admin controller init <absolute-directory>
    Provisioning without --password-stdin prompts twice without echo on a terminal.
    The explicit stdin mode reads one UTF-8 password line to EOF (optional final LF or CRLF).
    """;
if (args is ["--help"]) { Console.WriteLine(usage); return 0; }
if (!OperatingSystem.IsLinux()) { Console.Error.WriteLine("platform.unsupported"); return 1; }
if (args is ["controller", "init", var controllerDir])
{
    try
    {
        _ = ControllerStateStore.Initialize(new ControllerStateOptions(controllerDir));
        Console.WriteLine("Controller state database initialized.");
        return 0;
    }
    catch (ControllerStateException error) { Console.Error.WriteLine(error.Code); }
    catch (ArgumentException) { Console.Error.WriteLine("controller.invalidInput"); }
    catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
    { Console.Error.WriteLine("controller.unavailable"); }
    return 1;
}

var initialize = args is ["account", "init", _];
var pipe = false;
var role = NergalRoles.Administrator;
var validProvision = false;
if (!initialize && args.Length >= 4 && args[0] == "account" && args[1] == "provision")
{
    var index = 4;
    validProvision = true;
    while (index < args.Length)
    {
        if (args[index] == "--password-stdin" && !pipe)
        {
            pipe = true;
            index++;
        }
        else if (args[index] == "--role" && index + 1 < args.Length)
        {
            role = args[index + 1] switch
            {
                "administrator" => NergalRoles.Administrator,
                "auditor" => NergalRoles.Auditor,
                _ => "",
            };
            if (role.Length == 0) { validProvision = false; break; }
            index += 2;
        }
        else
        {
            validProvision = false;
            break;
        }
    }
}

if (!initialize && !validProvision) { Console.Error.WriteLine(usage); return 2; }
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
    var result = await scope.ServiceProvider.GetRequiredService<LocalAdministratorAccounts>().ProvisionAsync(args[3], password, role);
    if (!result.Succeeded)
    {
        foreach (var code in result.ErrorCodes) { Console.Error.WriteLine(code); }
        return 1;
    }
    Console.WriteLine(role == NergalRoles.Auditor ? "Local auditor provisioned." : "Local administrator provisioned.");
    return 0;
}
catch (AccountStoreException error) { Console.Error.WriteLine(error.Code); }
catch (Exception error) when (error is InvalidDataException or System.Text.DecoderFallbackException) { Console.Error.WriteLine("password.invalidInput"); }
catch (ArgumentException) { Console.Error.WriteLine("account.invalidInput"); }
catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
{ Console.Error.WriteLine("account.unavailable"); }
return 1;
