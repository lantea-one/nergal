using Nergal.Core.Deployment;
using Nergal.LocalState;

// Storage probe only: no process execution, firewall library or network operations.
if (args.Length != 2 || args[0] is not ("initialize" or "read"))
{
    return 2;
}

try
{
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
catch (UnauthorizedAccessException) { Console.Error.WriteLine("path.accessDenied"); return 1; }
