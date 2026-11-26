using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

[assembly: SupportedOSPlatform("linux")]

static class Program
{
    private const string NativeText = "# Synthetic 界🧪\r\n# Embedded\0NUL\rtable inet fixture { }\n";
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(
        Guid.Parse("de56ea26-d74d-401c-b15d-d7c13029ed78"));

    private static async Task<int> Main(string[] args)
    {
        try
        {
            Require(args.Length == 3, "Expected provider, phase, and snapshot path.");
            var provider = Enum.Parse<ControllerDatabaseProvider>(args[0]);
            var sourceOptions = Options(provider, "SOURCE");
            var restoredOptions = Options(provider, "RESTORED");
            var manifest = args[2];

            switch (args[1])
            {
                case "seed":
                    await Seed(sourceOptions, restoredOptions, manifest);
                    break;
                case "verify":
                    Verify(sourceOptions, restoredOptions, manifest);
                    break;
                default:
                    throw new FixtureFailure("Unknown fixture phase.");
            }

            Console.WriteLine($"{provider}: controller state {args[1]} passed");
            return 0;
        }
        catch (ControllerStateException error)
        {
            Console.Error.WriteLine($"Unexpected controller diagnostic {error.Code}.");
            Console.Error.WriteLine(error);
            return 1;
        }
        catch (FixtureFailure error)
        {
            Console.Error.WriteLine(error.Message);
            return 1;
        }
    }

    private static ControllerStateOptions Options(ControllerDatabaseProvider provider, string role) =>
        new(provider, Environment.GetEnvironmentVariable($"NERGAL_SQL_FIXTURE_{role}")
            ?? throw new FixtureFailure($"Missing {role} fixture connection."));

    private static async Task Seed(ControllerStateOptions sourceOptions, ControllerStateOptions restoredOptions,
        string manifest)
    {
        Denied(() => ControllerStateStore.Open(sourceOptions), "controller.databaseError");
        Denied(() => ControllerStateStore.Open(restoredOptions), "controller.databaseError");
        var source = ControllerStateStore.Initialize(sourceOptions);
        var original = source.ReadSystemSettingsVersion();
        Require(original.Version == 0 && original.UpdatedAtUtc is null && original.UpdatedByActor is null,
            "Fresh settings must start at version zero.");
        Require(SystemSettingsVersion.IsValidFormToken(original.FormToken), "Fresh settings require a valid form token.");
        Require(source.ListAuditEntries().Count == 0 && source.ListReusableObjects().Count == 0 &&
            source.ListNativeSources().Count == 0, "Fresh stores must have no audit entries, objects, or native sources.");

        var other = ControllerStateStore.Open(sourceOptions);
        Require(other.ReadSystemSettingsVersion() == original, "Independent handles must read the same fresh state.");
        var race = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = WriteAfterGate(source, original, "Synthetic first candidate", race.Task);
        var second = WriteAfterGate(other, original, "Synthetic second candidate", race.Task);
        race.SetResult();
        var winners = (await Task.WhenAll(first, second)).OfType<SystemSettingsVersion>().ToArray();
        Require(winners.Length == 1, "Exactly one concurrent settings submission must commit.");
        var winner = winners[0];
        Require(winner.FormToken != original.FormToken, "A committed update requires a new token.");
        var saved = ControllerStateStore.Open(sourceOptions);
        Require(saved.ReadSystemSettingsVersion() == winner, "Concurrent winner must survive reopen.");
        var audit = saved.ListAuditEntries();
        Require(audit.Count == 1, "A concurrent stale submission must write no audit entry.");
        CheckSettingsAudit(winner, audit[0], 1);
        Denied(() => Save(saved, original, "Synthetic stale replay"), "settings.stale");

        var submittedEntries = new[] { "192.0.2.10" };
        var content = new ReusableObjectContent("fixture_clients", ReusableObjectKind.Ipv4,
            "Synthetic IPv4 list", submittedEntries);
        submittedEntries[0] = "192.0.2.11";
        var created = saved.SaveReusableObject(null, 0, content, Actor, NergalRoles.Administrator);
        var changed = saved.SaveReusableObject(created.Id, created.Version, ObjectContent("203.0.113.10"),
            Actor, NergalRoles.Administrator);
        Denied(() => saved.SaveReusableObject(created.Id, created.Version, ObjectContent("203.0.113.11"),
            Actor, NergalRoles.Administrator), "object.staleVersion");
        Denied(() => saved.SaveReusableObject(created.Id, changed.Version, ObjectContent("203.0.113.11"),
            Actor, NergalRoles.Auditor), "rbac.denied");

        var versions = saved.ListReusableObjectVersions(created.Id);
        Require(versions.Select(version => version.Version).SequenceEqual(new[] { 2, 1 }) &&
            versions[0].Content.Entries.SequenceEqual(new[] { "203.0.113.10/32" }) &&
            versions[1].Content.Entries.SequenceEqual(new[] { "192.0.2.10/32" }),
            "Both pinned object versions must retain their exact entries.");
        var imported = saved.ImportNativeSource(new("synthetic.conf", NativeText), Actor, NergalRoles.Administrator);
        var revision = SavePolicy(saved, versions[1]);
        Require(revision.Revision == 1 && saved.GetPolicyRevision(1) == revision,
            "The first policy revision must be readable with its exact contents.");
        Require(saved.ListPolicyObjectUsage(created.Id).SequenceEqual(new[]
        {
            new PolicyObjectUsage(1, "filter.rules[0].sourceObject", 1),
        }), "Saved policy usage must pin the historical object version.");
        audit = saved.ListAuditEntries();
        Require(audit.Select(entry => entry.Action)
            .SequenceEqual(new[] { "policy.save", "source.import", "object.version", "object.create", "settings.update" }),
            "Each successful controller write must add its audit entry, with no entries for denied writes.");
        Require(audit.Take(4).All(entry => entry.ActorId == Actor && entry.ActorRole == NergalRoles.Administrator &&
            entry.Outcome == "succeeded" && entry.TimestampUtc.Offset == TimeSpan.Zero) &&
            audit[0].Target == "bundle" && audit[0].Revision == revision.Revision &&
            audit[1].Target == imported.Id.ToString("D") &&
            audit.Skip(2).Take(2).All(entry => entry.Target == created.Id.ToString("D")),
            "Audit entries must retain their actor, target, revision where applicable, and UTC timestamp.");
        var snapshot = Snapshot(saved, created.Id, imported.Id);
        Denied(() => ControllerStateStore.Initialize(sourceOptions), "controller.exists");
        Require(Snapshot(ControllerStateStore.Open(sourceOptions), created.Id, imported.Id) == snapshot,
            "A denied initialization must leave settings, audit and object history intact.");
        File.WriteAllText(manifest, JsonSerializer.Serialize(new Manifest(created.Id, imported.Id, snapshot)));
    }

    private static void Verify(ControllerStateOptions sourceOptions, ControllerStateOptions restoredOptions, string manifest)
    {
        var expected = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(manifest))
            ?? throw new FixtureFailure("Missing seed snapshot.");
        var source = ControllerStateStore.Open(sourceOptions);
        var restored = ControllerStateStore.Open(restoredOptions);
        Denied(() => ControllerStateStore.Initialize(restoredOptions), "controller.exists");
        Require(Snapshot(source, expected.ObjectId, expected.NativeSourceId) == expected.State &&
            Snapshot(restored, expected.ObjectId, expected.NativeSourceId) == expected.State, "Backup must preserve the controller snapshot on reopen.");

        var parent = source.ReadSystemSettingsVersion();
        var originalAudit = restored.ListAuditEntries().ToArray();
        var sourceBranch = Save(source, parent, "Synthetic source branch");
        var sourceSnapshot = Snapshot(source, expected.ObjectId, expected.NativeSourceId);
        Require(Snapshot(restored, expected.ObjectId, expected.NativeSourceId) == expected.State, "Source writes must leave the restore unchanged.");
        var restoredBranch = Save(restored, parent, "Synthetic restored branch");
        Require(sourceBranch.Version == 2 && restoredBranch.Version == sourceBranch.Version &&
            restoredBranch.FormToken != sourceBranch.FormToken && restoredBranch.FormToken != parent.FormToken,
            "Equal numerical versions across restored histories must have distinct tokens.");

        var divergentSnapshot = Snapshot(restored, expected.ObjectId, expected.NativeSourceId);
        Denied(() => Save(restored, sourceBranch, "Synthetic cross-database submission"), "settings.stale");
        Require(Snapshot(restored, expected.ObjectId, expected.NativeSourceId) == divergentSnapshot,
            "Rejecting a divergent token must leave the restore unchanged.");
        Denied(() => Save(source, restoredBranch, "Synthetic reverse submission"), "settings.stale");

        var final = Save(restored, restoredBranch, "Synthetic restored continuation");
        var revisedObject = restored.SaveReusableObject(expected.ObjectId, 2, ObjectContent("198.51.100.10"),
            Actor, NergalRoles.Administrator);
        var originalRevision = restored.GetPolicyRevision(1);
        var revisedPolicy = SavePolicy(restored, revisedObject);
        restored = ControllerStateStore.Open(restoredOptions);
        Require(final.Version == 3 && restored.ReadSystemSettingsVersion() == final,
            "The next restored settings update must survive reopening.");
        var versions = restored.ListReusableObjectVersions(expected.ObjectId);
        Require(revisedObject.Version == 3 && versions.Select(version => version.Version).SequenceEqual(new[] { 3, 2, 1 }) &&
            versions[0].Content.Entries.SequenceEqual(new[] { "198.51.100.10/32" }) &&
            versions[1].Content.Entries.SequenceEqual(new[] { "203.0.113.10/32" }) &&
            versions[2].Content.Entries.SequenceEqual(new[] { "192.0.2.10/32" }),
            "Restored object history must continue while preserving both original versions.");
        Require(revisedPolicy.Revision == 2 && restored.GetPolicyRevision(2) == revisedPolicy &&
            restored.GetPolicyRevision(1) == originalRevision &&
            restored.ListPolicyObjectUsage(expected.ObjectId).SequenceEqual(new[]
            {
                new PolicyObjectUsage(2, "filter.rules[0].sourceObject", 3),
                new PolicyObjectUsage(1, "filter.rules[0].sourceObject", 1),
            }), "The restored policy revision must advance and retain both version pins.");
        var audit = restored.ListAuditEntries();
        Require(audit.Count == originalAudit.Length + 4 && audit.Skip(4).SequenceEqual(originalAudit) &&
            audit.Zip(audit.Skip(1)).All(pair => pair.First.Sequence > pair.Second.Sequence),
            "Restored writes must append to the original audit and advance sequence numbers.");
        CheckSettingsAudit(final, audit[2], 3);
        CheckSettingsAudit(restoredBranch, audit[3], 2);
        Require(Snapshot(ControllerStateStore.Open(sourceOptions), expected.ObjectId, expected.NativeSourceId) == sourceSnapshot,
            "Recipient writes and the reverse stale denial must leave the source branch unchanged.");
    }

    private static Task<SystemSettingsVersion?> WriteAfterGate(ControllerStateStore store, SystemSettingsVersion original,
        string name, Task gate) => Task.Run<SystemSettingsVersion?>(async () =>
    {
        await gate;
        try
        {
            return Save(store, original, name);
        }
        catch (ControllerStateException error) when (error.Code == "settings.stale")
        {
            return null;
        }
    });

    private static SystemSettingsVersion Save(ControllerStateStore store, SystemSettingsVersion parent, string name)
    {
        var settings = parent.Settings with { Branding = parent.Settings.Branding with { ApplicationName = name } };
        return store.SaveSystemSettings(settings, parent.FormToken, Actor, NergalRoles.Administrator);
    }

    private static void CheckSettingsAudit(SystemSettingsVersion settings, ControllerAuditEntry audit, int version)
    {
        var binding = SHA256.HashData(Encoding.UTF8.GetBytes(settings.FormToken + SystemSettingsCodec.Serialize(settings.Settings)));
        Require(settings.Version == version && audit.ActorId == Actor &&
            audit.ActorRole == NergalRoles.Administrator && audit.Action == "settings.update" &&
            audit.Target == "system" && audit.Revision is null && audit.Outcome == "succeeded" &&
            audit.DetailCode == $"settings.version:{version}:{Convert.ToHexStringLower(binding)}" &&
            settings.UpdatedAtUtc == audit.TimestampUtc && audit.TimestampUtc.Offset == TimeSpan.Zero &&
            settings.UpdatedByActor == Actor, $"Settings version {version} must bind its attributed audit event.");
    }

    private static ReusableObjectContent ObjectContent(string entry) =>
        new("fixture_clients", ReusableObjectKind.Ipv4, "Synthetic IPv4 list", new[] { entry });

    private static PolicyRevisionRecord SavePolicy(ControllerStateStore store, ReusableObjectVersion version)
    {
        var reference = new PolicyObjectReference(version.Id, version.Version, version.Content);
        var bundle = new FirewallPolicyBundle(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, SourceObject: reference)]));
        return store.SavePolicyRevision(PolicyBundleJsonCodec.EncodeBundle(bundle), new string('a', 64),
            Actor, NergalRoles.Administrator, "Synthetic pinned policy");
    }

    private static string Snapshot(ControllerStateStore store, Guid objectId, Guid nativeSourceId)
    {
        var source = store.ReadNativeSource(nativeSourceId)
            ?? throw new FixtureFailure("Expected the saved native source.");
        var originalBytes = Encoding.UTF8.GetBytes(NativeText);
        Require(Encoding.UTF8.GetBytes(source.Content.Text).AsSpan().SequenceEqual(originalBytes) &&
            source.Summary.ByteLength == originalBytes.Length &&
            source.Summary.Digest == Convert.ToHexStringLower(SHA256.HashData(originalBytes)) &&
            store.ListNativeSources().SequenceEqual(new[] { source.Summary }),
            "The native source must retain exact UTF-8, including NUL, Unicode and line endings.");
        return JsonSerializer.Serialize(new
        {
            Current = store.ReadSystemSettingsVersion(),
            Audit = store.ListAuditEntries(),
            Objects = store.ListReusableObjects(),
            Versions = store.ListReusableObjectVersions(objectId),
            NativeSource = source,
            PolicyRevisions = store.ListPolicyRevisions(),
            PolicyObjectUsage = store.ListPolicyObjectUsage(objectId),
        });
    }

    private static void Denied(Action action, string code)
    {
        try
        {
            action();
        }
        catch (ControllerStateException error)
        {
            Require(error.Code == code, $"Expected {code}, received {error.Code}.");
            return;
        }

        throw new FixtureFailure($"Expected {code}, operation succeeded.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new FixtureFailure(message);
        }
    }

    private sealed record Manifest(Guid ObjectId, Guid NativeSourceId, string State);

    private sealed class FixtureFailure(string message) : Exception(message);
}
