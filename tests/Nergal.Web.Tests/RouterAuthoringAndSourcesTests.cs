using Nergal.Nftables;
using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Nergal.Core.Controller;
using Nergal.ControllerState;
using Nergal.Core.Agent;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Web.Controllers;
using Xunit;

namespace Nergal.Web.Tests;

/// <summary>Native inspection never executes sources; structured edits preserve advanced draft semantics.</summary>
[SupportedOSPlatform("linux")]
public sealed class RouterAuthoringAndSourcesTests
{
    /// <summary>Combined source viewing/import retains one immutable analysis and does not format private contents into logs.</summary>
    [Fact]
    public void NativeSource_SharesAnalysisAcrossViewerAndReview()
    {
        const string text = "# private-source-value\r\nether \\\r\n saddr 02:00:00:00:00:01 accept\n";
        var content = new NativeSourceContent("private-source-name", text);
        var source = new NativePolicySource(content.Name, content.Text, content.Digest);
        Assert.Same(source.Analysis.Review, source.Review);
        Assert.Equal(text, source.Analysis.Lexical.Document!.Source);
        Assert.Same(source.Analysis.Lexical.Document, source.Analysis.Structure.Tree!.Document);
        Assert.Equal(new[] { 2 }, source.Review.Signals.Single(s => s.Code == "review.sourceMac").Lines);
        Assert.False(source.Review.CanConvert);
        Assert.DoesNotContain("private-source", source.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Adding a simple rule cannot silently remove rpfilter, MSS, or an auxiliary table.</summary>
    [Fact]
    public void VisualEdit_PreservesExtendedPolicyAndPinnedMatchers()
    {
        var mac = new MacAddress("02:00:00:00:00:01");
        var filter = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("192.0.2.0/24"), SourceMac: mac, NegateSource: true)],
            new(FilterVerdict.Accept, [new(FilterVerdict.Drop, MatchFibUnreachable: true)]), 1360);
        var original = PolicyBundleJsonCodec.EncodeBundle(new(1, filter, auxiliaryFilter: new(-5,
            new(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept, []))));
        Assert.True(PolicyAuthoringService.TryUpdateFilterRule(original, 0,
            new("input", "ipv4", "tcp", "accept", "192.0.2.0/24", null, "443", null, null, null, null),
            out var updated, out var errors), string.Join(',', errors));
        var roundTrip = PolicyBundleJsonCodec.DecodeBundle(updated!).Value!;
        Assert.Equal(mac, roundTrip.Filter.Rules[0]!.SourceMac);
        Assert.True(roundTrip.Filter.Rules[0]!.NegateSource);
        Assert.Equal(1360, roundTrip.Filter.ForwardTcpMssClamp);
        Assert.True(roundTrip.Filter.RpFilter!.Rules[0]!.MatchFibUnreachable);
        Assert.Equal(-5, roundTrip.AuxiliaryFilter!.Priority);
    }

    /// <summary>An invalid stored settings payload is corruption, even when table and trigger definitions are intact.</summary>
    [Fact]
    public void StoredSettings_InvalidPayloadFailsClosed()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var root = Path.Combine(Path.GetTempPath(), "ng-setting-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(root));
            store.SaveSystemSettings(SystemSettingsSnapshot.Default, store.ReadSystemSettingsVersion().FormToken,
                ControllerActorIdentity.FromLocalAccount(Guid.NewGuid()), NergalRoles.Administrator);
            using (var db = new SqliteConnection("Data Source=" + Path.Combine(root, "controller.db")))
            {
                db.Open(); using var command = db.CreateCommand();
                command.CommandText = "SELECT sql FROM sqlite_master WHERE name='system_settings_no_update'";
                var definition = Assert.IsType<string>(command.ExecuteScalar());
                command.CommandText = "DROP TRIGGER system_settings_no_update; UPDATE system_settings SET settings_json = '{}' WHERE version = 1; " + definition;
                command.ExecuteNonQuery();
            }
            Assert.Equal("settings.corrupt", Assert.Throws<ControllerStateException>(() => store.ReadSystemSettings()).Code);
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>Auditors cannot inspect potentially sensitive native exports; imports are bounded and snapshotted.</summary>
    [Fact]
    public void NativeSources_AreBoundedSnapshotsAndAdministratorOnly()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var root = Path.Combine(Path.GetTempPath(), "ng-source-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var sources = Path.Combine(root, "sources"); Directory.CreateDirectory(sources);
            var file = Path.Combine(sources, "synthetic.conf");
            File.WriteAllText(file, "table inet synthetic { }\n");
            var catalog = new NativePolicySourceCatalog(sources);
            File.WriteAllText(file, "changed");
            Assert.Equal("table inet synthetic { }\n", Assert.Single(catalog.Sources).Text);
            var storePath = Path.Combine(root, "controller");
            Directory.CreateDirectory(storePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var store = ControllerStateStore.Initialize(new(storePath));
            var controller = new ManagementController(store, nativeSources: catalog)
            {
                ControllerContext = new() { HttpContext = new DefaultHttpContext() },
            };
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());
            controller.HttpContext.User = new(new ClaimsIdentity([new(ClaimTypes.Role, NergalRoles.Auditor), new(ControllerActorIdentity.ActorClaimType, actor)], "test"));
            Assert.IsType<ForbidResult>(controller.Sources());
            Assert.IsType<ForbidResult>(controller.SourceReview(Guid.Empty));
            controller.HttpContext.User = new(new ClaimsIdentity());
            Assert.IsType<ForbidResult>(controller.SourceReview(Guid.Empty));
            controller.HttpContext.User = new(new ClaimsIdentity([new(ClaimTypes.Role, NergalRoles.Administrator), new(ControllerActorIdentity.ActorClaimType, actor)], "test"));
            Assert.IsType<ViewResult>(controller.Sources());
            Assert.IsType<NotFoundResult>(controller.SourceReview(Guid.NewGuid()));
            Assert.IsType<NotFoundResult>(controller.SourceReview(Guid.Empty));
            Assert.IsType<RedirectToActionResult>(controller.ImportStagedSource("synthetic", catalog.Sources[0].Digest));
            var imported = Assert.Single(store.ListNativeSources());
            var report = Assert.IsType<FileContentResult>(controller.SourceReview(imported.Id));
            Assert.Equal("table inet synthetic { }\n", System.Text.Encoding.UTF8.GetString(Assert.IsType<FileContentResult>(controller.DownloadSource(imported.Id)).FileContents));
            Assert.IsType<NotFoundResult>(controller.ImportStagedSource("../synthetic", catalog.Sources[0].Digest));
            using var parsed = System.Text.Json.JsonDocument.Parse(report.FileContents);
            Assert.Equal(catalog.Sources[0].Digest, parsed.RootElement.GetProperty("sourceSha256").GetString());
            Assert.Equal(3, parsed.RootElement.GetProperty("schemaVersion").GetInt32());
            Assert.True(parsed.RootElement.GetProperty("structure").GetProperty("isComplete").GetBoolean());
            Assert.False(parsed.RootElement.GetProperty("review").GetProperty("canConvert").GetBoolean());
            Assert.Equal(1, parsed.RootElement.GetProperty("review").GetProperty("tableDeclarations").GetInt32());
            Assert.False(parsed.RootElement.TryGetProperty("text", out _));
            Assert.Equal("application/json", report.ContentType);
            File.CreateSymbolicLink(Path.Combine(sources, "linked.conf"), file);
            Assert.Throws<IOException>(() => new NativePolicySourceCatalog(sources));
            File.Delete(Path.Combine(sources, "linked.conf"));
            File.WriteAllText(file, new string('x', 524_289));
            Assert.Throws<IOException>(() => new NativePolicySourceCatalog(sources));
        }
        finally { Directory.Delete(root, true); }
    }

    /// <summary>Reports expose only structural metadata; private source values and token trees stay out of the wire contract.</summary>
    [Fact]
    public void NativeReport_PreservesLegacyConstructorAndMasksStructuralFailure()
    {
        var source = new NativePolicySource("synthetic", "private-token { counter ]", new string('a', 64));
        var current = new NativeSourceMigrationReport(source.Name, source.Digest, source.Review, source.Analysis.Structure.Summary);
        var legacy = new NativeSourceMigrationReport(source.Name, source.Digest, source.Review);
        Assert.Equal(2, current.SchemaVersion);
        Assert.Equal(1, legacy.SchemaVersion);
        Assert.Same(source.Analysis.Structure.Summary, current.Structure);
        var json = System.Text.Json.JsonSerializer.Serialize(current);
        Assert.DoesNotContain("private-token", json, StringComparison.Ordinal);
        Assert.DoesNotContain("counter", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Document", json, StringComparison.Ordinal);
        Assert.False(current.Structure!.IsComplete);
        Assert.Equal("source.mismatchedDelimiter", current.Structure.Diagnostic!.Code);
        Assert.DoesNotContain("Structure", System.Text.Json.JsonSerializer.Serialize(legacy), StringComparison.Ordinal);
    }
    /// <summary>Schema 3 serializes only source-bound rule counts and diagnostics, preserving older report constructors.</summary>
    [Fact]
    public void NativeReport_RuleSummaryExcludesPrivateAstAndIsUnavailableOnStructureFailure()
    {
        var source = new NativePolicySource("synthetic", "table inet private_name { chain input { ip saddr 192.0.2.1 accept; counter accept; } }", new string('b', 64));
        var report = new NativeSourceMigrationReport(source.Name, source.Digest, source.Review, source.Analysis.Structure.Summary, source.Analysis.RuleParsing);
        Assert.Equal(3, report.SchemaVersion);
        Assert.Same(source.Analysis.RuleParsing, report.RuleParsing);
        Assert.Equal(2, report.RuleParsing!.TotalRules);
        Assert.Equal(1, report.RuleParsing.ParsedRules);
        var json = System.Text.Json.JsonSerializer.Serialize(report);
        Assert.DoesNotContain("private_name", json, StringComparison.Ordinal);
        Assert.DoesNotContain("192.0.2", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Statement", json, StringComparison.Ordinal);
        var failed = NativeSourceAnalyzer.Analyze("{]");
        Assert.False(failed.RuleParsing.IsAvailable);
        Assert.Equal(0, failed.RuleParsing.TotalRules);
        Assert.Empty(failed.RuleParsing.Diagnostics);
    }

}
