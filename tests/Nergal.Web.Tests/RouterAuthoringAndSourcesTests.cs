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
        Assert.Equal(new[] { 2 }, Assert.Single(source.Review.Signals).Lines);
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

    /// <summary>A blank stored settings row is corruption, not permission to reset operator intent.</summary>
    [Fact]
    public void StoredSettings_BlankCorruptionFailsClosed()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var root = Path.Combine(Path.GetTempPath(), "ng-setting-corrupt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(root));
            store.SaveSystemSettings(SystemSettingsSnapshot.Default, ControllerActorIdentity.FromLocalAccount(Guid.NewGuid()), NergalRoles.Administrator);
            using (var db = new SqliteConnection("Data Source=" + Path.Combine(root, "controller.db")))
            {
                db.Open(); using var command = db.CreateCommand();
                command.CommandText = "UPDATE system_settings SET settings_json = ' ' WHERE singleton = 1";
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
}
