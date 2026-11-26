using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Web.Controllers;
using Xunit;

namespace Nergal.Web.Tests;

/// <summary>Verifies in-place rule editing, rule descriptions, dashboard overview model, and RBAC-gated system settings.</summary>
[SupportedOSPlatform("linux")]
public sealed class SystemSettingsAndInlineEditTests
{
    /// <summary>A settings save cannot repair or accept missing singleton protection in a current store.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SystemSettings_RejectsMissingOrIncompatibleTable(bool recreateWithoutConstraint)
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var directory = CreateOwnerOnlyTempDirectory();
        try
        {
            var options = new ControllerStateOptions(directory);
            var store = ControllerStateStore.Initialize(options);
            var original = store.ReadSystemSettingsVersion();
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            using var connection = new SqliteConnection($"Data Source={Path.Combine(directory, "controller.db")};Pooling=False");
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "DROP TABLE system_settings;";
            if (recreateWithoutConstraint)
            {
                command.CommandText += """
                    CREATE TABLE system_settings (
                        singleton INTEGER PRIMARY KEY, settings_json TEXT NOT NULL,
                        updated_by_actor TEXT NOT NULL, updated_at_utc TEXT NOT NULL
                    ) STRICT;
                    """;
            }
            command.ExecuteNonQuery();

            Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() => ControllerStateStore.Open(options)).Code);
            Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() => store.ReadSystemSettings()).Code);
            Assert.Equal("controller.corrupt", Assert.Throws<ControllerStateException>(() =>
                store.SaveSystemSettings(SystemSettingsSnapshot.Default, original.FormToken, actor, NergalRoles.Administrator)).Code);
            command.CommandText = "SELECT count(*) FROM sqlite_master WHERE name='system_settings'";
            Assert.Equal(recreateWithoutConstraint ? 1L : 0L, command.ExecuteScalar());
            command.CommandText = "SELECT count(*) FROM audit_log WHERE action='settings.update'";
            Assert.Equal(0L, command.ExecuteScalar());
        }
        finally { TryDelete(directory); }
    }

    /// <summary>Administrators can edit Filter, DNAT, SNAT, and Bridge rules in place with descriptions while Auditors are denied.</summary>
    [Fact]
    public void InlineEdit_UpdatesFilterDnatSnatBridgeRulesInPlaceAndDeniesAuditors()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var auditorActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("22222222-2222-2222-2222-222222222222"));

            var admin = CreateController(store, adminActor, NergalRoles.Administrator);
            var auditor = CreateController(store, auditorActor, NergalRoles.Auditor);
            var seed = PolicyAuthoringService.DefaultStarterBundleJson;

            // Auditors must be denied on all in-place edit endpoints.
            Assert.IsType<ForbidResult>(auditor.EditFilterRule(seed, null, null, 0, "input", "ipv4", "tcp", "accept", null, null, "443", null, null, null, null, description: "denied"));
            Assert.IsType<ForbidResult>(auditor.EditDnatRule(seed, null, null, 0, "ipv4", "tcp", "192.0.2.1/32", "198.51.100.2", 443, 8443, null, null, "denied"));
            Assert.IsType<ForbidResult>(auditor.EditSnatRule(seed, null, null, 0, "ipv4", "192.0.2.0/24", "198.51.100.1", null, null, "denied"));
            Assert.IsType<ForbidResult>(auditor.EditBridgeRule(seed, null, null, 0, "ipv4", "accept", "br0", null, "denied"));

            // 1. Edit existing filter rule #0 in place with a description.
            var m1 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.EditFilterRule(seed, "inline-edit", null, 0, "input", "ipv4", "tcp", "accept",
                    "192.0.2.0/24", null, "443", null, "eth0", null, "new, untracked", description: "Allow HTTPS from LAN")).Model);
            Assert.Empty(m1.Diagnostics);
            Assert.Single(m1.Bundle!.Filter.Rules);
            Assert.Equal("Allow HTTPS from LAN", m1.Bundle.Filter.Rules[0]!.Description);
            Assert.Equal(443, m1.Bundle.Filter.Rules[0]!.DestinationPort);
            Assert.Equal(ConnectionStateFlags.New | ConnectionStateFlags.Untracked, m1.Bundle.Filter.Rules[0]!.ConnectionStates);

            // 2. Add & edit DNAT rule in place.
            var m2 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddDnatRule(m1.BundleJson, "inline-edit", null, "ipv4", "tcp", "198.51.100.10/32", "192.0.2.10", 80, 8080, "wan0", null, "Initial HTTP DNAT")).Model);
            var m3 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.EditDnatRule(m2.BundleJson, "inline-edit", null, 0, "ipv4", "tcp", "198.51.100.10/32", "192.0.2.11", 443, 8443, "wan0", null, "Updated HTTPS DNAT")).Model);
            Assert.Empty(m3.Diagnostics);
            Assert.Single(m3.Bundle!.Nat!.DnatRules);
            Assert.Equal("192.0.2.11", m3.Bundle.Nat.DnatRules[0]!.TranslatedAddress);
            Assert.Equal("Updated HTTPS DNAT", m3.Bundle.Nat.DnatRules[0]!.Description);

            // 3. Add & edit SNAT rule in place.
            var m4 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddSnatRule(m3.BundleJson, "inline-edit", null, "ipv4", "192.0.2.0/24", "198.51.100.1", null, "wan0", "Old SNAT")).Model);
            var m5 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.EditSnatRule(m4.BundleJson, "inline-edit", null, 0, "ipv4", "192.0.2.0/24", "198.51.100.2", null, "wan0", "New SNAT")).Model);
            Assert.Empty(m5.Diagnostics);
            Assert.Equal("198.51.100.2", m5.Bundle!.Nat!.SnatRules[0]!.TranslatedAddress);
            Assert.Equal("New SNAT", m5.Bundle.Nat.SnatRules[0]!.Description);

            // 4. Add & edit Bridge rule in place.
            var m6 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.AddBridgeRule(m5.BundleJson, "inline-edit", null, "ipv4", "accept", "br0", null, "Initial bridge")).Model);
            var m7 = Assert.IsType<PolicyEditorViewModel>(Assert.IsType<ViewResult>(
                admin.EditBridgeRule(m6.BundleJson, "inline-edit", null, 0, "arp", "drop", "br0", "veth1", "Updated bridge drop")).Model);
            Assert.Empty(m7.Diagnostics);
            Assert.Single(m7.Bundle!.Bridge!.Rules);
            Assert.Equal(BridgeEtherType.Arp, m7.Bundle.Bridge.Rules[0]!.EtherType);
            Assert.Equal(FilterVerdict.Drop, m7.Bundle.Bridge.Rules[0]!.Verdict);
            Assert.Equal("Updated bridge drop", m7.Bundle.Bridge.Rules[0]!.Description);

            // 5. Out-of-range index returns 400 with diagnostic without mutating.
            var bad = Assert.IsType<ViewResult>(admin.EditFilterRule(m7.BundleJson, "inline-edit", null, 99, "input", "ipv4", "tcp", "accept", null, null, null, null, null, null, null));
            Assert.Equal(StatusCodes.Status400BadRequest, admin.Response.StatusCode);
            var badModel = Assert.IsType<PolicyEditorViewModel>(bad.Model);
            Assert.Contains(badModel.Diagnostics, d => d.Code == "rule.indexOutOfRange");
        }
        finally
        {
            TryDelete(dir);
        }
    }

    /// <summary>System settings persist with append-only audit entries, update dashboard metadata, and deny Auditors.</summary>
    [Fact]
    public async Task SystemSettings_AndDashboard_PersistSettingsAuditAndDenyAuditors()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var dir = CreateOwnerOnlyTempDirectory();
        try
        {
            var store = ControllerStateStore.Initialize(new ControllerStateOptions(dir));
            var adminActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-1111-1111-111111111111"));
            var auditorActor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("22222222-2222-2222-2222-222222222222"));

            var admin = CreateController(store, adminActor, NergalRoles.Administrator);
            var auditor = CreateController(store, auditorActor, NergalRoles.Auditor);

            // Auditor can view settings read-only, but cannot save.
            var auditorView = Assert.IsType<ViewResult>(auditor.Settings());
            var auditorModel = Assert.IsType<SystemSettingsViewModel>(auditorView.Model);
            Assert.False(auditorModel.CanMutate);

            var denied = auditor.SaveSettings(
                "Hacked", "sub", "blue", "dark", null,
                true, 30, 5, 15, 12,
                false, null, null, null, null, null, null, null, 3600,
                false, null, true, null, null, null, null, null, null,
                "sqlite", null, null, null, null, "require",
                30, 2, "drop", "drop", "accept", false, store.ReadSystemSettingsVersion().FormToken);
            Assert.IsType<ForbidResult>(denied);
            Assert.Equal("nergal", store.ReadSystemSettings().Branding.ApplicationName);

            // Store-level RBAC check also denies Auditor.
            var ex = Assert.Throws<ControllerStateException>(() =>
                store.SaveSystemSettings(SystemSettingsSnapshot.Default, store.ReadSystemSettingsVersion().FormToken, auditorActor, NergalRoles.Auditor));
            Assert.Equal("rbac.denied", ex.Code);

            // Administrator invalid settings return 400 with validation errors.
            var invalidRes = Assert.IsType<ViewResult>(admin.SaveSettings(
                "", "sub", "neon", "dark", null,
                true, 30, 5, 15, 12,
                true, "http://insecure.example.test", "", null, null, null, null, null, 3600,
                false, null, true, null, null, null, null, null, null,
                "sqlite", null, null, null, null, "require",
                30, 2, "drop", "drop", "accept", false, store.ReadSystemSettingsVersion().FormToken));
            Assert.Equal(StatusCodes.Status400BadRequest, admin.Response.StatusCode);
            var invalidModel = Assert.IsType<SystemSettingsViewModel>(invalidRes.Model);
            Assert.Contains("branding.applicationName", invalidModel.ValidationErrors);
            Assert.Contains("branding.accentColor", invalidModel.ValidationErrors);
            Assert.Contains("auth.oidc.authorityUrl", invalidModel.ValidationErrors);

            // Administrator valid save persists settings and writes an immutable settings.update audit record.
            var saveRes = admin.SaveSettings(
                "EdgeWall", "Edge nftables fleet", "emerald", "dark", "Authorized only",
                true, 45, 5, 15, 14,
                true, "https://idp.example.test/realms/net", "nergal-web", "openid profile email groups", null, "groups", "admins", "auditors", 1800,
                true, "ldaps://dir.example.test:636", true, "dc=example,dc=test", null, "(uid={0})", "memberOf", null, null,
                "sqlite", null, null, null, null, "require",
                60, 2, "drop", "drop", "accept", true, store.ReadSystemSettingsVersion().FormToken);
            var redirect = Assert.IsType<LocalRedirectResult>(saveRes);
            Assert.Equal("~/manage/settings?notice=saved", redirect.Url);

            var persisted = store.ReadSystemSettings();
            Assert.Equal("EdgeWall", persisted.Branding.ApplicationName);
            Assert.Equal("emerald", persisted.Branding.AccentColor);
            Assert.True(persisted.Oidc.Enabled);
            Assert.True(persisted.Ldap.Enabled);
            Assert.Equal(60, persisted.FirewallDefaults.DefaultConfirmationTimeoutSeconds);

            var audit = store.ListAuditEntries(10);
            Assert.Contains(audit, e => e.Action == "settings.update" && e.ActorId == adminActor && e.Outcome == "succeeded");

            // Overview dashboard reflects updated settings and active policy summary.
            var dashRes = Assert.IsType<ViewResult>(await admin.Index());
            var dashModel = Assert.IsType<FleetDashboardViewModel>(dashRes.Model);
            Assert.Equal("EdgeWall", dashModel.Settings.Branding.ApplicationName);
        }
        finally
        {
            TryDelete(dir);
        }
    }

    private static ManagementController CreateController(ControllerStateStore store, string actorId, string role)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Role, role),
            new Claim(ControllerActorIdentity.ActorClaimType, actorId),
        ],
        "test"));
        return new ManagementController(store)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal },
            },
        };
    }

    private static string CreateOwnerOnlyTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "nergal-settings-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return path;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
        }
    }
}
