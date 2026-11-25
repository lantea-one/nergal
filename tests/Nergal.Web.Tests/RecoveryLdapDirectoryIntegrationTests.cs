using System.Globalization;
using System.Runtime.Versioning;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises recovery against the same trusted synthetic OpenLDAP peer as the browser and protocol fixtures.</summary>
[SupportedOSPlatform("linux")]
public sealed class RecoveryLdapDirectoryIntegrationTests
{
    /// <summary>Requires the opt-in directory before performing network I/O.</summary>
    public static bool FixtureEnabled => LdapDirectoryIntegrationTests.FixtureEnabled;

    /// <summary>Matches the immutable entry across fresh binds, rejects generation changes, and requires ordinary MFA sign-in after recovery.</summary>
    [Fact(Skip = "Requires the disposable OpenLDAP fixture.", SkipUnless = nameof(FixtureEnabled))]
    public async Task DirectoryRecoveryRequiresSameEntryAndCurrentGeneration()
    {
        await using var f = await RecoveryFixture.Create();
        var admin = await f.Admin();
        var port = int.Parse(Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_PORT")!, CultureInfo.InvariantCulture);
        const string suffix = "dc=example,dc=test";
        const string password = "fixture-user-password";
        var settings = new LdapConnectionSettings(true, $"ldaps://directory.example.test:{port}", "127.0.0.1",
            "ou=people," + suffix, "cn=reader," + suffix, "uid", "cn=administrators,ou=roles," + suffix,
            "cn=auditors,ou=roles," + suffix, new());
        Assert.True((await f.Run(a => a.SaveLdapConnectionAsync(admin, 0, settings, "fixture-reader-password", f.Keys))).Succeeded);
        var connection = Assert.IsType<LdapConnectionSnapshot>(await f.Run(a => a.ReadLdapConnectionAsync(admin)));
        var actor = ControllerActorIdentity.FromLdapAccount(connection.DirectoryId, Guid.Parse("a5870a72-3cff-467c-8da0-cd75470cf41a"));
        var original = await f.Run(a => a.BeginLdapSignInAsync(1, "auditor", password, f.Keys));
        Assert.NotNull(original.LdapPrincipal);
        f.Advance();

        async Task<RecoveryAuthorization> Issue() => Assert.IsType<RecoveryAuthorization>(
            await f.Run(a => a.IssueRecoveryAsync(admin, actor, 1)));
        Task<RecoverySetup?> Begin(RecoveryAuthorization authorization, long generation, string username)
            => f.Run(a => a.BeginLdapRecoveryAsync(authorization.Authorization, generation, username, password, f.Keys));
        var grant = await Issue();
        Assert.Null(await Begin(grant, 2, "auditor"));
        Assert.Null(await Begin(grant, 1, "administrator"));
        var stale = Assert.IsType<RecoverySetup>(await Begin(grant, 1, "auditor"));
        Assert.True(await f.Run(a => a.ValidateLdapSessionAsync(original.LdapPrincipal)));
        Assert.True((await f.Run(a => a.SaveLdapConnectionAsync(admin, 1, settings, "", f.Keys))).Succeeded);
        Assert.False(await f.Confirm(stale, f.Code(stale.ManualKey)));

        var current = await f.Run(a => a.BeginLdapSignInAsync(2, "auditor", password, f.Keys));
        Assert.NotNull(current.LdapPrincipal);
        f.Advance();
        var setup = Assert.IsType<RecoverySetup>(await Begin(await Issue(), 2, "auditor"));
        Assert.True(await f.Confirm(setup, f.Code(setup.ManualKey)));
        Assert.False(await f.Run(a => a.ValidateLdapSessionAsync(current.LdapPrincipal)));
        f.Advance();
        var challenge = await f.Run(a => a.BeginLdapSignInAsync(2, "auditor", password, f.Keys));
        Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
        var completed = await f.Run(a => a.CompleteMfaSignInAsync(challenge.Continuation!, f.Code(setup.ManualKey), f.Keys));
        Assert.NotNull(completed.LdapPrincipal);
        Assert.True(completed.LdapPrincipal.IsInRole(NergalRoles.Auditor));
        Assert.True(await f.Run(a => a.ValidateLdapSessionAsync(completed.LdapPrincipal)));
    }
}
