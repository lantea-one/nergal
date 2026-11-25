using System.Runtime.Versioning;
using System.Security.Claims;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises local Administrator grants and independent recovery against private SQLite state.</summary>
[SupportedOSPlatform("linux")]
public sealed class LocalAdministratorBoundaryTests
{
    private const string Backup = "fixture-backup";

    /// <summary>Provider authority can manage ordinary users but cannot establish durable local Administrator access.</summary>
    [Fact]
    public async Task ExternalAdministrator_CannotCreatePromoteOrReactivateLocalAdministrator()
    {
        await using var fixture = await RecoveryFixture.Create();
        var local = await fixture.Admin();
        var external = ExternalAdministrator();

        Assert.True((await fixture.Run(a => a.CreateUserAsync(external, "fixture-auditor", RecoveryFixture.Password,
            NergalRoles.Auditor))).Succeeded);
        var auditor = await ReadAccount(fixture, external, "fixture-auditor");
        Assert.True((await fixture.Run(a => a.UpdateUserAsync(external, auditor.Id, auditor.Version, NergalRoles.Auditor,
            enabled: false))).Succeeded);
        auditor = await ReadAccount(fixture, external, auditor.UserName);
        var backup = await CreateBackup(fixture, local);
        Assert.True((await fixture.Run(a => a.UpdateUserAsync(local, backup.Id, backup.Version, NergalRoles.Administrator,
            enabled: false, keys: fixture.Keys))).Succeeded);
        backup = await ReadAccount(fixture, local, Backup);

        var audit = await fixture.Run(a => a.ReadIdentityAuditAsync(local));
        Assert.Equal(["account.localAdministratorRequired"], (await fixture.Run(a => a.CreateUserAsync(external,
            "fixture-denied", RecoveryFixture.Password, NergalRoles.Administrator))).ErrorCodes);
        foreach (var enabled in new[] { false, true })
        {
            Assert.Equal(["account.localAdministratorRequired"], (await fixture.Run(a => a.UpdateUserAsync(external,
                auditor.Id, auditor.Version, NergalRoles.Administrator, enabled))).ErrorCodes);
        }
        Assert.Equal(["account.localAdministratorRequired"], (await fixture.Run(a => a.UpdateUserAsync(external, backup.Id,
            backup.Version, NergalRoles.Administrator, enabled: true))).ErrorCodes);
        Assert.Equal(audit.ToArray(), (await fixture.Run(a => a.ReadIdentityAuditAsync(local))).ToArray());
        Assert.Equal(auditor, await ReadAccount(fixture, local, auditor.UserName));
        Assert.Equal(backup, await ReadAccount(fixture, local, Backup));
        Assert.DoesNotContain(await fixture.Run(a => a.ListUsersAsync(local)), account => account.UserName == "fixture-denied");

        Assert.True((await fixture.Run(a => a.UpdateUserAsync(external, auditor.Id, auditor.Version, NergalRoles.Auditor,
            enabled: true))).Succeeded);
        auditor = await ReadAccount(fixture, local, auditor.UserName);
        Assert.True((await fixture.Run(a => a.UpdateUserAsync(local, auditor.Id, auditor.Version, NergalRoles.Administrator,
            enabled: true))).Succeeded);
        Assert.True((await fixture.Run(a => a.UpdateUserAsync(local, backup.Id, backup.Version, NergalRoles.Administrator,
            enabled: true))).Succeeded);
    }

    /// <summary>Enforcement requires an enrolled local Administrator who can currently complete both authentication steps.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EnforcingMfa_RequiresAvailableAuthenticatorAdministrator(bool passwordLockout)
    {
        await using var fixture = await RecoveryFixture.Create();
        var admin = await EnrollAdministrator(fixture, await fixture.Admin());
        await BlockAdministrator(fixture, passwordLockout);

        var policy = await fixture.Run(a => a.ReadMfaPolicyAsync(admin));
        Task<LocalProvisionResult> Enforce() => fixture.Run(a => a.SaveMfaPolicyAsync(admin, policy.Version,
            MfaRequirement.Administrators, fixture.Keys));
        Assert.Equal(["account.lastAdministrator"], (await Enforce()).ErrorCodes);
        Assert.Equal(policy, await fixture.Run(a => a.ReadMfaPolicyAsync(admin)));

        await ExpireBlock(fixture, passwordLockout);
        Assert.True((await Enforce()).Succeeded);
    }

    /// <summary>Removing local Administrator access requires another account with an immediately usable independent sign-in.</summary>
    [Theory]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task RemovingLocalAdministrator_RequiresAvailableIndependentFallback(bool passwordLockout, bool enrolled)
    {
        await using var fixture = await RecoveryFixture.Create();
        var admin = await fixture.Admin();
        var target = await CreateBackup(fixture, admin);
        if (enrolled) { await EnrollAdministrator(fixture, admin); }
        await BlockAdministrator(fixture, passwordLockout);

        var external = ExternalAdministrator();
        Task<LocalProvisionResult> Disable() => fixture.Run(a => a.UpdateUserAsync(external, target.Id, target.Version,
            NergalRoles.Administrator, enabled: false, keys: fixture.Keys));
        Assert.Equal(["account.lastAdministrator"], (await Disable()).ErrorCodes);
        Assert.Equal(target, await ReadAccount(fixture, external, target.UserName));

        await ExpireBlock(fixture, passwordLockout);
        Assert.True((await Disable()).Succeeded);
    }

    private static async Task<LocalUserSnapshot> CreateBackup(RecoveryFixture fixture, ClaimsPrincipal admin)
    {
        Assert.True((await fixture.Run(a => a.CreateUserAsync(admin, Backup, RecoveryFixture.Password,
            NergalRoles.Administrator))).Succeeded);
        return await ReadAccount(fixture, admin, Backup);
    }

    private static async Task<LocalUserSnapshot> ReadAccount(RecoveryFixture fixture, ClaimsPrincipal admin, string name)
        => Assert.Single(await fixture.Run(a => a.ListUsersAsync(admin)), account => account.UserName == name);

    private static ClaimsPrincipal ExternalAdministrator()
    {
        const string issuer = "https://oidc.example.test";
        const string subject = "fixture-federated-admin";
        return new(new ClaimsIdentity([
            new("iss", issuer), new("sub", subject), new(ClaimTypes.Role, NergalRoles.Administrator),
            new(ControllerActorIdentity.ActorClaimType, ControllerActorIdentity.FromFederatedAccount(issuer, subject))
        ], "fixture-oidc"));
    }

    private static async Task<ClaimsPrincipal> EnrollAdministrator(RecoveryFixture fixture, ClaimsPrincipal admin)
    {
        var enrollment = Assert.IsType<TotpEnrollment>(await fixture.Run(a => a.BeginTotpEnrollmentAsync(admin, fixture.Keys)));
        var confirmed = await fixture.Run(a => a.ConfirmTotpEnrollmentAsync(admin, enrollment.Id,
            fixture.Code(enrollment.ManualKey), fixture.Keys));
        Assert.True(confirmed.Succeeded);
        fixture.Advance();
        return await fixture.Admin(enrollment.ManualKey);
    }

    private static async Task BlockAdministrator(RecoveryFixture fixture, bool passwordLockout)
    {
        if (passwordLockout)
        {
            for (var attempt = 0; attempt < 5; attempt++)
            {
                var failed = await fixture.Run(a => a.VerifyAsync(RecoveryFixture.Name, "synthetic incorrect password"));
                Assert.False(failed.Succeeded);
            }
        }
        else
        {
            foreach (var attemptCount in new[] { 3, 2 })
            {
                var challenge = await fixture.Run(a => a.BeginLocalSignInAsync(RecoveryFixture.Name, RecoveryFixture.Password, fixture.Keys));
                Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
                var continuation = Assert.IsType<string>(challenge.Continuation);
                for (var attempt = 0; attempt < attemptCount; attempt++)
                {
                    var rejected = await fixture.Run(a => a.CompleteMfaSignInAsync(continuation, "invalid", fixture.Keys));
                    Assert.Equal(attempt == attemptCount - 1 ? MfaSignInStatus.Denied : MfaSignInStatus.Challenge, rejected.Status);
                }
            }
        }
        var signIn = await fixture.Run(a => a.BeginLocalSignInAsync(RecoveryFixture.Name, RecoveryFixture.Password, fixture.Keys));
        Assert.Equal(MfaSignInStatus.Denied, signIn.Status);
    }

    private static async Task ExpireBlock(RecoveryFixture fixture, bool passwordLockout)
    {
        // Identity uses its own UTC clock. Set an expired deadline without waiting on wall time.
        if (passwordLockout)
        {
            await fixture.Sql("UPDATE AspNetUsers SET LockoutEnd = '2000-01-01 00:00:00+00:00' WHERE UserName = 'recovery-admin'");
        }
        else { fixture.Advance(15); }
    }
}
