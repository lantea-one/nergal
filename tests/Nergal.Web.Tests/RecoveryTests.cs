using System.Runtime.Versioning;
using System.Security.Claims;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Tests actor-scoped recovery against a fresh identity database with real password hashing and TOTP.</summary>
[SupportedOSPlatform("linux")]
public sealed class RecoveryTests
{
    /// <summary>The last Administrator keeps a usable ticket and authenticator through staging and failed audit, then must sign in again.</summary>
    [Fact]
    public async Task OfflineReplacementPreservesLastAdministratorUntilAtomicConfirmation()
    {
        await using var f = await RecoveryFixture.Create();
        var initial = await f.Admin();
        var id = Guid.Parse(initial.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var enrolled = await f.Run(a => a.BeginTotpEnrollmentAsync(initial, f.Keys));
        Assert.NotNull(enrolled);
        Assert.True((await f.Run(a => a.ConfirmTotpEnrollmentAsync(initial, enrolled.Id, f.Code(enrolled.ManualKey), f.Keys))).Succeeded);
        f.Advance();
        var admin = await f.Admin(enrolled.ManualKey);
        Assert.True((await f.Run(a => a.SaveMfaPolicyAsync(admin, 1, MfaRequirement.All, f.Keys))).Succeeded);
        f.Advance();
        admin = await f.Admin(enrolled.ManualKey);
        f.Advance();
        var oldProof = await f.Run(a => a.BeginLocalSignInAsync(RecoveryFixture.Name, RecoveryFixture.Password, f.Keys));
        Assert.Equal(MfaSignInStatus.Challenge, oldProof.Status);

        var grant = await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(id));
        Assert.NotNull(grant);
        var setup = await f.Begin(grant.Authorization);
        Assert.NotNull(setup);
        Assert.Null(await f.Begin(grant.Authorization));
        Assert.True(await f.Run(a => a.ValidateSessionAsync(admin)));
        Assert.True(await f.Run(a => a.HasTotpAsync(admin)));
        Assert.False(await f.Confirm(setup, "invalid"));

        await f.Sql("""
            CREATE TRIGGER fixture_recovery_audit BEFORE INSERT ON IdentityAudit
            WHEN NEW.Action = 'mfa.recovered' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END
            """);
        var failed = await Assert.ThrowsAsync<AccountStoreException>(() => f.Confirm(setup, f.Code(setup.ManualKey)));
        Assert.Equal("account.databaseError", failed.Code);
        Assert.True(await f.Run(a => a.ValidateSessionAsync(admin)));
        await f.Sql("DROP TRIGGER fixture_recovery_audit");

        // Both requests present the same valid proof. Only a committed recovery consumes it.
        var completions = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ =>
            Task.Run(() => f.Confirm(setup, f.Code(setup.ManualKey)), TestContext.Current.CancellationToken)));
        Assert.Single(completions, success => success);
        Assert.False(await f.Run(a => a.ValidateSessionAsync(admin)));
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
        Assert.Equal(MfaSignInStatus.Denied, (await f.Run(a => a.CompleteMfaSignInAsync(oldProof.Continuation!,
            f.Code(enrolled.ManualKey), f.Keys))).Status);
        var next = await f.Run(a => a.BeginLocalSignInAsync(RecoveryFixture.Name, RecoveryFixture.Password, f.Keys));
        Assert.Equal(MfaSignInStatus.Challenge, (await f.Run(a => a.CompleteMfaSignInAsync(next.Continuation!,
            f.Code(setup.ManualKey), f.Keys))).Status);
        f.Advance();
        var recovered = await f.Admin(setup.ManualKey);
        var audit = await f.Run(a => a.ReadIdentityAuditAsync(recovered));
        Assert.Single(audit, e => e.Action == "mfa.totpEnrolled");
        Assert.Single(audit, e => e.Action == "mfa.recovered");
        Assert.Single(audit, e => e.Action == "mfa.recoveryIssued" && e.ActorId == "operator:offline");
    }

    /// <summary>A required user without a factor can enroll only with their own password and current local Administrator authorization.</summary>
    [Fact]
    public async Task RecoversInitiallyUnenrolledUserAfterEnforcement()
    {
        await using var f = await RecoveryFixture.Create();
        const string username = "other-account";
        var admin = await f.Admin();
        Assert.True((await f.Run(a => a.CreateUserAsync(admin, username, RecoveryFixture.Password, NergalRoles.Auditor))).Succeeded);
        var target = Assert.Single(await f.Run(a => a.ListUsersAsync(admin)), u => u.UserName == username);
        var actor = ControllerActorIdentity.FromLocalAccount(target.Id);
        var enrolled = await f.Run(a => a.BeginTotpEnrollmentAsync(admin, f.Keys));
        Assert.NotNull(enrolled);
        Assert.True((await f.Run(a => a.ConfirmTotpEnrollmentAsync(admin, enrolled.Id, f.Code(enrolled.ManualKey), f.Keys))).Succeeded);
        f.Advance();
        admin = await f.Admin(enrolled.ManualKey);
        Assert.True((await f.Run(a => a.SaveMfaPolicyAsync(admin, 1, MfaRequirement.All, f.Keys))).Succeeded);
        Assert.Equal(MfaSignInStatus.Denied, (await f.Run(a => a.BeginLocalSignInAsync(username, RecoveryFixture.Password, f.Keys))).Status);
        f.Advance();
        admin = await f.Admin(enrolled.ManualKey);

        Assert.Null(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(target.Id)));
        Assert.Null(await f.Run(a => a.IssueRecoveryAsync(admin, actor, 1)));
        var grant = await f.Run(a => a.IssueRecoveryAsync(admin, actor, 2));
        Assert.NotNull(grant);
        Assert.Null(await f.Begin(grant.Authorization)); // Other account with the very same password.
        Assert.Null(await f.Begin(grant.Authorization, username, "incorrect fixture password"));
        var setup = await f.Begin(grant.Authorization, username);
        Assert.NotNull(setup);
        Assert.True(await f.Confirm(setup, f.Code(setup.ManualKey)));
        f.Advance();
        var challenge = await f.Run(a => a.BeginLocalSignInAsync(username, RecoveryFixture.Password, f.Keys));
        Assert.Equal(MfaSignInStatus.Challenge, challenge.Status);
        var auditor = await f.Complete(challenge, setup.ManualKey);
        Assert.True(auditor.IsInRole(NergalRoles.Auditor));
        var denial = await Assert.ThrowsAsync<AccountStoreException>(() => f.Run(a => a.IssueRecoveryAsync(auditor, actor, 2)));
        Assert.Equal("account.denied", denial.Code);
    }

    /// <summary>Staging a replacement cannot displace the last Administrator's working authenticator. A newer sign-in supersedes recovery.</summary>
    [Fact]
    public async Task ExistingAuthenticatorStillSignsInWhileReplacementIsPending()
    {
        await using var f = await RecoveryFixture.Create();
        var admin = await f.Admin();
        var id = Guid.Parse(admin.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var existing = Assert.IsType<TotpEnrollment>(await f.Run(a => a.BeginTotpEnrollmentAsync(admin, f.Keys)));
        Assert.True((await f.Run(a => a.ConfirmTotpEnrollmentAsync(admin, existing.Id, f.Code(existing.ManualKey), f.Keys))).Succeeded);
        f.Advance();
        var grant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(id)));
        var setup = Assert.IsType<RecoverySetup>(await f.Begin(grant.Authorization));
        var signedIn = await f.Admin(existing.ManualKey);
        Assert.True(await f.Run(a => a.ValidateSessionAsync(signedIn)));
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));

        // A new authorization can stage the same replacement, but a policy-generation change supersedes that proof.
        grant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(id)));
        setup = Assert.IsType<RecoverySetup>(await f.Begin(grant.Authorization));
        Assert.True((await f.Run(a => a.SaveMfaPolicyAsync(signedIn, 1, MfaRequirement.All, f.Keys))).Succeeded);
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
    }

    /// <summary>Credentials and TOTP confirmation have separate persistent attempt bounds on each explicit grant.</summary>
    [Fact]
    public async Task ThreeFailuresExhaustEachRecoveryStage()
    {
        await using var f = await RecoveryFixture.Create();
        var admin = await f.Admin();
        var id = Guid.Parse(admin.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var grant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(id)));
        for (var i = 0; i < 3; i++) { Assert.Null(await f.Begin(grant.Authorization, password: "incorrect fixture password")); }
        Assert.Null(await f.Begin(grant.Authorization));
        grant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(id)));
        var setup = Assert.IsType<RecoverySetup>(await f.Begin(grant.Authorization));
        for (var i = 0; i < 3; i++) { Assert.False(await f.Confirm(setup, "invalid")); }
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
        Assert.True(await f.Run(a => a.ValidateSessionAsync(admin)));
    }

    /// <summary>Expiry, superseding grants and explicit revocation each invalidate valid evidence independently.</summary>
    [Fact]
    public async Task RejectsStaleOrSupersededRecoveryEvidence()
    {
        await using var f = await RecoveryFixture.Create();
        var admin = await f.Admin();
        var actor = admin.FindFirstValue(ControllerActorIdentity.ActorClaimType)!;
        var id = Guid.Parse(admin.FindFirstValue(ClaimTypes.NameIdentifier)!);
        async Task<RecoveryAuthorization> Issue() => Assert.IsType<RecoveryAuthorization>(
            await f.Run(a => a.IssueRecoveryAsync(admin, actor, 1)));
        var expired = await Issue();
        f.Advance(10);
        Assert.Null(await f.Begin(expired.Authorization));
        var replaced = await Issue();
        var setup = await f.Begin(replaced.Authorization);
        Assert.NotNull(setup);
        var current = await Issue();
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
        setup = await f.Begin(current.Authorization);
        Assert.NotNull(setup);
        f.Advance(5);
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
        admin = await f.Admin();
        var revoked = await Issue();
        setup = await f.Begin(revoked.Authorization);
        Assert.NotNull(setup);
        Assert.True((await f.Run(a => a.RevokeUserAsync(admin, id, 1))).Succeeded);
        Assert.False(await f.Confirm(setup, f.Code(setup.ManualKey)));
    }

    /// <summary>Removing the issuing Administrator's access invalidates a staged grant for a different actor.</summary>
    [Fact]
    public async Task DemotingIssuerInvalidatesStagedRecoveryForAnotherAdministrator()
    {
        await using var f = await RecoveryFixture.Create();
        var issuer = await f.Admin();
        const string targetName = "second-recovery-admin";
        Assert.True((await f.Run(a => a.CreateUserAsync(issuer, targetName, RecoveryFixture.Password,
            NergalRoles.Administrator))).Succeeded);
        var target = (await f.Run(a => a.ListUsersAsync(issuer))).Single(user => user.UserName == targetName);
        var issuerId = Guid.Parse(issuer.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var targetSeedGrant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueOfflineAdministratorRecoveryAsync(target.Id)));
        var original = Assert.IsType<RecoverySetup>(await f.Begin(targetSeedGrant.Authorization, targetName));
        Assert.True(await f.Confirm(original, f.Code(original.ManualKey)));
        f.Advance();
        var challenge = await f.Run(a => a.BeginLocalSignInAsync(targetName, RecoveryFixture.Password, f.Keys));
        var targetAdmin = await f.Complete(challenge, original.ManualKey);
        var grant = Assert.IsType<RecoveryAuthorization>(await f.Run(a => a.IssueRecoveryAsync(issuer,
            ControllerActorIdentity.FromLocalAccount(target.Id), 1)));
        var replacement = Assert.IsType<RecoverySetup>(await f.Begin(grant.Authorization, targetName));
        Assert.True((await f.Run(a => a.UpdateUserAsync(targetAdmin, issuerId, 1, NergalRoles.Auditor, true, f.Keys))).Succeeded);
        Assert.False(await f.Confirm(replacement, f.Code(replacement.ManualKey)));
        f.Advance();
        challenge = await f.Run(a => a.BeginLocalSignInAsync(targetName, RecoveryFixture.Password, f.Keys));
        Assert.True((await f.Complete(challenge, original.ManualKey)).IsInRole(NergalRoles.Administrator));
    }
}
