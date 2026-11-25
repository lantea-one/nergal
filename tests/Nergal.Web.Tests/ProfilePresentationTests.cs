namespace Nergal.Web.Tests;

/// <summary>Value-free provider diagnostics should guide users without rendering raw field contents as messages.</summary>
public sealed class ProfilePresentationTests
{
    /// <summary>Known metadata failure codes get plain language; unknown strings are never echoed into guidance.</summary>
    [Fact]
    public void ProviderGuidance_UsesPlainLanguageWithoutUnknownInputReflection()
    {
        Assert.Equal("The provider supplied an invalid profile email address.", IdentityUiLabels.ProfileDiagnostic("email.invalid"));
        Assert.Equal("The provider did not supply a display name.", IdentityUiLabels.ProfileDiagnostic("displayName.missing"));
        Assert.Equal("A provider profile field is unavailable.", IdentityUiLabels.ProfileDiagnostic("<script>untrusted provider value</script>"));
    }
}
