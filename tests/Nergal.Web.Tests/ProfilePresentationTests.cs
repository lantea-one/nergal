using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;

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

    /// <summary>Translate known presentation labels and keep unknown machine values intact.</summary>
    [Fact]
    public void IdentityHistory_LocalizesKnownLabelsWithoutRewritingIdentifiers()
    {
        using var services = new ServiceCollection().AddLogging()
            .AddLocalization(options => options.ResourcesPath = "Resources").BuildServiceProvider();
        var strings = services.GetRequiredService<IStringLocalizer<UiStrings>>();
        var original = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("es-ES");
            Assert.Equal("Cuenta creada", IdentityUiLabels.Action("account.created", strings));
            Assert.Equal("Operador sin conexión", IdentityUiLabels.Account("operator:offline", [], strings));
            Assert.Equal("https://id.example.invalid", IdentityUiLabels.Account("https://id.example.invalid", [], strings));
            Assert.Equal("Password changed", IdentityUiLabels.Action("Password changed", strings));
            Assert.Equal("Un campo del perfil del proveedor no está disponible.", IdentityUiLabels.ProfileDiagnostic("unknown", strings));
        }
        finally { CultureInfo.CurrentUICulture = original; }
    }
}
