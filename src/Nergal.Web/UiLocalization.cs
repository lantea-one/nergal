using System.Globalization;
using Microsoft.AspNetCore.Localization;

namespace Nergal.Web;

internal static class UiLocalization
{
    internal const string CookieName = "nergal-language";
    internal static CultureInfo DefaultCulture { get; } = CultureInfo.GetCultureInfo("en-US");

    internal static IReadOnlyList<(CultureInfo Culture, string NativeName)> Languages { get; } = Array.AsReadOnly(new[]
    {
        (DefaultCulture, "English"),
        (CultureInfo.GetCultureInfo("es-ES"), "Español"),
    });

    internal static CultureInfo? FindCulture(string? name) => Languages
        .FirstOrDefault(language => string.Equals(language.Culture.Name, name, StringComparison.Ordinal)).Culture;

    internal static RequestLocalizationOptions CreateRequestOptions()
    {
        // UI language must not alter binding, parsing, or formatting for existing protocol fields.
        var existingCulture = CultureInfo.CurrentCulture;
        return new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture(existingCulture, DefaultCulture),
            SupportedCultures = new[] { existingCulture },
            SupportedUICultures = Languages.Select(language => language.Culture).ToArray(),
            FallBackToParentCultures = false,
            FallBackToParentUICultures = false,
            RequestCultureProviders = new[]
            {
                new CustomRequestCultureProvider(context =>
                {
                    var culture = FindCulture(context.Request.Cookies[CookieName]);
                    return Task.FromResult(culture is null ? null : new ProviderCultureResult(existingCulture.Name, culture.Name));
                }),
            },
        };
    }
}
