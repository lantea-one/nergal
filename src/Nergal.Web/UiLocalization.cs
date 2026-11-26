using System.Globalization;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Localization;

namespace Nergal.Web;

internal static class UiLocalization
{
    internal const string CookieName = "nergal-language";
    internal static CultureInfo DefaultCulture { get; } = CultureInfo.GetCultureInfo("en-US");

    internal static IReadOnlyList<(CultureInfo Culture, string NativeName)> Languages { get; } = Array.AsReadOnly(new[]
    {
        (DefaultCulture, "English"),
        (CultureInfo.GetCultureInfo("id-ID"), "Bahasa Indonesia"),
        (CultureInfo.GetCultureInfo("de-DE"), "Deutsch"),
        (CultureInfo.GetCultureInfo("es-ES"), "Español"),
        (CultureInfo.GetCultureInfo("fr-FR"), "Français"),
        (CultureInfo.GetCultureInfo("it-IT"), "Italiano"),
        (CultureInfo.GetCultureInfo("nl-NL"), "Nederlands"),
        (CultureInfo.GetCultureInfo("pl-PL"), "Polski"),
        (CultureInfo.GetCultureInfo("pt-BR"), "Português (Brasil)"),
        (CultureInfo.GetCultureInfo("vi-VN"), "Tiếng Việt"),
        (CultureInfo.GetCultureInfo("tr-TR"), "Türkçe"),
        (CultureInfo.GetCultureInfo("ru-RU"), "Русский"),
        (CultureInfo.GetCultureInfo("uk-UA"), "Українська"),
        (CultureInfo.GetCultureInfo("he-IL"), "עברית"),
        (CultureInfo.GetCultureInfo("ar"), "العربية"),
        (CultureInfo.GetCultureInfo("hi-IN"), "हिन्दी"),
        (CultureInfo.GetCultureInfo("zh-CN"), "简体中文"),
        (CultureInfo.GetCultureInfo("zh-TW"), "繁體中文"),
        (CultureInfo.GetCultureInfo("ja-JP"), "日本語"),
        (CultureInfo.GetCultureInfo("ko-KR"), "한국어"),
    });

    // The view declares whether its body uses the resource catalogs.
    internal static bool HasLocalizedBody(CultureInfo locale, bool localizedView) =>
        locale.Equals(DefaultCulture) || localizedView;

    internal static string MessageLanguage(LocalizedString message) =>
        message.ResourceNotFound ? DefaultCulture.Name : CultureInfo.CurrentUICulture.Name;

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
