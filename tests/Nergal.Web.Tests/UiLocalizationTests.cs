using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Exercises UI locale selection, translation fallback and the display-language preference endpoint.</summary>
public sealed class UiLocalizationTests
{
    /// <summary>Only an explicitly supported, exact preference cookie can select the display locale.</summary>
    [Theory]
    [InlineData(null, "en-US")]
    [InlineData("en-US", "en-US")]
    [InlineData("es-ES", "es-ES")]
    [InlineData("es", "en-US")]
    [InlineData("fr-FR", "fr-FR")]
    [InlineData("ar", "ar")]
    [InlineData("he-IL", "he-IL")]
    [InlineData("zh-TW", "zh-TW")]
    [InlineData("FR-fr", "en-US")]
    [InlineData("fr", "en-US")]
    [InlineData("sv-SE", "en-US")]
    public async Task OnlyAnExplicitSupportedCookieSelectsTheUiLanguage(string? cookie, string expectedLanguage)
    {
        var originalCulture = CultureInfo.CurrentCulture;
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?culture=es-ES");
        context.Request.Headers.AcceptLanguage = "es-ES";
        if (cookie is not null) { context.Request.Headers.Cookie = $"{UiLocalization.CookieName}={cookie}"; }

        var middleware = new RequestLocalizationMiddleware(http =>
        {
            Assert.Equal(expectedLanguage, CultureInfo.CurrentUICulture.Name);
            Assert.Equal(originalCulture, CultureInfo.CurrentCulture);
            Assert.Equal(expectedLanguage, http.Features.Get<IRequestCultureFeature>()?.RequestCulture.UICulture.Name);
            return Task.CompletedTask;
        }, Options.Create(UiLocalization.CreateRequestOptions()), NullLoggerFactory.Instance);

        await middleware.Invoke(context);
    }

    /// <summary>Every selectable non-English language ships core sign-in, authenticator recovery, and navigation resources.</summary>
    [Fact]
    public void EverySelectableLocaleIncludesSharedConsoleMessages()
    {
        using var services = new ServiceCollection().AddLogging()
            .AddLocalization(options => options.ResourcesPath = "Resources").BuildServiceProvider();
        var strings = services.GetRequiredService<IStringLocalizer<UiStrings>>();
        var original = CultureInfo.CurrentUICulture;
        var commonKeys = new[] { "Language", "Display language", "Set language", "Sign in", "Username", "Password",
            "Sign in with LDAP", "Sign in with OAuth", "Sign in with identity provider", "Primary navigation",
            "Import nftables.conf", "Review & apply", "Skip to content", "Stored UTC: {0}", "Verify sign-in", "Authenticator code",
            "Recover authenticator", "Recovery authorization", "Confirm replacement authenticator", "New authenticator code",
            "Accept", "Drop", "Reject", "Start confirmed apply", "Confirm active apply", "Immediate rollback",
            "Nergal verification code", "Your Nergal verification code is {0}. Use it only for the request you initiated." };
        try
        {
            foreach (var (culture, nativeName) in UiLocalization.Languages.Where(entry => !entry.Culture.Equals(UiLocalization.DefaultCulture)))
            {
                CultureInfo.CurrentUICulture = culture;
                Assert.False(string.IsNullOrWhiteSpace(nativeName));
                foreach (var key in commonKeys)
                {
                    var translation = strings[key];
                    Assert.False(translation.ResourceNotFound, $"{culture.Name} is missing '{key}'");
                    Assert.False(string.IsNullOrWhiteSpace(translation.Value));
                }

                Assert.Contains("synthetic-user", strings["My profile for {0}", "synthetic-user"].Value, StringComparison.Ordinal);
                Assert.Contains("123456", strings["Your Nergal verification code is {0}. Use it only for the request you initiated.", "123456"].Value, StringComparison.Ordinal);
                Assert.True(strings["Missing test message"].ResourceNotFound);
            }
        }
        finally { CultureInfo.CurrentUICulture = original; }
    }

    /// <summary>English fallback and the selected shell language have separate coverage.</summary>
    [Theory]
    [InlineData("en-US", false, false, true)]
    [InlineData("es-ES", true, false, true)]
    [InlineData("es-ES", false, false, false)]
    [InlineData("ar", true, false, false)]
    [InlineData("ja-JP", false, true, true)]
    public void LocalizedBodyRequiresCoverageForTheSelectedLocale(string locale, bool extended, bool shared, bool expected)
    {
        Assert.Equal(expected, UiLocalization.HasLocalizedBody(CultureInfo.GetCultureInfo(locale), extended, shared));
    }

    /// <summary>Spanish validation and status text are available, with an English fallback for missing messages.</summary>
    [Fact]
    public async Task SpanishCatalogTranslatesValidationAndStatusAndFallsBackToTheEnglishSource()
    {
        using var services = new ServiceCollection().AddLogging()
            .AddLocalization(options => options.ResourcesPath = "Resources").BuildServiceProvider();
        var strings = services.GetRequiredService<IStringLocalizer<UiStrings>>();
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{UiLocalization.CookieName}=es-ES";
        var middleware = new RequestLocalizationMiddleware(_ =>
        {
            Assert.Equal("El UID esperado del servidor no es válido.", strings["Invalid expected server UID."].Value);
            Assert.Equal("Pendiente de confirmación", strings["pending"].Value);
            Assert.Equal("Mi perfil de Synthetic", strings["My profile for {0}", "Synthetic"].Value);

            var missing = strings["NAT"];
            Assert.True(missing.ResourceNotFound);
            Assert.Equal("NAT", missing.Value);
            return Task.CompletedTask;
        }, Options.Create(UiLocalization.CreateRequestOptions()), NullLoggerFactory.Instance);

        await middleware.Invoke(context);
    }

    /// <summary>A valid preference stays local and changes only the browser language cookie.</summary>
    [Theory]
    [InlineData("/console/manage/hosts", "/console/manage/hosts")]
    [InlineData("https://example.invalid/", "~/")]
    [InlineData("//example.invalid/", "~/")]
    [InlineData("/\\example.invalid/", "~/")]
    [InlineData("/console/login?code=synthetic", "~/")]
    [InlineData("/console/manage#draft", "~/")]
    [InlineData("/another-app", "~/")]
    public async Task LanguageSelectionStoresOnlyThePreferenceAndRedirectsLocally(string returnPath, string expectedDestination)
    {
        var controller = CreateController("es-ES", returnPath);

        var redirect = Assert.IsType<LocalRedirectResult>(await controller.Select());

        Assert.Equal(expectedDestination, redirect.Url);
        var cookie = Assert.Single(controller.Response.Headers.SetCookie);
        Assert.NotNull(cookie);
        Assert.StartsWith("nergal-language=es-ES;", cookie);
        Assert.Contains("path=/console", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Unsupported or ambiguous input leaves the browser preference unchanged.</summary>
    [Fact]
    public async Task UnsupportedAndAmbiguousLanguageRequestsDoNotWriteCookies()
    {
        foreach (var input in new StringValues[] { "es", "fr", "sv-SE", new[] { "en-US", "es-ES" } })
        {
            var controller = CreateController(input, "/console/manage/hosts");
            Assert.IsType<BadRequestResult>(await controller.Select());
            Assert.True(controller.Response.Headers.SetCookie.Count is 0);
        }
    }

    private static LanguageController CreateController(StringValues language, string returnPath)
    {
        var context = new DefaultHttpContext();
        context.Request.PathBase = "/console";
        context.Request.Scheme = "https";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
        {
            ["culture"] = language,
            ["returnPath"] = returnPath,
        });
        var action = new ControllerContext { HttpContext = context, RouteData = new RouteData() };
        return new LanguageController { ControllerContext = action, Url = new UrlHelper(action) };
    }
}
