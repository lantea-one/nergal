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
    [InlineData("fr-FR", "en-US")]
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
        foreach (var input in new StringValues[] { "es", "fr-FR", new[] { "en-US", "es-ES" } })
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
