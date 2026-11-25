using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;

namespace Nergal.Web;

/// <summary>A value-free browser error description. Request URLs, exception messages and configuration are never reflected.</summary>
/// <param name="Status">Original HTTP status, retained when rendering the page.</param>
/// <param name="Title">Plain-language error title.</param>
/// <param name="Message">Recovery guidance without internal failure details.</param>
/// <param name="ActionText">Primary navigation label.</param>
/// <param name="ActionPath">Fixed local destination selected from available host features.</param>
public sealed record BrowserErrorModel(int Status, string Title, string Message, string ActionText, string ActionPath);

internal static class BrowserResponses
{
    internal static bool WantsHtml(HttpRequest request)
    {
        if (new[] { "/controller", "/agent", "/api", "/healthz", "/_framework" }
            .Any(prefix => request.Path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))) { return false; }
        try
        {
            return request.GetTypedHeaders().Accept?.Any(value =>
                string.Equals(value.MediaType.Value, "text/html", StringComparison.OrdinalIgnoreCase) && (value.Quality ?? 1) > 0) == true;
        }
        catch (FormatException) { return false; }
    }

    internal static Task LoginChallenge(RedirectContext<CookieAuthenticationOptions> context)
    {
        if (WantsHtml(context.Request)) { context.Response.Redirect(context.Request.PathBase + "/login"); }
        else { context.Response.StatusCode = StatusCodes.Status401Unauthorized; }
        return Task.CompletedTask;
    }

    internal static Task StatusPageAsync(Microsoft.AspNetCore.Diagnostics.StatusCodeContext context)
    {
        var http = context.HttpContext;
        if (http.Response.StatusCode == 401 && WantsHtml(http.Request))
        { http.Response.Redirect(http.Request.PathBase + "/login"); return Task.CompletedTask; }
        return RenderAsync(http, http.Response.StatusCode);
    }

    internal static BrowserErrorModel Describe(int status, bool authenticated, bool sessions, bool controller) => new(status,
        status switch
        {
            400 => "We couldn't process that request",
            401 => "Sign in to continue",
            403 => "Access denied",
            404 => "Page not found",
            405 => "That action isn't available",
            429 => "Please wait before trying again",
            503 => "Service temporarily unavailable",
            _ => status >= 500 ? "Something went wrong" : "Request unsuccessful",
        },
        status switch
        {
            400 => "Review the submitted information, then try again. Your change may not have been saved.",
            401 => "Your session has ended or a sign-in is required. Sign in to open the console.",
            403 => "Your account doesn't have permission for this page or action. Contact an Administrator if you need access.",
            404 => "This page may have moved, or the address may be incorrect. Use the console navigation to continue.",
            405 => "Return to the console and use the available controls for this action.",
            429 => "Too many requests arrived in a short time. Wait a minute, then try again.",
            _ => "Try again shortly. If the problem continues, ask an Administrator to check the application logs.",
        },
        !authenticated && sessions ? "Sign in" : controller && authenticated ? "Go to overview" : "Go to home",
        !authenticated && sessions ? "/login" : controller && authenticated ? "/manage" : "/");

    // Render the standalone Razor view directly. MVC profile/result filters and
    // credential queries must not be prerequisites for an error response.
    internal static async Task RenderAsync(HttpContext context, int status)
    {
        if (!WantsHtml(context.Request)) { return; }
        var services = context.RequestServices;
        var configuration = services.GetRequiredService<IConfiguration>();
        var model = Describe(status, context.User.Identity?.IsAuthenticated == true,
            configuration.GetValue<bool>("LocalSessions:Enabled"), configuration.GetValue<bool>("ControllerState:Enabled"));
        var action = new ActionContext(context, new RouteData(), new ActionDescriptor());
        var engine = services.GetRequiredService<IRazorViewEngine>();
        var view = engine.GetView(null, "~/Views/Shared/BrowserError.cshtml", true);
        if (!view.Success) { throw new InvalidOperationException("The browser error view is unavailable."); }
        var data = new ViewDataDictionary<BrowserErrorModel>(new EmptyModelMetadataProvider(), new ModelStateDictionary()) { Model = model };
        var tempData = new TempDataDictionary(context, services.GetRequiredService<ITempDataProvider>());
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        await view.View.RenderAsync(new ViewContext(action, view.View, data, tempData, writer, new HtmlHelperOptions()));
        context.Response.StatusCode = status;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(writer.ToString(), context.RequestAborted);
    }
}
