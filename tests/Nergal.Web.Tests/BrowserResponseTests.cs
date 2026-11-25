using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace Nergal.Web.Tests;

/// <summary>Browser navigation may render guidance; APIs retain their status semantics and login destinations remain fixed.</summary>
public sealed class BrowserResponseTests
{
    /// <summary>Only explicitly requested HTML outside API routes receives browser treatment.</summary>
    [Theory]
    [InlineData("/manage", "text/html", true)]
    [InlineData("/profile", "text/html,application/xhtml+xml", true)]
    [InlineData("/missing", "text/html", true)]
    [InlineData("/profile", "text/html;q=0,application/json", false)]
    [InlineData("/manage", "application/json", false)]
    [InlineData("/manage", "not-a-media-type", false)]
    [InlineData("/controller/hosts", "text/html", false)]
    [InlineData("/agent/status", "text/html", false)]
    [InlineData("/api/policies", "text/html", false)]
    [InlineData("/healthz", "text/html", false)]
    [InlineData("/_framework/blazor.web.js", "text/html", false)]
    public void BrowserDetection_RespectsNegotiationAndApiBoundaries(string path, string accept, bool expected)
    {
        var http = new DefaultHttpContext();
        http.Request.Path = path;
        http.Request.Headers.Accept = accept;
        Assert.Equal(expected, BrowserResponses.WantsHtml(http.Request));
    }

    /// <summary>Neither an attacker-supplied redirect nor the original request query chooses the sign-in destination.</summary>
    [Theory]
    [InlineData("text/html", 302)]
    [InlineData("application/json", 401)]
    public async Task LoginChallenge_UsesFixedLocalPath(string accept, int status)
    {
        var http = new DefaultHttpContext();
        http.Request.PathBase = "/console";
        http.Request.Path = "/manage";
        http.Request.Headers.Accept = accept;
        var redirect = new RedirectContext<CookieAuthenticationOptions>(http,
            new AuthenticationScheme("synthetic", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(), new AuthenticationProperties(), "https://untrusted.example/return");
        await BrowserResponses.LoginChallenge(redirect);
        Assert.Equal(status, http.Response.StatusCode);
        Assert.Equal(status == 302 ? "/console/login" : "", http.Response.Headers.Location.ToString());
    }

    /// <summary>Errors offer navigation to an available host feature without requiring credential-store access.</summary>
    [Theory]
    [InlineData(false, true, true, "/login")]
    [InlineData(true, true, true, "/manage")]
    [InlineData(false, false, false, "/")]
    [InlineData(true, true, false, "/")]
    public void ErrorGuidance_UsesKnownLocalDestinations(bool authenticated, bool sessions, bool controller, string destination)
    {
        var error = BrowserResponses.Describe(503, authenticated, sessions, controller);
        Assert.Equal(503, error.Status);
        Assert.Equal("Service temporarily unavailable", error.Title);
        Assert.Equal(destination, error.ActionPath);
    }
}
