using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Nergal.Web.Controllers;

namespace Nergal.Web.Tests;

/// <summary>Entry navigation uses validated session state and fixed local destinations, never request redirect parameters.</summary>
[SupportedOSPlatform("linux")]
public sealed class BrowserEntryTests
{
    /// <summary>Anonymous visitors see sign-in; authenticated console users reach the overview in either reader role.</summary>
    [Theory]
    [InlineData(false, false, "~/login")]
    [InlineData(false, true, "~/login")]
    [InlineData(true, false, "~/session")]
    [InlineData(true, true, "~/manage")]
    public void Root_UsesEnabledFeaturesAndAuthenticatedState(bool authenticated, bool controller, string destination)
    {
        var home = new HomeController(Configuration(true, controller)) { ControllerContext = Context(authenticated) };
        Assert.Equal(destination, Assert.IsType<LocalRedirectResult>(home.Index()).Url);
    }

    /// <summary>The explicit development scaffold has no sign-in endpoint and must not redirect into a loop.</summary>
    [Fact]
    public void DisabledSessions_RetainDevelopmentScaffold()
    {
        var home = new HomeController(Configuration(false, false)) { ControllerContext = Context(false) };
        Assert.IsType<ViewResult>(home.Index());
    }

    /// <summary>Revisiting sign-in with a current session bypasses the credential form; OIDC uses the same fixed destination.</summary>
    [Theory]
    [InlineData(false, "~/session", "/session")]
    [InlineData(true, "~/manage", "/manage")]
    public async Task LoginAndFederatedCompletion_UseAvailableOverview(bool controller, string local, string federated)
    {
        var session = new SessionController(null!, Configuration(true, controller)) { ControllerContext = Context(true) };
        Assert.Equal(local, Assert.IsType<LocalRedirectResult>(session.Login()).Url);
        Assert.Equal(federated, Assert.IsType<ChallengeResult>(await session.Federated()).Properties!.RedirectUri);
        session.ControllerContext = Context(false);
        Assert.IsType<ViewResult>(session.Login());
    }

    private static IConfiguration Configuration(bool sessions, bool controller) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["LocalSessions:Enabled"] = sessions.ToString(),
            ["ControllerState:Enabled"] = controller.ToString(),
        }).Build();

    private static ControllerContext Context(bool authenticated) => new()
    {
        HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([], authenticated ? "synthetic-session" : null)),
        },
    };
}
