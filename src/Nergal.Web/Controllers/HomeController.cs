using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Nergal.Web.Controllers;

/// <summary>Routes the console entry point while retaining the unauthenticated development scaffold.</summary>
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class HomeController(IConfiguration configuration) : Controller
{
    /// <summary>Opens sign-in or the authenticated overview without accepting caller-supplied destinations.</summary>
    [AllowAnonymous, HttpGet("/")]
    public IActionResult Index()
    {
        if (!configuration.GetValue<bool>("LocalSessions:Enabled")) { return View(); }
        return LocalRedirect(User.Identity?.IsAuthenticated == true
            ? configuration.GetValue<bool>("ControllerState:Enabled") ? "~/manage" : "~/session"
            : "~/login");
    }
}
