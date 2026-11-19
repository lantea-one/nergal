using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Nergal.Web.Controllers;

/// <summary>Provides the read-only development landing page.</summary>
public sealed class HomeController : Controller
{
    /// <summary>Displays the project's current status without reading host configuration.</summary>
    [AllowAnonymous, HttpGet("/")]
    public IActionResult Index() => View();
}
