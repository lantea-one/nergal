using System.Runtime.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Identity;

namespace Nergal.Web;

[SupportedOSPlatform("linux")]
internal sealed class UserPresentationFilter : IAsyncResultFilter
{
    private readonly LocalAdministratorAccounts accounts;
    public UserPresentationFilter(LocalAdministratorAccounts accounts) => this.accounts = accounts;

    public async Task OnResultExecutionAsync(ResultExecutingContext context, ResultExecutionDelegate next)
    {
        if (context.Result is ViewResult view && context.HttpContext.User.Identity?.IsAuthenticated == true)
        {
            try
            {
                var profile = await accounts.ReadProfileAsync(context.HttpContext.User);
                view.ViewData!["UserDisplayName"] = string.IsNullOrWhiteSpace(profile.DisplayName) ? profile.LoginName : profile.DisplayName;
                if (context.HttpContext.RequestServices.GetService<ControllerStateStore>() is { } store)
                {
                    try { view.ViewData["Branding"] = store.ReadSystemSettings().Branding; }
                    catch (ControllerStateException) { view.ViewData["Branding"] = SystemSettingsSnapshot.Default.Branding; }
                }
            }
            catch (AccountStoreException error)
            { context.Result = error.Code == "account.denied" ? new UnauthorizedResult() : new StatusCodeResult(503); }
        }
        await next();
    }
}
