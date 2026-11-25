using Microsoft.AspNetCore.DataProtection;
using Nergal.Web.Components;
using Nergal.Web;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddLocalization(options => options.ResourcesPath = "Resources");
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddHealthChecks();
var sessions = builder.Configuration.GetSection("LocalSessions");
var enabled = sessions.GetValue<bool>("Enabled");
if (enabled && !OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("Local sessions require Linux."); }
using var keys = enabled && OperatingSystem.IsLinux() ? LocalSessionHost.Configure(builder.Services, sessions) : null;
if (!enabled) { builder.Services.AddDataProtection().SetApplicationName("nergal").UseEphemeralDataProtectionProvider(); }

var oidcEnabled = enabled;
if (oidcEnabled)
{
    if (!OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("OIDC requires Linux."); }
    if (keys is null) { throw new InvalidOperationException("OIDC requires the protected local session host."); }
    FederatedLogin.Configure(builder.Services, builder.Configuration.GetSection("Oidc"), keys);
}
if (enabled && OperatingSystem.IsLinux())
{
    ControllerAuthorization.Configure(builder.Services, oidcEnabled);
}
var agentSettings = builder.Configuration.GetSection("AgentStatus");
var statusEnabled = agentSettings.GetValue<bool>("Enabled");
if (statusEnabled)
{
    if (!OperatingSystem.IsLinux() || !enabled) { throw new InvalidOperationException("Agent status requires local administrator sessions on Linux."); }
    ControllerStatus.Configure(builder.Services, agentSettings, oidcEnabled);
}
var controllerStateSettings = builder.Configuration.GetSection("ControllerState");
var controllerStateEnabled = controllerStateSettings.GetValue<bool>("Enabled");
if (controllerStateEnabled)
{
    if (!OperatingSystem.IsLinux() || !enabled) { throw new InvalidOperationException("Controller state requires local administrator sessions on Linux."); }
    ControllerStateHost.Configure(builder.Services, controllerStateSettings);
}
if (builder.Configuration["NativeSources:Directory"] is { Length: > 0 } sourceDirectory)
{
    if (!OperatingSystem.IsLinux() || !controllerStateEnabled) { throw new InvalidOperationException("Native source inspection requires an authenticated Linux controller."); }
    builder.Services.AddSingleton(new NativePolicySourceCatalog(sourceDirectory));
}
// MVC registers a framework key-ring preloader independently of the selected
// IDataProtectionProvider. Both of our modes own their provider lifecycle.
// Omit only Data Protection's hosted service so it cannot open a profile ring.
foreach (var service in builder.Services.Where(service => service.ServiceType == typeof(IHostedService) &&
    service.ImplementationType?.FullName == "Microsoft.AspNetCore.DataProtection.Internal.DataProtectionHostedService" &&
    service.ImplementationType.Assembly == typeof(EphemeralDataProtectionProvider).Assembly).ToArray())
{
    builder.Services.Remove(service);
}

var app = builder.Build();
app.UseRequestLocalization(UiLocalization.CreateRequestOptions());
app.UseStatusCodePages(BrowserResponses.StatusPageAsync);
app.UseExceptionHandler(handler => handler.Run(context =>
{
    var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
    var status = error is Nergal.Identity.AccountStoreException or Nergal.ControllerState.ControllerStateException ? 503 : 500;
    context.Response.StatusCode = status;
    return BrowserResponses.RenderAsync(context, status);
}));
if (enabled && OperatingSystem.IsLinux()) { await LocalSessionHost.EnableAsync(app); }
app.UseAntiforgery();
// Public build assets must remain available when credential/profile storage is
// unavailable, so sign-in and error pages do not inherit that dependency.
app.MapStaticAssets().AllowAnonymous().ShortCircuit();
app.MapHealthChecks("/healthz").AllowAnonymous();
app.MapControllers();
if (oidcEnabled)
{
    app.MapControllerRoute("federated-login", "login/oidc", new { controller = "Session", action = "Federated" });
}
if (statusEnabled && OperatingSystem.IsLinux()) { ControllerStatus.Map(app); }
if (controllerStateEnabled && OperatingSystem.IsLinux()) { ControllerStateHost.Map(app); }
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
