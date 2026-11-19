using Microsoft.AspNetCore.DataProtection;
using Nergal.Web.Components;
using Nergal.Web;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddHealthChecks();
var sessions = builder.Configuration.GetSection("LocalSessions");
var enabled = sessions.GetValue<bool>("Enabled");
if (enabled && !OperatingSystem.IsLinux()) { throw new PlatformNotSupportedException("Local sessions require Linux."); }
using var keys = enabled && OperatingSystem.IsLinux() ? LocalSessionHost.Configure(builder.Services, sessions) : null;
if (!enabled) { builder.Services.AddDataProtection().SetApplicationName("nergal").UseEphemeralDataProtectionProvider(); }

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
if (enabled && OperatingSystem.IsLinux()) { await LocalSessionHost.EnableAsync(app); }
app.UseAntiforgery();
app.MapStaticAssets().AllowAnonymous();
app.MapHealthChecks("/healthz").AllowAnonymous();
app.MapControllers();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
