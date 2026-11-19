using Microsoft.AspNetCore.DataProtection;
using Nergal.Web.Components;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddHealthChecks();
// This read-only foundation has no durable identity sessions. Do not create or
// share machine-wide keys; authenticated releases will need an explicit key store.
builder.Services.AddDataProtection().SetApplicationName("nergal").UseEphemeralDataProtectionProvider();

var app = builder.Build();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapHealthChecks("/healthz");
app.MapControllers();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
