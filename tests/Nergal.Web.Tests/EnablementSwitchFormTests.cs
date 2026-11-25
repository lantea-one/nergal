using System.Runtime.Versioning;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace Nergal.Web.Tests;

/// <summary>Native off switches omit their field; this must not permit incomplete or ambiguous access forms.</summary>
[SupportedOSPlatform("linux")]
public sealed class EnablementSwitchFormTests
{
    /// <summary>Only the explicit switch may be absent; unknown and repeated fields remain denied.</summary>
    [Theory]
    [InlineData("id=example&version=1&role=auditor&__RequestVerificationToken=synthetic", true)]
    [InlineData("id=example&version=1&role=auditor&__RequestVerificationToken=synthetic&enabled=true", true)]
    [InlineData("id=example&version=1&__RequestVerificationToken=synthetic", false)]
    [InlineData("id=example&version=1&role=auditor", false)]
    [InlineData("id=example&version=1&role=auditor&__RequestVerificationToken=synthetic&other=true", false)]
    [InlineData("id=example&version=1&role=auditor&__RequestVerificationToken=synthetic&enabled=true&enabled=false", false)]
    [InlineData("id=example&version=1&role=auditor&role=administrator&__RequestVerificationToken=synthetic", false)]
    public async Task OptionalSwitch_DoesNotBroadenOtherFormFields(string body, bool accepted)
    {
        var http = new DefaultHttpContext();
        http.Request.ContentType = "application/x-www-form-urlencoded";
        http.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var controller = new FormProbe { ControllerContext = new ControllerContext { HttpContext = http } };
        Assert.Equal(accepted, await controller.AcceptsAsync());
    }

    private sealed class FormProbe() : IdentityUiController(null!, new ConfigurationBuilder().Build())
    {
        internal async Task<bool> AcceptsAsync() =>
            await ReadFieldsWithOptionalSwitchAsync("enabled", "id", "version", "role") is not null;
    }
}
