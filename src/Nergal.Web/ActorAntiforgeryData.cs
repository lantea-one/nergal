using Microsoft.AspNetCore.Antiforgery;
using Nergal.Core.Identity;

namespace Nergal.Web;

// Framework antiforgery can identify federated users by subject alone. Bind
// each form to the complete controller actor, including its provider namespace.
internal sealed class ActorAntiforgeryData : IAntiforgeryAdditionalDataProvider
{
    public string GetAdditionalData(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true) { return ""; }
        var claims = context.User.FindAll(ControllerActorIdentity.ActorClaimType).Take(2).ToArray();
        return claims.Length == 1 && ControllerActorIdentity.IsValid(claims[0].Value) ? claims[0].Value : "";
    }

    public bool ValidateAdditionalData(HttpContext context, string additionalData)
    {
        var current = GetAdditionalData(context);
        return (current.Length != 0 || context.User.Identity?.IsAuthenticated != true) &&
            string.Equals(current, additionalData, StringComparison.Ordinal);
    }
}
