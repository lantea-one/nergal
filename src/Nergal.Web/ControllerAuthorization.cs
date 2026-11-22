using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Nergal.Core.Identity;

namespace Nergal.Web;

internal static class ControllerAuthorization
{
    internal static void Configure(IServiceCollection services, bool federated)
    {
        var scheme = federated ? FederatedLogin.Browser : IdentityConstants.ApplicationScheme;
        services.AddAuthorization(options =>
        {
            options.AddPolicy(ControllerAuthorizationPolicies.Administrator, policy =>
                policy.AddAuthenticationSchemes(scheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(NergalRoles.Administrator));

            options.AddPolicy(ControllerAuthorizationPolicies.Reader, policy =>
                policy.AddAuthenticationSchemes(scheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(NergalRoles.Administrator, NergalRoles.Auditor));
        });
    }

    internal static bool TryResolveActor(ClaimsPrincipal user, out string actorId, out string role)
    {
        actorId = user.FindFirstValue(ControllerActorIdentity.ActorClaimType) ?? "";
        role = user.FindFirstValue(ClaimTypes.Role) ?? "";
        return NergalRoles.IsDefined(role) && ControllerActorIdentity.IsValid(actorId);
    }
}
