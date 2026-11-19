# ADR 0014 — Local administrator browser sessions

Use a password and the existing singleton application account for local sign-in.
The web controller owns authentication. The firewall agent has no role in issuing
cookies or handling passwords. OIDC can later supply an additional login method.

Enable local sessions only through explicit configuration. Before serving requests,
check the existing account and open the protected key repository with operator-
supplied wrapping credentials. Startup must never create or replace an account.
Use a separate TLS certificate. Reject HTTP requests before authentication, form
processing or antiforgery when local sessions are enabled. Direct HTTPS is the
first supported topology.

Use one application cookie. Issue it only after the password transaction commits,
using the account and security stamp observed during verification. Recheck the
stamp and supported account state on each authenticated request. Use an absolute
fifteen-minute lifetime with no sliding renewal, and a host-only, secure, HttpOnly,
SameSite=Strict session cookie. Password lockout limits new sign-ins. Logging out
rotates the singleton account's security stamp, revoking all its sessions.

Protect both sign-in and sign-out POSTs with antiforgery validation. Bound form
sizes and concurrent password work. Use fixed local destinations after sign-in and
sign-out. Never echo entered credentials or expose differences between unknown,
incorrect and locked accounts. Authenticated web routes require a valid session.
The initial protected page reports only the session. Agent status requires a
separate authorization and transport integration.

MVC also registers a framework hosted service that opens its own default key
ring at startup, independently of the application provider. Omit that specific
preloader in both modes. Keep a regression check for unintended profile key
files across restarts. See [the framework preloader](https://github.com/dotnet/aspnetcore/blob/v10.0.0/src/DataProtection/DataProtection/src/Internal/DataProtectionHostedService.cs).
