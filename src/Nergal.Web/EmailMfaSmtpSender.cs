using System.Net;
using System.Net.Mail;
using System.Runtime.Versioning;
using System.Security.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web;

/// <summary>Sends reserved email codes through the exact configured SMTP STARTTLS generation.</summary>
[SupportedOSPlatform("linux")]
internal sealed class EmailMfaSmtpSender(LocalAdministratorAccounts accounts, IDataProtectionProvider keys) : IMfaEmailSender
{
    public async Task SendAsync(EmailMfaDelivery delivery, CancellationToken cancellationToken)
    {
        if (!EmailDeliverySettings.IsMailbox(delivery.Address) || delivery.Code is not { Length: 6 } ||
            !delivery.Code.All(char.IsAsciiDigit))
        { throw new IOException("Email delivery unavailable."); }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var relay = await accounts.ReadEmailDeliveryRuntimeAsync(delivery.Generation, keys)
                ?? throw new IOException("Email delivery unavailable.");
            var settings = relay.Snapshot.Settings;
            using var client = new SmtpClient(settings.Host, settings.Port)
            {
                // System SMTP requires successful STARTTLS before sending credentials or the message.
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false
            };
            if (settings.UserName.Length != 0)
            { client.Credentials = new NetworkCredential(settings.UserName, relay.Password); }

            using var message = new MailMessage(settings.FromAddress, delivery.Address)
            {
                Subject = "Nergal verification code",
                Body = "Your Nergal verification code is " + delivery.Code + ". Use it only for the request you initiated."
            };
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromSeconds(10));
            await client.SendMailAsync(message, deadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new IOException("Email delivery unavailable."); }
        catch (Exception error) when (error is SmtpException or AuthenticationException or AccountStoreException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // SMTP responses can include addresses and credential diagnostics.
            throw new IOException("Email delivery unavailable.");
        }
    }
}
