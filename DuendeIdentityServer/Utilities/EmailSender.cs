
using IdentityServer.Models.ViewModels;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer.Utilities.EmailConfigurations
{
    public class EmailSender : IEmailSender
    {
        private readonly IOptions<MailDetailsViewModel> _options;
        public EmailSender(IOptions<MailDetailsViewModel> options) 
        { 
            _options = options;
        }
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            var emailToSend = new MimeMessage();
            emailToSend.From.Add(MailboxAddress.Parse(_options.Value.Email));
            emailToSend.To.Add(MailboxAddress.Parse(email));
            emailToSend.Subject = subject;
            emailToSend.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = htmlMessage };
            using (var emailClient = new MailKit.Net.Smtp.SmtpClient())
            {
                emailClient.Connect(_options.Value.Host, _options.Value.Port, MailKit.Security.SecureSocketOptions.StartTls);
                emailClient.Authenticate(_options.Value.Username, _options.Value.Password);
                emailClient.Send(emailToSend);
                emailClient.Disconnect(true);
            }
            return Task.CompletedTask;
        }
    }
}
