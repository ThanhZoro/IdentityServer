using SendGrid;
using SendGrid.Helpers.Mail;
using System.Threading.Tasks;

namespace IdentityServer.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly string _sendGridKey;
        public EmailSender(string sendGridUser, string sendGridKey)
        {
            _sendGridKey = sendGridKey;
        }

        public Task SendEmailAsync(string email, string subject, string message)
        {
            var sendStatus = Execute(subject, message, email);
            return sendStatus;
        }

        public Task Execute(string subject, string message, string email)
        {
            var client = new SendGridClient(_sendGridKey);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("noreply@email-quarantine.google.com", "TNT MGMT"),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(email));
            return client.SendEmailAsync(msg);
        }
    }
}