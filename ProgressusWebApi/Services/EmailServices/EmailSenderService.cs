using Microsoft.Extensions.Options;
using ProgressusWebApi.Utilities;
using System.Net.Mail;
using System.Net;
using ProgressusWebApi.Services.EmailServices.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace ProgressusWebApi.Services.EmailServices
{
    public class EmailSenderService : IEmailSenderService
    {
        private readonly GmailSetter _mailSetter;
        public EmailSenderService(IOptions<GmailSetter> mailSetter)
        {
            _mailSetter = mailSetter.Value;
        }

        public async Task<IActionResult> SendEmail(string subject, string body, string to)
        {
            try
            {
                var fromEmail = _mailSetter.Email;
                var password = _mailSetter.Password;
                var message = new MailMessage();
                message.From = new MailAddress(fromEmail);
                message.Subject = subject;
                message.Body = body;
                message.To.Add(new MailAddress(to));
                message.IsBodyHtml = true;

                var smtpClient = new SmtpClient("smtp.gmail.com")
                {
                    Port = 587, //_mailSetter.Port,
                    Credentials = new NetworkCredential(fromEmail, password), //fromEmail, password
                    EnableSsl = true,
                };
                smtpClient.Send(message);
                return new OkObjectResult(HttpStatusCode.OK);
            }
            catch (Exception e)
            {
                throw new Exception("No se pudo enviar el email", e);
            }
        }
    }
}
