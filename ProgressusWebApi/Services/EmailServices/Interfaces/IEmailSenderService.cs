using Microsoft.AspNetCore.Mvc;

namespace ProgressusWebApi.Services.EmailServices.Interfaces
{
    public interface IEmailSenderService
    {
        Task<IActionResult> SendEmail(string subject, string body, string to);
    }
}
