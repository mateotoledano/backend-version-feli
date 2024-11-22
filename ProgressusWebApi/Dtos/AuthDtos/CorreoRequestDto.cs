using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Dtos.AuthDtos
{
    public class CorreoRequestDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
