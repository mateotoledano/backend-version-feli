using Microsoft.AspNetCore.Identity;

namespace ProgressusWebApi.Dtos.AuthDtos
{
    public class CodigoDeVerificacionDto
    {
        public string Email { get; set; }
        public string Codigo { get; set; }
    }
}
