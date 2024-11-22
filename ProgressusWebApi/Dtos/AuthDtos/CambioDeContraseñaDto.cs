namespace ProgressusWebApi.Dtos.AuthDtos
{
    public class CambioDeContraseñaDto
    {
        public string Email { get; set; }
        public string Token {  get; set; }

        public string nuevaContraseña { get; set; } = string.Empty;
    }
}
