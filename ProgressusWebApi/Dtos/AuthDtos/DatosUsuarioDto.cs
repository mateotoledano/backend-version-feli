namespace ProgressusWebApi.Dtos.AuthDtos
{
    public class DatosUsuarioDto
    {
        public string IdentityUserId {  get; set; }
        public string Nombre { get; set; }
        public string Apellido { get; set; }
        public string Telefono { get; set; }
        public string Email { get; set; }
        public List<String> Roles { get; set; }
    }
}
