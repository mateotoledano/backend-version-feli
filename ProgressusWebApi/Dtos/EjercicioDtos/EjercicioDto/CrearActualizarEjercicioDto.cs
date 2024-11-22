namespace ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto
{
    public class CrearActualizarEjercicioDto
    {
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public string? ImagenMaquina { get; set; }
        public string? VideoEjercicio { get; set; }
    }
}
