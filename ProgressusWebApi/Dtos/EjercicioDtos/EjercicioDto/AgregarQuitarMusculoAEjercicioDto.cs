namespace ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto
{
    public class AgregarQuitarMusculoAEjercicioDto
    {
        public int EjercicioId { get; set; }
        public List<int> MusculosIds { get; set; }
    }
}
