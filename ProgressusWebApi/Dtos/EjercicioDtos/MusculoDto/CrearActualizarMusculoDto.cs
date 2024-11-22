using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Dtos.EjercicioDtos.MusculoDto
{
    public class CrearActualizarMusculoDto
    {
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public int GrupoMuscularId { get; set; }
        public string? ImagenMusculo { get; set; }
    }
}
