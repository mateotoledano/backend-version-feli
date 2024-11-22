using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Models.EjercicioModels
{
    public class GrupoMuscular
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public string? ImagenGrupoMuscular { get; set; }
        public List<Musculo>? MusculosDelGrupo { get; set; } = new List<Musculo>();
    }
}
