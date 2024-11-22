using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressusWebApi.Models.EjercicioModels
{
    public class Musculo
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Nombre { get; set; }
        public string Descripcion { get; set; }

        [Required]
        public int GrupoMuscularId { get; set; }

        [ForeignKey(nameof(GrupoMuscularId))]
        public GrupoMuscular GrupoMuscular { get; set; }
        public string? ImagenMusculo { get; set; }
        public List<MusculoDeEjercicio> MusculosDeEjercicio { get; set; } = new List<MusculoDeEjercicio>();
    }
}
