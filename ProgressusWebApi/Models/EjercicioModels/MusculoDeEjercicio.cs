using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressusWebApi.Models.EjercicioModels
{
    public class MusculoDeEjercicio
    {
        [Key]
        public int EjercicioId { get; set; }

        [ForeignKey(nameof(EjercicioId))]
        public Ejercicio Ejercicio { get; set; }

        [Key]
        public int MusculoId { get; set; }

        [ForeignKey(nameof(MusculoId))]
        public Musculo Musculo { get; set; }
    }
}
