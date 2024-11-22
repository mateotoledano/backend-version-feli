using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Models.PlanEntrenamientoModels
{
    public class EjercicioEnDiaDelPlan
    {
        [Key, Column(Order = 0)]
        public int DiaDePlanId { get; set; }

        [ForeignKey(nameof(DiaDePlanId))]
        public DiaDePlan DiaDePlan { get; set; }

        [Key, Column(Order = 1)]
        public int EjercicioId { get; set; }

        [ForeignKey(nameof(EjercicioId))]
        public Ejercicio Ejercicio { get; set; }

        [Required]
        public int OrdenDeEjercicio { get; set; }

        [Required]
        public int Series { get; set; }

        [Required]
        public int Repeticiones { get; set; }
        public List<SerieDeEjercicio> SeriesDeEjercicio { get; set; } = new List<SerieDeEjercicio>();
    }
}
