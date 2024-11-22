using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ProgressusWebApi.Models.PlanEntrenamientoModels;

namespace ProgressusWebApi.Model
{
    public class SerieDeEjercicio
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int DiaDePlanId { get; set; }

        [Required]
        public int EjercicioId { get; set; }

        [ForeignKey("DiaDePlanId, EjercicioId")]
        public EjercicioEnDiaDelPlan EjercicioDelDia { get; set; }

        [Required]
        public int NumeroDeSerie { get; set; }

        [Required]
        public int SemanaDelPlan { get; set; }

        [Required]
        public int RepeticionesConcretadas { get; set; }
        public DateTime fechaDeRealizacion { get; set; }
    }
}
