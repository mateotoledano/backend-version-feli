using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using ProgressusWebApi.Models.PlanEntrenamientoModels;

namespace ProgressusWebApi.Model
{
    public class DiaDePlan
    {
        [Key]
        public int Id { get; set; }
        
        public int PlanDeEntrenamientoId { get; set; }
        
        [ForeignKey(nameof(PlanDeEntrenamientoId)), Required]
        public PlanDeEntrenamiento PlanDeEntrenamiento { get; set; }

        [Required]
        public int NumeroDeDia { get; set; }
        public List<EjercicioEnDiaDelPlan>? EjerciciosDelDia { get; set; } = new List<EjercicioEnDiaDelPlan>();
    }
}
