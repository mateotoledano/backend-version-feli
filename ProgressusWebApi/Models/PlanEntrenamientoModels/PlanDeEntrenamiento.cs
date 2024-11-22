using Microsoft.AspNetCore.Identity;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressusWebApi.Model
{
    public class PlanDeEntrenamiento
    {
        public int Id { get; set; }

        public string DueñoDePlanId { get; set; }
        public IdentityUser DueñoDelPlan { get; set; }

        [Required]
        public string Nombre { get; set; }
        public string Descripcion { get; set; }

        [Required]
        public int ObjetivoDelPlanId { get; set; }

        [ForeignKey(nameof(ObjetivoDelPlanId))]
        public ObjetivoDelPlan ObjetivoDelPlan { get; set; }

        [Required]
        public int DiasPorSemana { get; set; }
        public DateTime FechaDeCreacion { get; set; } = DateTime.Now;
        public bool EsPlantilla { get; set; }
        public List<DiaDePlan> DiasDelPlan { get; set; } = new List<DiaDePlan>();
        public List<AsignacionDePlan> Asignaciones { get; set; } = new List<AsignacionDePlan>();
    }
}
