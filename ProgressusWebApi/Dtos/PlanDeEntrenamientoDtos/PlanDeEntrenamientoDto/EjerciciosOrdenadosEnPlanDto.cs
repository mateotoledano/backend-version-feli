using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamiento
{
    public class EjerciciosOrdenadosEnPlanDto
    {
        public int EjercicioId { get; set; }
        public int NumeroDiaDelPlan { get; set; }
        public int OrdenDelEjercicio { get; set; }
        public int Series { get; set; }
        public int Repeticiones { get; set; }
    }
}
