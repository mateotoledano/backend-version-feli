using ProgressusWebApi.Model;

namespace ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamiento
{
    public class AgregarQuitarEjerciciosAPlanDto
    {
        public int PlanDeEntrenamientoId { get; set; }
        public List<EjerciciosOrdenadosEnPlanDto> Ejercicios { get; set; }
    }
}
