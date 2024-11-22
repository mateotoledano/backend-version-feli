using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamientoDto
{
    public class CrearPlanDeEntrenamientoDto
    {
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public int ObjetivoDelPlanId { get; set; }
        public int DiasPorSemana { get; set; }

        public string DueñoId { get; set; }
    }
}
