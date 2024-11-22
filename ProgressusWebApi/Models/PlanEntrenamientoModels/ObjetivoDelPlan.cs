using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Model
{
    public class ObjetivoDelPlan
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Nombre { get; set; }
        public string Descripcion { get; set; }

        public List<PlanDeEntrenamiento> PlanesDeEntrenamiento { get; set; } = new List<PlanDeEntrenamiento>();
    }
}
