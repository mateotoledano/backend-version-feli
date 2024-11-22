using Microsoft.AspNetCore.Identity;
using ProgressusWebApi.Model;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ProgressusWebApi.Models.PlanEntrenamientoModels
{
    public class AsignacionDePlan
    {
        public string SocioId { get; set; }

        [ForeignKey(nameof(SocioId)), Required]
        public IdentityUser Socio { get; set; }

        public int PlanDeEntrenamientoId { get; set; }

        [ForeignKey(nameof(PlanDeEntrenamientoId))]
        public PlanDeEntrenamiento PlanDeEntrenamiento { get; set; }

        public DateTime fechaDeAsginacion { get; set; } = DateTime.Now;
        public bool esVigente { get; set; }
    }
}
