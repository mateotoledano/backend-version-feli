namespace ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.AsignacionDePlanDto
{
    public class ObtenerAsignacionDePlanDto
    {
        public string SocioId { get; set; }
        public int PlanDeEntrenamientoId { get; set; }
        public DateTime FechaDeAsginacion { get; set; }
        public bool EsVigente { get; set; }
    }
}
