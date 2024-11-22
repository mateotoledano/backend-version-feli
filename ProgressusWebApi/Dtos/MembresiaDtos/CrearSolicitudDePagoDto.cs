namespace ProgressusWebApi.Dtos.MembresiaDtos
{
    public class CrearSolicitudDePagoDto
    {
        public string SocioId { get; set; }
        public int MembresiaId { get; set; }
        public int TipoDePagoId { get; set; }
    }
}
