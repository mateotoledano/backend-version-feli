namespace ProgressusWebApi.Models.MembresiaModels
{
    public class HistorialSolicitudDePago
    {
        public int Id { get; set; }
        public int EstadoSolicitudId { get; set; }
        public EstadoSolicitud EstadoSolicitud { get; set; }
        public int SolicitudDePagoId { get; set; }
        public SolicitudDePago SolicitudDePago { get; set; }
        public DateTime FechaCambioEstado { get; set; }
    }
}
