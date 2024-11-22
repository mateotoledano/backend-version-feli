using ProgressusWebApi.Models.CobroModels;

namespace ProgressusWebApi.Models.MembresiaModels
{
    public class SolicitudDePago
    {
        public int Id { get; set; }
        public string IdentityUserId { get; set; }
        public int TipoDePagoId { get; set; }
        public TipoDePago TipoDePago { get; set; }
        public int MembresiaId { get; set; }
        public Membresia Membresia { get; set; }
        public List<HistorialSolicitudDePago> HistorialSolicitudDePagos { get; set; }
        public DateTime FechaCreacion {  get; set; }
    }
}
