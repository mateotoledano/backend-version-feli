using MercadoPago.Client.Preference;

namespace WebApiMercadoPago.Dto.SolicitudDePagoDto
{
    public class CreatePreferenceRequestDto
    {
        public List<int> ItemsId { get; set; }
        public int PayerId { get; set; }
        public PreferenceBackUrlsRequest BackUrls { get; set; }
        public string NotificationUrl { get; set; }
    }
}
