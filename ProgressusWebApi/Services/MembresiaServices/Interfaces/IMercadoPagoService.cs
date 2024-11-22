using MercadoPago.Client.Preference;
using MercadoPago.Resource.Preference;

namespace WebApiMercadoPago.Services.Interface
{
    public interface IMercadoPagoService
    {
        Task<Preference> CreatePreferenceAsync(PreferenceRequest preference);
    }
}
