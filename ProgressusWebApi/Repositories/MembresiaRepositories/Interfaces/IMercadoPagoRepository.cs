using MercadoPago.Client.Preference;
using MercadoPago.Config;
using MercadoPago.Resource.Preference;
using ProgressusWebApi.Models.MembresiaModels;

namespace WebApiMercadoPago.Repositories.Interface
{
    public interface IMercadoPagoRepository
    {
        Task<Preference> CreatePreferenceAsync(SolicitudDePago solicitud);
       
    }
}
