using MercadoPago.Client.Preference;
using MercadoPago.Resource.Preference;
using ProgressusWebApi.Models.MembresiaModels;
using WebApiMercadoPago.Repositories.Interface;
using WebApiMercadoPago.Services.Interface;

namespace WebApiMercadoPago.Services
{
    public class MercadoPagoService : IMercadoPagoService
    {
        private readonly IMercadoPagoRepository _mercadoPagoRepository;

        public MercadoPagoService(IMercadoPagoRepository mercadoPagoRepository)
        {
            _mercadoPagoRepository = mercadoPagoRepository;
        }

        public async Task<Preference> CreatePreferenceAsync(PreferenceRequest preference)
        {
            SolicitudDePago solicitud = new SolicitudDePago();
            return await _mercadoPagoRepository.CreatePreferenceAsync(solicitud);
        }
    }
}
