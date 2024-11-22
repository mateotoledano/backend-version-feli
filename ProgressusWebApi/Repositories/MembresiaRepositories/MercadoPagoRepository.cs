using MercadoPago.Client.Common;
using MercadoPago.Client.Payment;
using MercadoPago.Client.Preference;
using MercadoPago.Config;
using MercadoPago.Resource.Preference;
using Microsoft.AspNetCore.Identity;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.MembresiaModels;
using ProgressusWebApi.Services.AuthServices.Interfaces;
using WebApiMercadoPago.Repositories.Interface;

namespace WebApiMercadoPago.Repositories
{
    public class MercadoPagoRepository : IMercadoPagoRepository
    {

        private readonly ProgressusDataContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        public MercadoPagoRepository(ProgressusDataContext dataContext, UserManager<IdentityUser> userManager)
        {
            _context = dataContext;
            _userManager = userManager;

            
        }

        public async Task<Preference> CreatePreferenceAsync(SolicitudDePago solicitud)
        {
            var client = new PreferenceClient();

            var usuario = _userManager.FindByIdAsync(solicitud.IdentityUserId).Result;

            var request = new PreferenceRequest
            {
                Items = new List<PreferenceItemRequest>
                {
                  new PreferenceItemRequest
                  {
                      Title = solicitud.Membresia.Nombre,
                      CurrencyId = "ARS",
                      PictureUrl = "https://www.mercadopago.com/org-img/MP3/home/logomp3.gif",
                      Description = solicitud.Membresia.Descripcion,
                      Quantity = 1,
                      UnitPrice = solicitud.Membresia.Precio
                  }
                },
                Payer = new PreferencePayerRequest
                {
                    Name = usuario.UserName,
                    Email = usuario.Email,
                },
                
                //Redirección del usuario según resultado del pago
                BackUrls = new PreferenceBackUrlsRequest
                {
                    Success = "https://www.success.com",
                    Failure = "https://www.failure.com",
                    Pending = "https://www.pending.com"
                },

                //URL para recibir la información del pago        
                NotificationUrl = "https://www.notification.com",

                AutoReturn = "approved",
                PaymentMethods = new PreferencePaymentMethodsRequest
                {
                    //
                },

                //Expira en una hora
                Expires = true,
                ExpirationDateFrom = DateTime.Now,
                ExpirationDateTo = DateTime.Now.AddHours(1),
            };

            //Devuelve el init-point (link a donde redirigir al cliente para el pago)
            Preference result = await client.CreateAsync(request);
            return result;
        }
    }
}
