using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json.Linq;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Dtos.AuthDtos;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Models.MembresiaModels;
using ProgressusWebApi.Services.AuthServices.Interfaces;
using ProgressusWebApi.Services.EmailServices.Interfaces;

namespace ProgressusWebApi.Services.AuthServices
{
    public class AuthService : IAuthService
    {
        readonly IMemoryCache _memoryCache;
        readonly IEmailSenderService _emailSenderService;
        readonly UserManager<IdentityUser> _userManager;
        readonly ProgressusDataContext _progressusDataContext;

        public AuthService(IMemoryCache memoryCache, IEmailSenderService emailSenderService, UserManager<IdentityUser> userManager, ProgressusDataContext progressusDataContext)
        {
            _memoryCache = memoryCache;
            _emailSenderService = emailSenderService;
            _userManager = userManager;
            _progressusDataContext = progressusDataContext;
        }
        public async Task<IActionResult> EnviarCodigoDeVerificacion(string correo)
        {
            if (_memoryCache.TryGetValue(correo, out string codigoVerificacionExistente))
            {
                return new BadRequestObjectResult("El código para ese email ya se generó y se debe esperar 2 minutos.");
            }

            var codigoVerificacion = new Random().Next(1000, 9999).ToString();
            await _emailSenderService.SendEmail("Código de confirmación", codigoVerificacion, correo);
            _memoryCache.Set(correo, codigoVerificacion, TimeSpan.FromMinutes(2));

            return new OkObjectResult("El código de verificación se generó correctamente.");
        }

        public async Task<IActionResult> CambiarContraseña(string correo, string contraseñaNueva, string contraseñaActual)
        {
            try
            {
                IdentityUser? usuarioCambioContraseña = await _userManager.FindByEmailAsync(correo);
                if (!_userManager.CheckPasswordAsync(usuarioCambioContraseña, contraseñaActual).Result)
                {
                    return new BadRequestObjectResult("La contraseña es incorrecta");
                }
                var tokenCambioContraseña = await _userManager.GeneratePasswordResetTokenAsync(usuarioCambioContraseña);
                CambioDeContraseñaDto cambioDeContraseñaDto = new CambioDeContraseñaDto()
                {
                    Token = tokenCambioContraseña,
                    Email = correo,
                    nuevaContraseña = contraseñaNueva,
                };
                await this.RecuperarContraseña(cambioDeContraseñaDto);
                return new OkObjectResult(usuarioCambioContraseña);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
  
        }

        public async Task<IActionResult?> ConfirmarCorreo(CodigoDeVerificacionDto codigoDeVerificacion)
        {
            try
            {
                if (ComprobarCodigoDeVerificacion(codigoDeVerificacion).Result == false)
                {
                    return null;
                }

                IdentityUser? usuarioAConfirmar = await _userManager.FindByEmailAsync(codigoDeVerificacion.Email);
                if (usuarioAConfirmar == null)
                {
                    return null;
                }

                var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(usuarioAConfirmar);
                var result = await _userManager.ConfirmEmailAsync(usuarioAConfirmar, confirmationToken);
                if (!result.Succeeded)
                {
                    return null; // Fallo en la confirmación del correo
                }

                return new OkObjectResult("Email de usuario confirmado");
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
        }

        public async Task<IActionResult?> ObtenerTokenCambioDeContraseña(CodigoDeVerificacionDto codigoDeVerificacion)
        {
            try
            {
                if (ComprobarCodigoDeVerificacion(codigoDeVerificacion).Result == false)
                {
                    return null;
                }

                IdentityUser? usuarioCambioContraseña = await _userManager.FindByEmailAsync(codigoDeVerificacion.Email);
                if (usuarioCambioContraseña == null)
                {
                    return null;
                }
                CambioDeContraseñaDto cambioDeContraseña = new CambioDeContraseñaDto()
                {
                    Token = await _userManager.GeneratePasswordResetTokenAsync(usuarioCambioContraseña),
                    Email = codigoDeVerificacion.Email,
                };


                return new OkObjectResult(cambioDeContraseña);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
        }

        public async Task<IActionResult> RecuperarContraseña(CambioDeContraseñaDto cambioDeContraseñaDto)
        {
            try
            {
                IdentityUser? usuarioCambioContraseña = await _userManager.FindByEmailAsync(cambioDeContraseñaDto.Email);
                await _userManager.ResetPasswordAsync(usuarioCambioContraseña, cambioDeContraseñaDto.Token, cambioDeContraseñaDto.nuevaContraseña);
                return new OkResult();
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
        }
        public async Task<bool> ComprobarCodigoDeVerificacion(CodigoDeVerificacionDto codigoDeVerificacion)
        {
            try
            {
                if (!_memoryCache.TryGetValue(codigoDeVerificacion.Email, out string codigoDeVerificacionEnCache))
                {
                    return false;
                }

                if (codigoDeVerificacionEnCache != codigoDeVerificacion.Codigo)
                {
                    return false;
                }

                _memoryCache.Remove(codigoDeVerificacion.Email); // Eliminar el código de la caché
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task<IActionResult> RegistrarEntrenador(string email, string nombre, string apellido)
        {
            IdentityUser? usuarioARegistrar = await _userManager.FindByEmailAsync(email);
            Entrenador entrenador = new Entrenador()
            {
                User = usuarioARegistrar,
                UserId = usuarioARegistrar.Id,
                Nombre = nombre,
                Apellido = apellido
            };
            try
            {
                _progressusDataContext.Entrenadores.Add(entrenador);
                await _progressusDataContext.SaveChangesAsync();
                await _userManager.AddToRoleAsync(usuarioARegistrar, "ENTRENADOR");
                return new OkObjectResult(entrenador);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
        }

        public async Task<IActionResult> RegistrarSocio(string email, string nombre, string apellido)
        {
            IdentityUser? usuarioARegistrar = await _userManager.FindByEmailAsync(email);
            Socio socio = new Socio()
            {
                User = usuarioARegistrar,
                UserId = usuarioARegistrar.Id,
                Nombre = nombre,
                Apellido = apellido
            };
            try
            {
                _progressusDataContext.Socios.Add(socio);
                await _progressusDataContext.SaveChangesAsync();
                await _userManager.AddToRoleAsync(usuarioARegistrar, "SOCIO");
                return new OkObjectResult(socio);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex);
            }
        }

        public async Task<IActionResult> ObtenerDatosDelUsuario(string email)
        {
            IdentityUser usuario = await _userManager.FindByEmailAsync(email);
            var socio = await _progressusDataContext.Socios.FirstOrDefaultAsync(e => e.UserId == usuario.Id);
            if (socio == null) 
            {
                var entrenador = await _progressusDataContext.Entrenadores.FirstOrDefaultAsync(e => e.UserId == usuario.Id);
                DatosUsuarioDto datosDelEntrenador = new DatosUsuarioDto()
                {
                    IdentityUserId = usuario.Id,
                    Nombre = entrenador.Nombre,
                    Apellido = entrenador.Apellido,
                    Telefono = entrenador.Telefono,
                    Roles = _userManager.GetRolesAsync(usuario).Result.ToList(),
                    Email = email,
                   
                };
                return new OkObjectResult(datosDelEntrenador);
            }
            DatosUsuarioDto datosDelSocio = new DatosUsuarioDto()
            {
                IdentityUserId = usuario.Id,
                Nombre = socio.Nombre,
                Apellido = socio.Apellido,
                Telefono = socio.Telefono,
                Roles = _userManager.GetRolesAsync(usuario).Result.ToList(),
                Email = email,
            };
            
            return new OkObjectResult(datosDelSocio);
        }
    }
}
