using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.AuthDtos;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ProgressusWebApi.Services.AuthServices.Interfaces
{
    public interface IAuthService
    {

        Task<IActionResult> CambiarContraseña(string correo, string contraseñaNueva, string contraseñaActual);
        Task<IActionResult?> EnviarCodigoDeVerificacion(string email);

        Task<IActionResult?> ConfirmarCorreo(CodigoDeVerificacionDto codigoDeVerificacion);

        Task<IActionResult?> ObtenerTokenCambioDeContraseña(CodigoDeVerificacionDto codigoDeVerificacion);

        Task<bool> ComprobarCodigoDeVerificacion(CodigoDeVerificacionDto codigoDeVerificacion);

        Task<IActionResult> RecuperarContraseña(CambioDeContraseñaDto cambioDeContraseñaDto);
        Task<IActionResult> ObtenerDatosDelUsuario(string email);
        Task<IActionResult> RegistrarSocio(string email, string nombre, string apellido);
        Task<IActionResult> RegistrarEntrenador(string email, string nombre, string apellido);
    }
}
