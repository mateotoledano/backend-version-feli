using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.AuthDtos;
using ProgressusWebApi.Services.AuthServices.Interfaces;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ProgressusWebApi.Controllers.AuthControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _usuarioService;

        public AuthController(IAuthService usuarioService)
        {
            _usuarioService = usuarioService;
        }

        [HttpPut("CambiarContraseña")]
        public async Task<IActionResult> CambiarContraseña([FromBody] string correo, string nuevaContraseña, string contraseñaActual)
        {
            return await _usuarioService.CambiarContraseña(correo, nuevaContraseña, contraseñaActual);
        }

        [HttpPost("EnviarCodigoDeVerificacionRecuperarContraseña")]
        public async Task<IActionResult> EnviarCodigoDeVerificacionCambioContraseña([FromBody] CorreoRequestDto correo)
        {
            return await _usuarioService.EnviarCodigoDeVerificacion(correo.Email);
        }

        [HttpPost("EnviarCodigoDeVerificacionConfirmarEmail")]
        public async Task<IActionResult> EnviarCodigoDeVerificacionConfirmarEmail([FromBody] CorreoRequestDto correo)
        {
            return await _usuarioService.EnviarCodigoDeVerificacion(correo.Email);
        }

        [HttpPost("ComprobarCodigoDeRecuperarContraseña")]
        public async Task<IActionResult> ComprobarCodigoDeRecuperarContraseña([FromBody] CodigoDeVerificacionDto codigoDeVerificacion)
        {
            return await _usuarioService.ObtenerTokenCambioDeContraseña(codigoDeVerificacion);
        }

        [HttpPut("RecuperarContraseña")]
        public async Task<IActionResult> RecuperarContraseña([FromBody] CambioDeContraseñaDto cambioDeContraseñaDto)
        {
            return await _usuarioService.RecuperarContraseña(cambioDeContraseñaDto);
        }

        [HttpPost("ComprobarCodigoDeConfirmacionCorreo")]
        public async Task<IActionResult> ConfirmarCorreo([FromBody] CodigoDeVerificacionDto codigoDeVerificacion)
        {
            return await _usuarioService.ConfirmarCorreo(codigoDeVerificacion);
        }


        [HttpGet("ObtenerDatosDelUsuario")]
        public async Task<IActionResult> ObtenerDatosDelUsuario(string email)
        {
            return await _usuarioService.ObtenerDatosDelUsuario(email);
        }

        [HttpPost("RegistrarComoSocio")]
        public async Task<IActionResult> RegistrarComoSocio(string email, string nombre, string apellido, string telefono)
        {
            return await _usuarioService.RegistrarSocio(email,nombre, apellido);
        }

        [HttpPost("RegistrarComoEntrenador")]
        public async Task<IActionResult> RegistrarComoEntrenador(string email, string nombre, string apellido, string telefono)
        {
            return await _usuarioService.RegistrarEntrenador(email, nombre, apellido);
        }

    }

}
