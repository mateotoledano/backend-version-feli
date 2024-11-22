using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.MembresiaDtos;
using ProgressusWebApi.Models.MembresiaModels;
using ProgressusWebApi.Services.MembresiaServices;
using ProgressusWebApi.Services.MembresiaServices.Interfaces;

[ApiController]
[Route("api/[controller]")]
public class SolicitudDePagoController : ControllerBase
{
    private readonly ISolicitudDePagoService _solicitudDePagoService;

    public SolicitudDePagoController(ISolicitudDePagoService solicitudDePagoService)
    {
        _solicitudDePagoService = solicitudDePagoService;
    }

    [HttpPost("CrearSolicitudDePago")]
    public async Task<IActionResult> CrearSolicitudDePago(CrearSolicitudDePagoDto dto)
    {
        SolicitudDePago solicitud = await _solicitudDePagoService.CrearSolicitudDePago(dto);
        return Ok(solicitud);
    }

    [HttpPut("RegistrarPagoEnEfectivo")]
    public async Task<IActionResult> RegistrarPagoEnEfectivo(int idSolicitudDePago)
    {
        var solicitudExistente = await _solicitudDePagoService.RegistrarPagoEnEfectivo(idSolicitudDePago);
        if (solicitudExistente == null)
            return NotFound(); // Retornar 404 si no se encuentra la solicitud
        return Ok(solicitudExistente); // Retornar la solicitud actualizada
    }

    [HttpPut("RegistrarPagoConMercadoPago")]
    public async Task<IActionResult> RegistrarPagoConMercadoPago(int idSolicitudDePago)
    {
        var pref = await _solicitudDePagoService.RegistrarPagoConMercadoPago(idSolicitudDePago);
        if (pref == null)
            return NotFound(); // Retornar 404 si no se encuentra la solicitud
        return Ok(pref); // Retornar la solicitud actualizada
    }

    [HttpPut("CancelarSolicitudDePago")]
    public async Task<IActionResult> CancelarSolicitudDePago(int idSolicitudDePago)
    {
        var solicitudExistente = await _solicitudDePagoService.CancelarSolicitudDePago(idSolicitudDePago);
        if (solicitudExistente == null)
            return NotFound(); // Retornar 404 si no se encuentra la solicitud
        return Ok(solicitudExistente); // Retornar la solicitud cancelada
    }

    [HttpGet("ObtenerEstadoActualDeSolicitud")]
    public async Task<IActionResult> ObtenerEstadoActualDeSolicitud(int idSolicitudDePago)
    {
        return new OkObjectResult(_solicitudDePagoService.ObtenerEstadoActualDeSolicitud(idSolicitudDePago).Result);
    }

    [HttpGet("ObtenerSolicitudDePagoDeSocio")]
    public async Task<IActionResult> ObtenerSolicitudDePagoDeSocio(string IdentityUserId)
    {
        return new OkObjectResult(_solicitudDePagoService.ObtenerSolicitudDePagoDeSocio(IdentityUserId).Result);
    }

    [HttpGet("ObtenerTiposDePagos")]
    public async Task<IActionResult> ObtenerTiposDePagos()
    {
        return new OkObjectResult(await _solicitudDePagoService.ObtenerTiposDePago());
    }

    [HttpGet("ConsultarVigenciaDeMembresia")]
    public async Task<IActionResult> ConsultarVigenciaDeMembresia(string identityUserId)
    {
        return new OkObjectResult(await _solicitudDePagoService.ConsultarVigenciaDeMembresia(identityUserId));
    }
}   
