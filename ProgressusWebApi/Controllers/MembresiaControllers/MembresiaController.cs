using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.MembresiaDtos;
using ProgressusWebApi.Services.MembresiaServices;
using ProgressusWebApi.Services.MembresiaServices.Interfaces;

[ApiController]
[Route("api/[controller]")]
public class MembresiaController : ControllerBase
{
    private readonly IMembresiaService _membresiaService;

    public MembresiaController(IMembresiaService membresiaService)
    {
        _membresiaService = membresiaService;
    }

    [HttpGet("ObtenerTodas")]
    public async Task<IActionResult> ObtenerTodas()
    {
        var membresias = await _membresiaService.GetAll();
        if (membresias == null || membresias.Count == 0) return NotFound();
        return Ok(membresias);
    }

    [HttpGet("ObtenerMembresiaPorId")]
    public async Task<IActionResult> ObtenerPorId(int id)
    {
        var membresia = await _membresiaService.GetById(id);
        if (membresia == null) return NotFound();
        return Ok(membresia);
    }

    [HttpPost("CrearMembresia")]
    public async Task<IActionResult> CrearMembresia(CrearMembresiaDto dto)
    {
        await _membresiaService.Add(dto);
        return Ok(dto);
    }

    [HttpPut("ActualizarMembresia")]
    public async Task<IActionResult> ActualizarMembresia(int id, CrearMembresiaDto dto)
    {
        var membresiaExistente = await _membresiaService.GetById(id);
        if (membresiaExistente == null) return NotFound();

        await _membresiaService.Update(dto, id);
        return NoContent();
    }

    [HttpDelete("EliminarMembresia")]
    public async Task<IActionResult> EliminarMembresia(int id)
    {
        var membresiaExistente = await _membresiaService.GetById(id);
        if (membresiaExistente == null) return NotFound();

        await _membresiaService.Delete(id);
        return NoContent();
    }
}

