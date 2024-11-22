using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.GrupoMuscularDto;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Services.EjercicioServices;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;
using ProgressusWebApi.Services.PlanEntrenamientoServices;

namespace ProgressusWebApi.Controllers.EjercicioControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GrupoMuscularController : ControllerBase
    {
        private readonly IGrupoMuscularService _grupoMuscularService;
        public GrupoMuscularController(IGrupoMuscularService grupoMuscularService)
        {
            _grupoMuscularService = grupoMuscularService;
        }

        [HttpPost("CrearGrupoMuscular")]
        public async Task<IActionResult> Crear([FromBody] CrearActualizarGrupoMuscularDto grupoMuscular)
        {
            var grupoMuscularCreado = await _grupoMuscularService.Crear(grupoMuscular);
            return CreatedAtAction(nameof(ObtenerPorId), new { id = grupoMuscularCreado.Id }, grupoMuscularCreado);
        }

        [HttpGet("ObtenerGrupoMuscularPorId")]
        public async Task<IActionResult> ObtenerPorId(int grupoMuscularId)
        {
            var grupoMuscular = await _grupoMuscularService.ObtenerPorId(grupoMuscularId);
            if (grupoMuscular == null) return NotFound();
            return Ok(grupoMuscular);
        }

        [HttpDelete("EliminarGrupoMuscular")]
        public async Task<IActionResult> Eliminar(int id)
        {
            var grupoMuscularEliminado = await _grupoMuscularService.Eliminar(id);
            if (grupoMuscularEliminado == null) return NotFound();
            return Ok(grupoMuscularEliminado);
        }

        [HttpGet("ObtenerTodosLosGruposMusculares")]
        public async Task<IActionResult> ObtenerTodos()
        {
            var gruposMusculares = await _grupoMuscularService.ObtenerTodos();
            return Ok(gruposMusculares);
        }


        [HttpGet("ObtenerGrupoMuscularPorNombre")]
        public async Task<IActionResult> ObtenerPorMusculo(string nombre)
        {
            var gruposMusculares = await _grupoMuscularService.ObtenerPorNombre(nombre);
            if (gruposMusculares == null) return NotFound();
            return Ok(gruposMusculares);
        }

        [HttpPut("ActualizarGrupoMuscular")]
        public async Task<IActionResult> Actualizar(int id, [FromBody] CrearActualizarGrupoMuscularDto grupoMuscular)
        {
            var grupoMuscularActualizado = await _grupoMuscularService.Actualizar(id, grupoMuscular);
            if (grupoMuscularActualizado == null) return NotFound();
            return Ok(grupoMuscularActualizado);
        }
    }
}
