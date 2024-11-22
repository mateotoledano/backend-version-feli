using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Dtos.EjercicioDtos.GrupoMuscularDto;
using ProgressusWebApi.Dtos.EjercicioDtos.MusculoDto;
using ProgressusWebApi.Services.EjercicioServices;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Controllers.EjercicioControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MusculoController : ControllerBase
    {
        private readonly IMusculoService _musculoService;
        private readonly IMusculoDeEjercicioService _musculoDeEjercicioService;

        public MusculoController (IMusculoService musculoService, IMusculoDeEjercicioService musculoDeEjercicioService)
        {
            _musculoService = musculoService;
            _musculoDeEjercicioService = musculoDeEjercicioService;
        }

        [HttpPost("CrearMusculo")]
        public async Task<IActionResult> Crear([FromBody] CrearActualizarMusculoDto musculo)
        {
            var musculoCreado = await _musculoService.Crear(musculo);
            return CreatedAtAction(nameof(ObtenerPorId), new { id = musculoCreado.Id }, musculoCreado);
        }

        [HttpGet("ObtenerMusculoPorId")]
        public async Task<IActionResult> ObtenerPorId(int musculoId)
        {
            var musculo = await _musculoService.ObtenerPorId(musculoId);
            if (musculo == null) return NotFound();
            return Ok(musculo);
        }

        [HttpDelete("EliminarMusculo")]
        public async Task<IActionResult> Eliminar(int id)
        {
            var musculoEliminado = await _musculoService.Eliminar(id);
            if (musculoEliminado == null) return NotFound();
            return Ok(musculoEliminado);
        }

        [HttpGet("ObtenerTodosLosMusculos")]
        public async Task<IActionResult> ObtenerTodos()
        {
            var musculos = await _musculoService.ObtenerTodos();
            return Ok(musculos);
        }


        [HttpGet("ObtenerMusculoPorNombre")]
        public async Task<IActionResult> ObtenerPorMusculo(string nombre)
        {
            var musculos = await _musculoService.ObtenerPorNombre(nombre);
            if (musculos == null) return NotFound();
            return Ok(musculos);
        }

        [HttpPut("ActualizarMusculo")]
        public async Task<IActionResult> Actualizar(int id, [FromBody] CrearActualizarMusculoDto musculo)
        {
            var musculoActualizado = await _musculoService.Actualizar(id, musculo);
            if (musculoActualizado == null) return NotFound();
            return Ok(musculoActualizado);
        }

        [HttpGet("ObtenerMusculoPorGrupoMuscular")]
        public async Task<IActionResult> ObtenerPorGrupoMuscular(int grupoMuscularId)
        {
            var ejercicios = await _musculoService.ObtenerPorGrupoMuscular(grupoMuscularId);
            if (ejercicios == null) return NotFound();
            return Ok(ejercicios);
        }
    }
}
