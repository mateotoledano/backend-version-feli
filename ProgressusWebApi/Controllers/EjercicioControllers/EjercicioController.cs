using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Controllers.EjercicioControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EjercicioController : ControllerBase
    {
        private readonly IEjercicioService _ejercicioService;
        private readonly IMusculoDeEjercicioService _musculoDeEjercicioService;
        private readonly ProgressusDataContext _progressusDataContext;

        public EjercicioController(IEjercicioService ejercicioService, IMusculoDeEjercicioService musculoDeEjercicioService, ProgressusDataContext progressusDataContext)
        {
            _ejercicioService = ejercicioService;
            _musculoDeEjercicioService = musculoDeEjercicioService;
            _progressusDataContext = progressusDataContext;
        }

        [HttpPut("ActualizarMusculosDeEjercicio(PARCHE)")]
        public async Task<IActionResult> Prueba([FromBody] AgregarQuitarMusculoAEjercicioDto agregarQuitarMusculoAEjercicioDto)
        {
            int ejercicioId = agregarQuitarMusculoAEjercicioDto.EjercicioId;
            var musculosActualesIds = await _progressusDataContext.MusculosDeEjercicios
                                                .Where(me => me.EjercicioId == ejercicioId)
                                                .Select(me => me.MusculoId)
                                                .ToListAsync();

            var musculosActualizadosIds = agregarQuitarMusculoAEjercicioDto.MusculosIds;

            List<int> musculosParaAgregar = musculosActualizadosIds.Except(musculosActualesIds).ToList();
            List<int> musculosParaEliminar = musculosActualesIds.Except(musculosActualizadosIds).ToList();

            foreach (var musculoId in musculosParaAgregar)
            {
                MusculoDeEjercicio musculoAgregado = new MusculoDeEjercicio()
                {
                    MusculoId = musculoId,
                    EjercicioId = ejercicioId
                };
                _progressusDataContext.Set<MusculoDeEjercicio>().Add(musculoAgregado);
                await _progressusDataContext.SaveChangesAsync();
            }

            foreach (var musculoId in musculosParaEliminar)
            {
                MusculoDeEjercicio musculoEliminado = new MusculoDeEjercicio()
                {
                    MusculoId = musculoId,
                    EjercicioId = ejercicioId
                };
                _progressusDataContext.Set<MusculoDeEjercicio>().Remove(musculoEliminado);
                await _progressusDataContext.SaveChangesAsync();
            }

            var musculosActualizados = await _progressusDataContext.MusculosDeEjercicios
                                                .Where(me => me.EjercicioId == ejercicioId)
                                                .Select(me => me.MusculoId)
                                                .ToListAsync();

            return Ok(musculosActualizados);
        }


        [HttpPost("CrearEjercicio")]
        public async Task<IActionResult> Crear([FromBody] CrearActualizarEjercicioDto ejercicio)
        {
            var ejercicioCreado = await _ejercicioService.Crear(ejercicio);
            return CreatedAtAction(nameof(ObtenerPorId), new { id = ejercicioCreado.Id }, ejercicioCreado);
        }

        [HttpGet("ObtenerEjercicioPorId")]
        public async Task<IActionResult> ObtenerPorId(int id)
        {
            var ejercicio = await _ejercicioService.ObtenerPorId(id);
            if (ejercicio == null) return NotFound();
            return Ok(ejercicio);
        }

        [HttpGet("ObtenerEjercicioPorGrupoMuscular")]
        public async Task<IActionResult> ObtenerPorGrupoMuscular(int grupoMuscularId)
        {
            var ejercicios = await _ejercicioService.ObtenerPorGrupoMuscular(grupoMuscularId);
            if (ejercicios == null) return NotFound();
            return Ok(ejercicios);
        }

        [HttpGet("ObtenerEjercicioPorMusculo")]
        public async Task<IActionResult> ObtenerPorMusculo(int grupoMuscularId)
        {
            var ejercicios = await _ejercicioService.ObtenerPorMusculo(grupoMuscularId);
            if (ejercicios == null) return NotFound();
            return Ok(ejercicios);
        }

        [HttpGet("ObtenerTodosLosEjercicios")]
        public async Task<IActionResult> ObtenerTodos()
        {
            var ejercicios = await _ejercicioService.ObtenerTodos();
            return Ok(ejercicios);
        }

        [HttpPut("ActualizarEjercicio")]
        public async Task<IActionResult> Actualizar(int id, [FromBody] CrearActualizarEjercicioDto ejercicio)
        {
            var ejercicioActualizado = await _ejercicioService.Actualizar(id, ejercicio);
            if (ejercicioActualizado == null) return NotFound();
            return Ok(ejercicioActualizado);
        }

        [HttpDelete("EliminarEjercicio")]
        public async Task<IActionResult> Eliminar(int id)
        {
            var ejercicioEliminado = await _ejercicioService.Eliminar(id);
            if (ejercicioEliminado == null) return NotFound();
            return Ok(ejercicioEliminado);
        }

        [HttpPut("ActualizarMusculosDeEjercicio")]
        public async Task<IActionResult> ActualizarMusculosDeEjercicio([FromBody]AgregarQuitarMusculoAEjercicioDto agregarQuitarMusculoAEjercicioDto)
        {
            var resultado = await _musculoDeEjercicioService.ActualizarMusculosDeEjercicio(agregarQuitarMusculoAEjercicioDto);
            if (resultado == null) return NotFound();
            return Ok();
        }
    }
}
