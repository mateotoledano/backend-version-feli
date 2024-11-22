using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.ObjetivoDePlanDto;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;

namespace ProgressusWebApi.Controllers.PlanEntrenamientoControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ObjetivoDePlanController : ControllerBase
    {
        private readonly IObjetivoDelPlanService _objetivoDelPlanService;
        public ObjetivoDePlanController(IObjetivoDelPlanService objetivoDelPlanService)
        {
            _objetivoDelPlanService = objetivoDelPlanService;
        }

        [HttpPost("CrearObjetivoDePlan")]
        public async Task<IActionResult> Crear([FromBody] CrearObjetivoDePlanDto objetivoDePlanDto)
        {
            var objetivoCreado = await _objetivoDelPlanService.Crear(objetivoDePlanDto);
            return CreatedAtAction(nameof(ObtenerPorId), new { id = objetivoCreado.Id }, objetivoCreado);
        }

        [HttpGet("ObtenerObjetivoPorId")]
        public async Task<IActionResult> ObtenerPorId(int id)
        {
            var objetivo = await _objetivoDelPlanService.ObtenerPorId(id);
            if (objetivo == null) return NotFound();
            return Ok(objetivo);
        }

        [HttpGet("ObtenerTodosLosObjetivos")]
        public async Task<IActionResult> ObtenerTodos()
        {
            var objetivos = await _objetivoDelPlanService.ObtenerTodos();
            return Ok(objetivos);
        }

        [HttpDelete("EliminarObjetivo")]
        public async Task<IActionResult> Eliminar(int id)
        {
            var objetivoEliminado = await _objetivoDelPlanService.Eliminar(id);
            if (objetivoEliminado == null) return NotFound();
            return Ok(objetivoEliminado);
        }

    }
}
