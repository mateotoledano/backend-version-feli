using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamiento;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamientoDto;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;

namespace ProgressusWebApi.Controllers.PlanEntrenamientoControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PlanDeEntrenamientoController : ControllerBase
    {
        private readonly IPlanDeEntrenamientoService _planDeEntrenamientoService;
        public PlanDeEntrenamientoController(IPlanDeEntrenamientoService planDeEntrenamientoService)
        {
            _planDeEntrenamientoService = planDeEntrenamientoService;
        }

        //ObtenerPorId, ObtenerPlantillas, ObtenerPorNombre, ObtenerPorObjetivo

        [HttpPost("CrearPlanDeEntrenamiento")]
        public async Task<IActionResult> CrearPlanDeEntrenamiento([FromBody] CrearPlanDeEntrenamientoDto planDto)
        {
            PlanDeEntrenamiento planCreado = await _planDeEntrenamientoService.Crear(planDto);
            return Ok(planCreado);
        }

        [HttpPost("ActualizarPlanDeEntrenamiento")]
        public async Task<IActionResult> ActualizarPlanDeEntrenamiento(int id, ActualizarPlanDeEntrenamientoDto planDto)
        {
            PlanDeEntrenamiento planActualizado = await _planDeEntrenamientoService.Actualizar(id, planDto);
            return Ok(planActualizado);
        }

        [HttpPut("ActualizarEjerciciosDelPlan")]
        public async Task<IActionResult> ActualizarEjerciciosDelPlan(AgregarQuitarEjerciciosAPlanDto ejerciciosEnPlanDto)
        {
            PlanDeEntrenamiento? ejerciciosActualizados = await _planDeEntrenamientoService.ActualizarEjerciciosDelPlan(ejerciciosEnPlanDto.PlanDeEntrenamientoId, ejerciciosEnPlanDto);
            return Ok(ejerciciosActualizados);
        }

        [HttpPut("ConvertirPlanEnPlantilla")]
        public async Task<IActionResult> ConvertirEnPlantilla(int id)
        {
            PlanDeEntrenamiento? nuevaPlantilla = await _planDeEntrenamientoService.ConvertirEnPlantilla(id);
            return Ok(nuevaPlantilla);
        }

        [HttpPut("QuitarConvertirPlanEnPlantilla")]
        public async Task<IActionResult> QuitarConvertirEnPlantilla(int id)
        {
            PlanDeEntrenamiento? nuevaPlantilla = await _planDeEntrenamientoService.QuitarConvertirEnPlantilla(id);
            return Ok(nuevaPlantilla);
        }

        [HttpDelete("EliminarPlanDeEntrenamiento")]
        public async Task<IActionResult> EliminarPlanDeEntrenamiento(int id)
        {
            bool? planEliminado = await _planDeEntrenamientoService.Eliminar(id);
            return Ok();
        }


        [HttpGet("ObtenerPlanesPlantillas")]
        public async Task<IActionResult> ObtenerPlanesPlantillas()
        {
            List<PlanDeEntrenamiento> planes = await _planDeEntrenamientoService.ObtenerPlantillasDePlanes();
            return Ok(planes);
        }

        [HttpGet("ObtenerPlanesDelUsuario")]
        public async Task<IActionResult> ObtenerPlanesDelUsuario(string identityUser)
        {
            List<PlanDeEntrenamiento?> planes = await _planDeEntrenamientoService.ObtenerPlanesDelUsuario(identityUser);
            return Ok(planes);
        }

        [HttpGet("ObtenerTodosLosPlanes")]
        public async Task<IActionResult> ObtenerTodosLosPlanes()
        {
            List<PlanDeEntrenamiento?> planes = await _planDeEntrenamientoService.ObtenerTodosLosPlanes();
            return Ok(planes);
        }

        [HttpGet("ObtenerPlanPorId")]
        public async Task<IActionResult> ObtenerPlanPorId(int id)
        {
            var plan = _planDeEntrenamientoService.ObtenerPorId(id).Result;
            return Ok(plan);
        }
    }
}
