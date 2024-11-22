using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.AsignacionDePlanDto;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;
using System.Numerics;

namespace ProgressusWebApi.Controllers.PlanEntrenamientoControllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AsignacionDePlanController : ControllerBase
    {
        private readonly IAsignacionDePlanService _asignacionDePlanService;
        public AsignacionDePlanController (IAsignacionDePlanService asignacionDePlanService)
        {
            _asignacionDePlanService = asignacionDePlanService;
        }


        [HttpPost("AsignarPlanDeEntrenamiento")]
        public async Task<IActionResult> AsignarPlanDeEntrenamiento(string socioId, int planId)
        {
            try
            {
                var asignacion = await _asignacionDePlanService.AsignarPlan(socioId, planId);
                return Ok(asignacion);
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        [HttpDelete("QuitarAsignacionDePlanDeEntrenamiento")]
        public async Task<IActionResult> QuitarAsignacionDePlanDeEntrenamiento(string socioId, int planId)
        {
            try
            {
                var asignacion = await _asignacionDePlanService.QuitarAsignacionDePlan(socioId, planId);
                return Ok(asignacion);
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        [HttpGet("ObtenerHistorialDePlanes")]
        public async Task<IActionResult> ObtenerHistorialDePlanes(string socioId)
        {
            try
            {
                var asignacion = await _asignacionDePlanService.ObtenerHistorialDePlanes(socioId);
                return Ok(asignacion);
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

        [HttpGet("ObtenerPlanAsignado")]
        public async Task<IActionResult> ObtenerPlanAsignado(string socioId)
        {
            try
            {
                var asignacion = await _asignacionDePlanService.ObtenerPlanAsignado(socioId);
                return Ok(asignacion);
            }
            catch (Exception ex)
            {
                return BadRequest(ex);
            }
        }

    }
}
