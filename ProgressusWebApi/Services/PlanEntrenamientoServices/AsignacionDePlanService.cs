using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.AsignacionDePlanDto;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices
{
   public class AsignacionDePlanService : IAsignacionDePlanService
{
    private readonly IAsignacionDePlanRepository _asignacionDePlanRepository;
    private readonly ProgressusDataContext _progressusDataContext;

    public AsignacionDePlanService(IAsignacionDePlanRepository asignacionDePlanRepository)
    {
        _asignacionDePlanRepository = asignacionDePlanRepository;
    }

    public async Task<ObtenerAsignacionDePlanDto?> AsignarPlan(string socioId, int planId)
    {
        ObtenerAsignacionDePlanDto? planActual =  this.ObtenerPlanAsignado(socioId).Result;
        this.QuitarAsignacionDePlan(socioId, planActual.PlanDeEntrenamientoId);
        var asignacion = await _asignacionDePlanRepository.AsignarPlan(socioId, planId);
        return asignacion != null ? MapToDto(asignacion) : null;
    }

    public async Task<List<ObtenerAsignacionDePlanDto>> ObtenerHistorialDePlanes(string socioId)
    {
        var historial = await _asignacionDePlanRepository.ObtenerHistorialDePlanesAsignados(socioId);
        return historial.Select(MapToDto).ToList();
    }

    public async Task<ObtenerAsignacionDePlanDto?> ObtenerPlanAsignado(string socioId)
    {
        var planAsignado = await _asignacionDePlanRepository.ObtenerPlanAsignado(socioId);
        return planAsignado != null ? MapToDto(planAsignado) : null;
    }

    public async Task<ObtenerAsignacionDePlanDto?> QuitarAsignacionDePlan(string socioId, int planId)
    {
        var asignacion = await _asignacionDePlanRepository.QuitarAsignacionDePlan(socioId, planId);
        return asignacion != null ? MapToDto(asignacion) : null;
    }

    private ObtenerAsignacionDePlanDto MapToDto(AsignacionDePlan asignacion)
    {
        return new ObtenerAsignacionDePlanDto
        {
            SocioId = asignacion.SocioId,
            PlanDeEntrenamientoId = asignacion.PlanDeEntrenamientoId,
            FechaDeAsginacion = asignacion.fechaDeAsginacion,
            EsVigente = asignacion.esVigente
        };
    }
}


}
