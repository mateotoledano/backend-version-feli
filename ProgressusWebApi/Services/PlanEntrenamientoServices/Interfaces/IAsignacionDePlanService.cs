using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.AsignacionDePlanDto;
using ProgressusWebApi.Models.PlanEntrenamientoModels;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces
{
    public interface IAsignacionDePlanService
    {
        Task<ObtenerAsignacionDePlanDto> AsignarPlan(string socioId, int planId);
        Task<ObtenerAsignacionDePlanDto> QuitarAsignacionDePlan(string socioId, int planId);
        Task<ObtenerAsignacionDePlanDto> ObtenerPlanAsignado(string socioId);
        Task<List<ObtenerAsignacionDePlanDto>> ObtenerHistorialDePlanes(string socioId);
    }
}
