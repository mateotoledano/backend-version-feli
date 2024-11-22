using ProgressusWebApi.Models.PlanEntrenamientoModels;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces
{
    public interface IAsignacionDePlanRepository
    {
        Task<AsignacionDePlan> ObtenerPlanAsignado(string socioId);
        Task<List<AsignacionDePlan>> ObtenerHistorialDePlanesAsignados(string socioId);
        Task<AsignacionDePlan?> AsignarPlan(string socioId, int planEntrenamientoId);
        Task<AsignacionDePlan?> QuitarAsignacionDePlan(string socioId, int planDeEntrenamientoId);
    }
}
