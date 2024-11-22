using ProgressusWebApi.Model;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces
{
    public interface IDiaDePlanRepository
    {
        Task<DiaDePlan> Crear(DiaDePlan diaDePlan);
        Task<bool> Eliminar(DiaDePlan diaDePlan);
        Task<DiaDePlan> ObtenerDiaDePlan(int planId, int numeroDeDia);
    }
}
