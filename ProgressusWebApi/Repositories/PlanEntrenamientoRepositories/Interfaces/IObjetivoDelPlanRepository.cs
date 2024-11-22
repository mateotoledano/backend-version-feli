using ProgressusWebApi.Model;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces
{
    public interface IObjetivoDelPlanRepository
    {
        Task<ObjetivoDelPlan> Crear(ObjetivoDelPlan objetivoDelPlan);
        Task<ObjetivoDelPlan> Eliminar(int id);
        Task<List<ObjetivoDelPlan>> ObtenerTodos();
        Task<ObjetivoDelPlan> ObtenerPorId(int id);
    }
}
