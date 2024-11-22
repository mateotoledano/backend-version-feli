using ProgressusWebApi.Models.PlanEntrenamientoModels;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces
{
    public interface IEjercicioEnDiaDelPlanRepository
    {
        Task<List<EjercicioEnDiaDelPlan>> ObtenerEjerciciosDelDia(int diaDelPlanId);
        Task<EjercicioEnDiaDelPlan?> AgregarEjercicioADiaDelPlan(EjercicioEnDiaDelPlan ejercicioEnDiaDelPlan);
        Task QuitarEjerciciosDelPlan(int planId);
    }
}
