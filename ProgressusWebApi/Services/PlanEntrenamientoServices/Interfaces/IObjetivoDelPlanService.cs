using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.ObjetivoDePlanDto;
using ProgressusWebApi.Model;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces
{
    public interface IObjetivoDelPlanService
    {
        Task<ObjetivoDelPlan> Crear(CrearObjetivoDePlanDto crearActualizarObjetivoDePlanDto);
        Task<ObjetivoDelPlan> Eliminar(int id);
        Task<List<ObjetivoDelPlan>> ObtenerTodos();
        Task<ObjetivoDelPlan> ObtenerPorId(int id);
    }
}
