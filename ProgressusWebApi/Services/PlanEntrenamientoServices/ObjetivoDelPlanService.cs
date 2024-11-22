using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.ObjetivoDePlanDto;
using ProgressusWebApi.Model;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices
{
    public class ObjetivoDelPlanService : IObjetivoDelPlanService
    {
        private readonly IObjetivoDelPlanRepository _objetivoDelPlanRepository;
        public ObjetivoDelPlanService(IObjetivoDelPlanRepository objetivoDelPlanRepository)
        {
            _objetivoDelPlanRepository = objetivoDelPlanRepository;
        }
        public async Task<ObjetivoDelPlan> Crear(CrearObjetivoDePlanDto objetivoDePlanDto)
        {
            ObjetivoDelPlan objetivoDelPlan = new ObjetivoDelPlan()
            {
                Nombre = objetivoDePlanDto.Nombre,
                Descripcion = objetivoDePlanDto.Descripcion,
            };
            return await _objetivoDelPlanRepository.Crear(objetivoDelPlan);
        }

        public async Task<ObjetivoDelPlan> Eliminar(int id)
        {
            return await _objetivoDelPlanRepository.Eliminar(id);
        }

        public async Task<ObjetivoDelPlan> ObtenerPorId(int id)
        {
            return await _objetivoDelPlanRepository.ObtenerPorId(id);
        }

        public async Task<List<ObjetivoDelPlan>> ObtenerTodos()
        {
            return await _objetivoDelPlanRepository.ObtenerTodos();
        }
    }
}
