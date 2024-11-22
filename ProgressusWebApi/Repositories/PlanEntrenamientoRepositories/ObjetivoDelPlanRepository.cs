using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories
{
    public class ObjetivoDelPlanRepository : IObjetivoDelPlanRepository
    {
        private readonly ProgressusDataContext _progressusDataContext;
        public ObjetivoDelPlanRepository(ProgressusDataContext progressusDataContext)
        {
            _progressusDataContext = progressusDataContext;
        }

        public async Task<ObjetivoDelPlan> Crear(ObjetivoDelPlan objetivoDelPlan)
        {
            _progressusDataContext.ObjetivosDePlanes.Add(objetivoDelPlan);
            await _progressusDataContext.SaveChangesAsync();
            return objetivoDelPlan;
        }

        public async Task<ObjetivoDelPlan?> ObtenerPorId(int id) 
        {
            return await _progressusDataContext.ObjetivosDePlanes
                                 .FirstOrDefaultAsync(e => e.Id == id);
        }

        public async Task<ObjetivoDelPlan> Eliminar(int id)
        {
            var objetivo = await _progressusDataContext.ObjetivosDePlanes.FindAsync(id);
            if (objetivo == null) return null;
            _progressusDataContext.ObjetivosDePlanes.Remove(objetivo);
            await _progressusDataContext.SaveChangesAsync();
            return objetivo;
        }

        public async Task<List<ObjetivoDelPlan>> ObtenerTodos()
        {
            return await _progressusDataContext.ObjetivosDePlanes
                             .ToListAsync();
        }
    }
}
