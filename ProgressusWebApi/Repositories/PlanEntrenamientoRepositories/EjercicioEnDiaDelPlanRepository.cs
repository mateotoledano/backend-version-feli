using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories
{
    public class EjercicioEnDiaDelPlanRepository : IEjercicioEnDiaDelPlanRepository
    {
        private readonly ProgressusDataContext _progressusDataContext;
        public EjercicioEnDiaDelPlanRepository(ProgressusDataContext progressusDataContext)
        {
            _progressusDataContext = progressusDataContext;
        }
        public async Task<EjercicioEnDiaDelPlan?> AgregarEjercicioADiaDelPlan(EjercicioEnDiaDelPlan ejercicioEnDiaDelPlan)
        {
            _progressusDataContext.EjerciciosDelDia.Add(ejercicioEnDiaDelPlan);
            await _progressusDataContext.SaveChangesAsync();
            return ejercicioEnDiaDelPlan;
        }

        public async Task<List<EjercicioEnDiaDelPlan>> ObtenerEjerciciosDelDia(int diaDelPlanId)
        {
            return await _progressusDataContext.EjerciciosDelDia
               .Where(e => e.DiaDePlanId == diaDelPlanId)
               .ToListAsync();
        }

        public async Task QuitarEjerciciosDelPlan(int planId)
        {
            // Obtiene los ejercicios a eliminar
            var ejerciciosAEliminar = _progressusDataContext.EjerciciosDelDia
                .Where(e => e.DiaDePlan.PlanDeEntrenamientoId == planId);

            // Elimina los ejercicios obtenidos
            _progressusDataContext.EjerciciosDelDia.RemoveRange(ejerciciosAEliminar);

            // Guarda los cambios en la base de datos
            await _progressusDataContext.SaveChangesAsync();
        }
    }
}
