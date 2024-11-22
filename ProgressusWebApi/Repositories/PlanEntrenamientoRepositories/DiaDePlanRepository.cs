using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using System.Numerics;
using System.Runtime.Intrinsics.Arm;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories
{
    public class DiaDePlanRepository : IDiaDePlanRepository
    {
        private readonly ProgressusDataContext _progressusDataContext;
        public DiaDePlanRepository (ProgressusDataContext progressusDataContext)
        {
            _progressusDataContext = progressusDataContext;
        }
        public async Task<DiaDePlan> Crear(DiaDePlan diaDePlan)
        {
            _progressusDataContext.DiasDePlan.Add(diaDePlan);
            await _progressusDataContext.SaveChangesAsync();
            return diaDePlan;
        }

        public async Task<bool> Eliminar(DiaDePlan diaDePlan)
        {
            var diaDePlanExiste = await _progressusDataContext.DiasDePlan.FindAsync(diaDePlan.Id);
            if (diaDePlanExiste != null)
            {
                _progressusDataContext.DiasDePlan.Remove(diaDePlan);
                await _progressusDataContext.SaveChangesAsync();
                return true;
            }
            return false;
        }

        public async Task<DiaDePlan> ObtenerDiaDePlan(int planId, int numeroDeDia)
        {
            return await _progressusDataContext.DiasDePlan
                .FirstOrDefaultAsync(ddp => ddp.PlanDeEntrenamientoId == planId && ddp.NumeroDeDia == numeroDeDia);
        }
    }
}
