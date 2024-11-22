using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories
{
    public class AsignacionDePlanRepository : IAsignacionDePlanRepository
    {
        private readonly ProgressusDataContext _context;
        public AsignacionDePlanRepository(ProgressusDataContext context)
        {
            _context = context;
        }

        public async Task<AsignacionDePlan?> AsignarPlan(string socioId, int planEntrenamientoId)
        {
            // Verificar si ya existe una asignación vigente para el socio
            var asignacionExistente = await _context.AsignacionesDePlanes
                .FirstOrDefaultAsync(ap => ap.SocioId == socioId && ap.PlanDeEntrenamientoId == planEntrenamientoId);

            if (asignacionExistente != null)
            {
                // Actualizar la vigencia de la asignación existente
                asignacionExistente.esVigente = true;
                await _context.SaveChangesAsync();
                return asignacionExistente;
            }
            else
            {
                // Crear una nueva asignación
                var nuevaAsignacion = new AsignacionDePlan
                {
                    SocioId = socioId,
                    PlanDeEntrenamientoId = planEntrenamientoId,
                    esVigente = true,
                    fechaDeAsginacion = DateTime.Now
                };

                _context.AsignacionesDePlanes.Add(nuevaAsignacion);
                await _context.SaveChangesAsync();
                return nuevaAsignacion;
            }
        }

        public async Task<List<AsignacionDePlan>> ObtenerHistorialDePlanesAsignados(string socioId)
        {
            return await _context.AsignacionesDePlanes
                .Where(ap => ap.SocioId == socioId)
                .OrderByDescending(ap => ap.fechaDeAsginacion)
                .ToListAsync();
        }

        public async Task<AsignacionDePlan?> ObtenerPlanAsignado(string socioId)
        {
            return await _context.AsignacionesDePlanes
                .FirstOrDefaultAsync(ap => ap.SocioId == socioId && ap.esVigente);
        }

        public async Task<AsignacionDePlan?> QuitarAsignacionDePlan(string socioId, int planDeEntrenamientoId)
        {
            var asignacionExistente = await _context.AsignacionesDePlanes
                .FirstOrDefaultAsync(ap => ap.SocioId == socioId && ap.PlanDeEntrenamientoId == planDeEntrenamientoId);

            if (asignacionExistente != null)
            {
                asignacionExistente.esVigente = false;
                await _context.SaveChangesAsync();
            }

            return asignacionExistente;
        }
    }
}
