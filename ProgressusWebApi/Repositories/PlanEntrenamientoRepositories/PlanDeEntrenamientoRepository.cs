using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Model;
using ProgressusWebApi.Repositories.Interfaces;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories 
{
    public class PlanDeEntrenamientoRepository : IPlanDeEntrenamientoRepository
    {
        private readonly ProgressusDataContext _context;

        public PlanDeEntrenamientoRepository(ProgressusDataContext context)
        {
            _context = context;
        }

        public async Task<PlanDeEntrenamiento> Crear(PlanDeEntrenamiento plan)
        {
            _context.PlanesDeEntrenamiento.Add(plan);
            await _context.SaveChangesAsync();
            return plan;
        }

        public async Task<PlanDeEntrenamiento?> ObtenerPorId(int id)
        {
            return await _context.PlanesDeEntrenamiento
                .Include(op => op.ObjetivoDelPlan)
                .Include(p => p.DiasDelPlan)
                    .ThenInclude(dp => dp.EjerciciosDelDia)
                        .ThenInclude(e => e.Ejercicio)
                .FirstOrDefaultAsync(p => p.Id == id);
        }

        public async Task<IActionResult> ObtenerPorIdSimplificado(int id)
        {
            var plan = await _context.PlanesDeEntrenamiento
                .Where(p => p.Id == id)
                .Select(p => new
                {
                    p.Id,
                    p.DueñoDePlanId,
                    p.Nombre,
                    p.Descripcion,
                    p.ObjetivoDelPlanId,
                    ObjetivoDelPlan = new
                    {
                        p.ObjetivoDelPlan.Nombre
                    },
                    p.DiasPorSemana,
                    p.FechaDeCreacion,
                    p.EsPlantilla,
                    DiasDelPlan = p.DiasDelPlan.Select(dp => new
                    {
                        dp.Id,
                        dp.PlanDeEntrenamientoId,
                        dp.NumeroDeDia,
                        EjerciciosDelDia = dp.EjerciciosDelDia.Select(ed => new
                        {
                            ed.DiaDePlanId,
                            ed.EjercicioId,
                            Ejercicio = new
                            {
                                ed.Ejercicio.Id,
                                ed.Ejercicio.Nombre
                            },
                            ed.OrdenDeEjercicio,
                            ed.Series,
                            ed.Repeticiones,
                        })
                    })
                })
                .FirstOrDefaultAsync();

            if (plan == null)
            {
                return new NotFoundObjectResult($"El plan con id {id} no existe.");
            }

            return new OkObjectResult(plan);
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPorNombre(string nombre)
        {
            return await _context.PlanesDeEntrenamiento
                .Include(p => p.ObjetivoDelPlan)
                .Where(p => p.Nombre.Contains(nombre))
                .ToListAsync();
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPorObjetivo(int objetivoDelPlanId)
        {
            return await _context.PlanesDeEntrenamiento
                .Include(p => p.ObjetivoDelPlan)
                .Where(p => p.ObjetivoDelPlanId == objetivoDelPlanId)
                .ToListAsync();
        }

        public async Task<PlanDeEntrenamiento> Actualizar(int id, PlanDeEntrenamiento plan)
        {
            _context.PlanesDeEntrenamiento.Update(plan);
            await _context.SaveChangesAsync();
            return plan;
        }

        public async Task<bool> Eliminar(int id)
        {
            var plan = await _context.PlanesDeEntrenamiento.FindAsync(id);
            if (plan != null)
            {
                _context.PlanesDeEntrenamiento.Remove(plan);
                await _context.SaveChangesAsync();
                return true;
            }
            return false;
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPlantillasDePlanes()
        {
            return await _context.PlanesDeEntrenamiento
                .Include(p => p.ObjetivoDelPlan)
                .Where(p => p.EsPlantilla == true)
                .ToListAsync();
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPlanesDelUsuario(string identityUser)
        {
            return await _context.PlanesDeEntrenamiento
            .Include(p => p.ObjetivoDelPlan)
            .Where(p => p.DueñoDePlanId == identityUser)
            .ToListAsync();
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerTodosLosPlanes()
        {
            return await _context.PlanesDeEntrenamiento
                .Include(p => p.ObjetivoDelPlan)
                .ToListAsync();
        }
    }
}
