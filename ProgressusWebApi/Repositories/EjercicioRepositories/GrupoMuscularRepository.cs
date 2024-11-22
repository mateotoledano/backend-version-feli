using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.EjercicioRepositories
{
    public class GrupoMuscularRepository : IGrupoMuscularRepository
    {
        private readonly ProgressusDataContext _context;

        public GrupoMuscularRepository(ProgressusDataContext context)
        {
            _context = context;
        }
        public async Task<GrupoMuscular?> Actualizar(int id, GrupoMuscular grupoMuscular)
        {
            var existingGrupoMuscular = await _context.GruposMusculares.FindAsync(id);
            if (existingGrupoMuscular == null) return null;
            existingGrupoMuscular.Nombre = grupoMuscular.Nombre;
            existingGrupoMuscular.Descripcion = grupoMuscular.Descripcion;
            existingGrupoMuscular.ImagenGrupoMuscular = grupoMuscular.ImagenGrupoMuscular;
            await _context.SaveChangesAsync();
            return existingGrupoMuscular;
        }

        public async Task<bool> ComprobarExistencia(int id)
        {
            return await _context.GruposMusculares.AnyAsync(g => g.Id == id);
        }

        public async Task<GrupoMuscular> Crear(GrupoMuscular grupoMuscular)
        {
            _context.GruposMusculares.Add(grupoMuscular);
            await _context.SaveChangesAsync();
            return grupoMuscular;
        }

        public async Task<GrupoMuscular> Eliminar(int id)
        {
            var grupoMuscular = await _context.GruposMusculares.FindAsync(id);
            if (grupoMuscular == null) return null;
            _context.GruposMusculares.Remove(grupoMuscular);
            await _context.SaveChangesAsync();
            return grupoMuscular;
        }

        public async Task<GrupoMuscular?> ObtenerPorId(int id)
        {
            return await _context.GruposMusculares.FindAsync(id);
        }

        public async Task<List<GrupoMuscular>>? ObtenerPorNombre(string nombre)
        {
            return await _context.GruposMusculares
                                 .Where(gm => gm.Nombre.Contains(nombre))
                                 .ToListAsync();
        }

        public async Task<List<GrupoMuscular>> ObtenerTodos()
        {
            return await _context.GruposMusculares.Include(m => m.MusculosDelGrupo).ToListAsync();
        }
    }
}
