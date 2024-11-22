using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.EjercicioRepositories
{
    public class MusculoRepository : IMusculoRepository
    {
        private readonly ProgressusDataContext _context;

        public MusculoRepository(ProgressusDataContext context)
        {
            _context = context;
        }


        public async Task<Musculo?> Actualizar(int id, Musculo musculo)
        {
            var existingMusculo = await _context.Musculos.FindAsync(id);
            if (existingMusculo == null) return null;
            existingMusculo.Nombre = musculo.Nombre;
            existingMusculo.Descripcion = musculo.Descripcion;
            existingMusculo.ImagenMusculo = musculo.ImagenMusculo;
            existingMusculo.GrupoMuscularId = musculo.GrupoMuscularId;
            await _context.SaveChangesAsync();
            return existingMusculo;
        }

        public async Task<Musculo> Crear(Musculo musculo)
        {
            _context.Musculos.Add(musculo);
            await _context.SaveChangesAsync();
            return musculo;
        }

        public async Task<Musculo?> Eliminar(int id)
        {
            var musculo = await _context.Musculos.FindAsync(id);
            if (musculo == null)
            {
                return null;
            }
            _context.Musculos.Remove(musculo);
            await _context.SaveChangesAsync();
            return musculo;
        }

        public async Task<List<Musculo>> ObtenerPorGrupoMuscular(int grupoMuscularId)
        {
            return await _context.Musculos
            .Where(m => m.GrupoMuscularId == grupoMuscularId)
            .Include(m => m.GrupoMuscular)
            .ToListAsync();
        }

        public async Task<Musculo?> ObtenerPorId(int id)
        {
            return await _context.Musculos
              .Include(m => m.GrupoMuscular)
              .FirstOrDefaultAsync(m => m.Id == id);
        }

        public async Task<List<Musculo>>? ObtenerPorNombre(string nombre)
        {
            return await _context.Musculos
                                        .Where(gm => gm.Nombre.Contains(nombre))
                                        .ToListAsync();
        }

        public async Task<List<Musculo>> ObtenerTodos()
        {
            return await _context.Musculos
                .Include(m => m.GrupoMuscular)
                .ToListAsync();
        }
    }
}
