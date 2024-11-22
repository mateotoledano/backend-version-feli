using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.CobroModels;
using ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.MembresiaRepositories
{
    public class MembresiaRepository : IMembresiaRepository
    {
        private readonly ProgressusDataContext _context;

        public MembresiaRepository(ProgressusDataContext context)
        {
            _context = context;
        }

        public async Task<List<Membresia>> GetAll()
        {
            return await _context.Membresias.ToListAsync();
        }

        public async Task<Membresia> GetById(int id)
        {
            return await _context.Membresias.FindAsync(id);
        }

        public async Task Add(Membresia membresia)
        {
            await _context.Membresias.AddAsync(membresia);
            await _context.SaveChangesAsync();
        }

        public async Task Update(Membresia membresia)
        {
            _context.Membresias.Update(membresia);
            await _context.SaveChangesAsync();
        }

        public async Task Delete(int id)
        {
            var membresia = await _context.Membresias.FindAsync(id);
            if (membresia != null)
            {
                _context.Membresias.Remove(membresia);
                await _context.SaveChangesAsync();
            }
        }
    }
}
