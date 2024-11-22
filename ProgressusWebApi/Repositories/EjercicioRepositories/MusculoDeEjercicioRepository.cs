using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Repositories.EjercicioRepositories
{
    public class MusculoDeEjercicioRepository : IMusculoDeEjercicioRepository
    {
        private readonly ProgressusDataContext _progressusDataContext;

        public MusculoDeEjercicioRepository(ProgressusDataContext progressusDataContext)
        {
            _progressusDataContext = progressusDataContext;
        }

        public async Task<MusculoDeEjercicio?> AgregarMusculoAEjercicio(MusculoDeEjercicio musculoDeEjercicio)
        {
            _progressusDataContext.Set<MusculoDeEjercicio>().Add(musculoDeEjercicio);
            await _progressusDataContext.SaveChangesAsync();

            return musculoDeEjercicio;
        }

        public async Task<List<int>?> ObtenerIdsDeMusculosDeEjercicio(int ejercicioId)
        {
            var resultado = await _progressusDataContext.MusculosDeEjercicios
                                                .Where(me => me.EjercicioId == ejercicioId)
                                                .Select(me => me.MusculoId)
                                                .ToListAsync();
            return resultado;
        }

        public async Task QuitarMusculoAEjercicio(int ejercicioId, int musculoId)
        {
            var musculoExiste = await _progressusDataContext.Set<MusculoDeEjercicio>()
                                               .FirstOrDefaultAsync(mde => mde.EjercicioId == ejercicioId && mde.MusculoId == musculoId);

            if (musculoExiste != null)
            {
                _progressusDataContext.Set<MusculoDeEjercicio>().Remove(musculoExiste);
                await _progressusDataContext.SaveChangesAsync();
            }
        }

    }
}
