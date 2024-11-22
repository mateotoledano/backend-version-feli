using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces
{
    public interface IMusculoDeEjercicioRepository
    {
        Task<List<int>> ObtenerIdsDeMusculosDeEjercicio(int ejercicioId);
        Task<MusculoDeEjercicio?> AgregarMusculoAEjercicio(MusculoDeEjercicio musculoDeEjercicio);
        Task QuitarMusculoAEjercicio(int ejercicioId, int musculoId);
    }
}
