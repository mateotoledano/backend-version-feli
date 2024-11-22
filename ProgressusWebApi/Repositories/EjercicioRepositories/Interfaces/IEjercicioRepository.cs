using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces
{
    public interface IEjercicioRepository
    {
        Task<Ejercicio> Crear(Ejercicio ejercicio);
        Task<Ejercicio?> ObtenerPorId(int id);
        Task<List<Ejercicio?>> ObtenerTodos();
        Task<Ejercicio?> Actualizar(int id, Ejercicio ejercicio);
        Task<Ejercicio?> Eliminar(int id);
        Task<List<Ejercicio?>> ObtenerPorGrupoMuscular(int grupoMuscularId);
        Task<List<Ejercicio?>> ObtenerPorMusculo(int musculoId);

    }
}
