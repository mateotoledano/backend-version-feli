using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces
{
    public interface IMusculoRepository
    {

        Task<Musculo> Crear(Musculo musculo);
        Task<Musculo?> Eliminar(int id);

        Task<Musculo?> Actualizar(int id, Musculo musculo);
        Task<Musculo?> ObtenerPorId(int id);
        Task <List<Musculo>>? ObtenerPorNombre(string nombre);
        Task<List<Musculo>> ObtenerTodos();
        Task<List<Musculo>> ObtenerPorGrupoMuscular(int grupoMuscularId);
    }
}
