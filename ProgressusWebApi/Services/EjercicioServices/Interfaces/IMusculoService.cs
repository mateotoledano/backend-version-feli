using ProgressusWebApi.Dtos.EjercicioDtos.MusculoDto;
using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Services.EjercicioServices.Interfaces
{
    public interface IMusculoService
    {
        Task<Musculo> Crear(CrearActualizarMusculoDto musculoDto);
        Task<Musculo> Actualizar(int id, CrearActualizarMusculoDto musculoDto);
        Task<Musculo?> Eliminar(int id);
        Task<Musculo?> ObtenerPorId(int id);
        Task<List<Musculo?>> ObtenerPorNombre(string nombre);
        Task<List<Musculo>> ObtenerTodos();
        Task<List<Musculo>> ObtenerPorGrupoMuscular(int grupoMuscularId);
    }
}
