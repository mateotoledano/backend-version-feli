using ProgressusWebApi.Dtos.EjercicioDtos.GrupoMuscularDto;
using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Services.EjercicioServices.Interfaces
{
    public interface IGrupoMuscularService
    {
        Task<GrupoMuscular> Crear(CrearActualizarGrupoMuscularDto grupoMuscular);
        Task<GrupoMuscular> Eliminar(int id);
        Task<GrupoMuscular> Actualizar(int id, CrearActualizarGrupoMuscularDto grupoMuscular);
        Task<GrupoMuscular> ObtenerPorId(int id);
        Task<List<GrupoMuscular>> ObtenerPorNombre(string nombre);
        Task<List<GrupoMuscular>> ObtenerTodos();
    }
}
