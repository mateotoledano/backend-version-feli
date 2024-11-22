using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Services.EjercicioServices.Interfaces
{
    public interface IEjercicioService
    {
        Task<Ejercicio> Crear(CrearActualizarEjercicioDto ejercicio);
        Task<Ejercicio?> ObtenerPorId(int id);
        Task<List<Ejercicio>> ObtenerTodos();
        Task<List<Ejercicio>> ObtenerPorGrupoMuscular(int grupoMuscularId);
        Task<List<Ejercicio>> ObtenerPorMusculo(int musculoId);
        Task<Ejercicio?> Actualizar(int id, CrearActualizarEjercicioDto ejercicio);
        Task<Ejercicio?> Eliminar(int id);
    }
}
