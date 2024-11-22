using ProgressusWebApi.Dtos.EjercicioDtos.GrupoMuscularDto;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Services.EjercicioServices
{
    public class GrupoMuscularService : IGrupoMuscularService
    {
        private readonly IGrupoMuscularRepository _grupoMuscularRepository;
        public GrupoMuscularService(IGrupoMuscularRepository grupoMuscularRepository)
        {
            _grupoMuscularRepository = grupoMuscularRepository;
        }
        public async Task<GrupoMuscular> Crear(CrearActualizarGrupoMuscularDto grupoMuscularDto)
        {
            GrupoMuscular grupoMuscular = new GrupoMuscular()
            {
                Nombre = grupoMuscularDto.Nombre,
                Descripcion = grupoMuscularDto.Descripcion,
                ImagenGrupoMuscular = grupoMuscularDto.ImagenGrupoMuscular,
            };
            return await _grupoMuscularRepository.Crear(grupoMuscular);
        }

        public async Task<GrupoMuscular?> Eliminar(int id)
        {
            return await _grupoMuscularRepository.Eliminar(id);
        }

        public async Task<GrupoMuscular> ObtenerPorId(int id)
        {
            return await _grupoMuscularRepository.ObtenerPorId(id);
        }

        public async Task<List<GrupoMuscular>> ObtenerPorNombre(string nombre)
        {
            return await _grupoMuscularRepository.ObtenerPorNombre(nombre);
        }

        public async Task<GrupoMuscular> Actualizar(int id, CrearActualizarGrupoMuscularDto grupoMuscularDto)
        {
            GrupoMuscular grupoMuscular = new GrupoMuscular()
            {
                Nombre = grupoMuscularDto.Nombre,
                Descripcion = grupoMuscularDto.Descripcion,
                ImagenGrupoMuscular = grupoMuscularDto.ImagenGrupoMuscular,
            };
            return await _grupoMuscularRepository.Actualizar(id, grupoMuscular);
        }
        public async Task<List<GrupoMuscular>> ObtenerTodos()
        {
            return await _grupoMuscularRepository.ObtenerTodos();
        }
    }
}
