using ProgressusWebApi.Dtos.EjercicioDtos.MusculoDto;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Services.EjercicioServices
{
    public class MusculoService : IMusculoService
    {
        public readonly IMusculoRepository _musculoRepository;
        public MusculoService(IMusculoRepository musculoRepository)
        {
            _musculoRepository = musculoRepository;
        }

        public async Task<Musculo> Crear(CrearActualizarMusculoDto musculoDto)
        {
            Musculo musculoCreado = new Musculo()
            {
                Nombre = musculoDto.Nombre,
                Descripcion = musculoDto.Descripcion,
                ImagenMusculo = musculoDto.ImagenMusculo,
                GrupoMuscularId = musculoDto.GrupoMuscularId
            };
            return await _musculoRepository.Crear(musculoCreado);
        }

        public async Task<Musculo> Actualizar(int id, CrearActualizarMusculoDto musculoDto)
        {
            Musculo musculoActualizado = new Musculo()
            {
                Nombre = musculoDto.Nombre,
                Descripcion = musculoDto.Descripcion,
                ImagenMusculo = musculoDto.ImagenMusculo,
                GrupoMuscularId = musculoDto.GrupoMuscularId
            };
            return await _musculoRepository.Actualizar(id, musculoActualizado);
        }

        public async Task<Musculo?> Eliminar(int id)
        {
            return await _musculoRepository.Eliminar(id);
        }

        public async Task<List<Musculo>> ObtenerPorGrupoMuscular(int grupoMuscularId)
        {
            return await _musculoRepository.ObtenerPorGrupoMuscular(grupoMuscularId);
        }

        public async Task<Musculo?> ObtenerPorId(int id)
        {
            return await _musculoRepository.ObtenerPorId(id);
        }

        public async Task<List<Musculo>>? ObtenerPorNombre(string nombre)
        {
            return await _musculoRepository.ObtenerPorNombre(nombre);
        }

        public async Task<List<Musculo>> ObtenerTodos()
        {
            return await _musculoRepository.ObtenerTodos();
        }
    }
}
