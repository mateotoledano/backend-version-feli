using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;

namespace ProgressusWebApi.Services.EjercicioServices
{
    public class MusculoDeEjercicioService : IMusculoDeEjercicioService
    {
        private readonly IMusculoDeEjercicioRepository _musculoDeEjercicioRepository;
        private readonly IEjercicioRepository _ejercicioRepository;
        public MusculoDeEjercicioService(IMusculoDeEjercicioRepository musculoDeEjercicioRepository, IEjercicioRepository ejercicioRepository)
        {
            _musculoDeEjercicioRepository = musculoDeEjercicioRepository;
            _ejercicioRepository = ejercicioRepository;
        }

        public async Task<IActionResult> ActualizarMusculosDeEjercicio(AgregarQuitarMusculoAEjercicioDto agregarQuitarMusculoAEjercicioDto)
        {
            int ejercicioId = agregarQuitarMusculoAEjercicioDto.EjercicioId;
            List<int> musculosActualesIds = await _musculoDeEjercicioRepository.ObtenerIdsDeMusculosDeEjercicio(ejercicioId);
            List<int> musculosActualizadosIds = agregarQuitarMusculoAEjercicioDto.MusculosIds;

            List<int> musculosParaAgregar = musculosActualizadosIds.Except(musculosActualesIds).ToList();
            List<int> musculosParaEliminar = musculosActualesIds.Except(musculosActualizadosIds).ToList();

            foreach (var musculoId in musculosParaAgregar)
            {
                MusculoDeEjercicio musculoAgregado = new MusculoDeEjercicio()
                {
                    MusculoId = musculoId,
                    EjercicioId = ejercicioId
                };
                await _musculoDeEjercicioRepository.AgregarMusculoAEjercicio(musculoAgregado);
            }

            foreach (var musculoId in musculosParaEliminar)
            {
                await _musculoDeEjercicioRepository.QuitarMusculoAEjercicio(ejercicioId, musculoId);
            }

            var musculosActualizados = await _musculoDeEjercicioRepository.ObtenerIdsDeMusculosDeEjercicio(agregarQuitarMusculoAEjercicioDto.EjercicioId);
            return new OkObjectResult(musculosActualizados);
        }
    }
}
