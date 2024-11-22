 using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Models.EjercicioModels;

namespace ProgressusWebApi.Services.EjercicioServices.Interfaces
{
    public interface IMusculoDeEjercicioService
    {
        Task<IActionResult> ActualizarMusculosDeEjercicio(AgregarQuitarMusculoAEjercicioDto agregarQuitarMusculoAEjercicioDto);

    }
}
