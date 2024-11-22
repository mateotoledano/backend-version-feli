using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamiento;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamientoDto;
using ProgressusWebApi.Model;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces
{
    public interface IPlanDeEntrenamientoService
    {
        Task<PlanDeEntrenamiento> Crear(CrearPlanDeEntrenamientoDto planCreadoDto);
        Task<PlanDeEntrenamiento> Actualizar(int id, ActualizarPlanDeEntrenamientoDto planActualizadoDto);
        Task<bool> Eliminar(int id);
        Task<List<PlanDeEntrenamiento>> ObtenerPlantillasDePlanes();
        Task<PlanDeEntrenamiento> ActualizarEjerciciosDelPlan(int id, AgregarQuitarEjerciciosAPlanDto ejerciciosActualizados);
        Task<PlanDeEntrenamiento> ConvertirEnPlantilla(int id);
        Task<PlanDeEntrenamiento> QuitarConvertirEnPlantilla(int id);
        Task<IActionResult> ObtenerPorId(int id);
        Task<List<PlanDeEntrenamiento>> ObtenerPorObjetivo(int objetivoDelPlanId);
        Task<List<PlanDeEntrenamiento>> ObtenerPorNombre(string nombre);
        Task<List<PlanDeEntrenamiento>> ObtenerPlanesDelUsuario(string identityUser);
        Task<List<PlanDeEntrenamiento>> ObtenerTodosLosPlanes();
    }
}
