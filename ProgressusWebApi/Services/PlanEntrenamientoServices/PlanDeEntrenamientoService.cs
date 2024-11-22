using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Dtos.EjercicioDtos.EjercicioDto;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamiento;
using ProgressusWebApi.Dtos.PlanDeEntrenamientoDtos.PlanDeEntrenamientoDto;
using ProgressusWebApi.Model;
using ProgressusWebApi.Models.EjercicioModels;
using ProgressusWebApi.Models.PlanEntrenamientoModels;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Repositories.Interfaces;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;

namespace ProgressusWebApi.Services.PlanEntrenamientoServices
{
    public class PlanDeEntrenamientoService : IPlanDeEntrenamientoService
    {
        private readonly IPlanDeEntrenamientoRepository _planEntrenamientoRepository;
        private readonly IDiaDePlanRepository _diaDePlanRepository;
        private readonly IEjercicioEnDiaDelPlanRepository _ejercicioDePlanRepository;
        private readonly IEjercicioRepository _ejercicioRepository;
        public PlanDeEntrenamientoService(IPlanDeEntrenamientoRepository planEntrenamientoRepository, IDiaDePlanRepository diaDePlanRepository, IEjercicioEnDiaDelPlanRepository ejercicioDePlanRepository, IEjercicioRepository ejercicioRepository)
        {
            _planEntrenamientoRepository = planEntrenamientoRepository;
            _diaDePlanRepository = diaDePlanRepository;
            _ejercicioDePlanRepository = ejercicioDePlanRepository;
            _ejercicioRepository = ejercicioRepository;
        }
        public async Task<PlanDeEntrenamiento> Crear(CrearPlanDeEntrenamientoDto planDto)
        {
            PlanDeEntrenamiento plan = new PlanDeEntrenamiento()
            {
                Nombre = planDto.Nombre,
                Descripcion = planDto.Descripcion,
                DiasPorSemana = planDto.DiasPorSemana,
                ObjetivoDelPlanId = planDto.ObjetivoDelPlanId,
                DueñoDePlanId = planDto.DueñoId,
            };

            PlanDeEntrenamiento planCreado = await _planEntrenamientoRepository.Crear(plan);

            for (int i = 0; i < plan.DiasPorSemana; i++)
            {
                DiaDePlan diaDePlan = new DiaDePlan()
                {
                    PlanDeEntrenamientoId = plan.Id,
                    NumeroDeDia = i + 1
                };
                await _diaDePlanRepository.Crear(diaDePlan); 
            }
            return planCreado;
        }
        public async Task<PlanDeEntrenamiento> Actualizar(int id, ActualizarPlanDeEntrenamientoDto planActualizadoDto)
        {
            var plan = await _planEntrenamientoRepository.ObtenerPorId(id);

            if (plan == null) throw new Exception("Plan de entrenamiento no encontrado.");

            plan.Nombre = planActualizadoDto.Nombre;
            plan.Descripcion = planActualizadoDto.Descripcion;
            plan.ObjetivoDelPlanId = planActualizadoDto.ObjetivoDelPlanId;
        
            return await _planEntrenamientoRepository.Actualizar(id, plan);
        }

        public async Task<PlanDeEntrenamiento?> ActualizarEjerciciosDelPlan(int planId, AgregarQuitarEjerciciosAPlanDto ejerciciosEnPlanDto)
        {
            var plan = await _planEntrenamientoRepository.ObtenerPorId(planId);

            if (plan == null) throw new Exception("Plan de entrenamiento no encontrado.");

            _ejercicioDePlanRepository.QuitarEjerciciosDelPlan(planId);

            foreach (var ejercicio in ejerciciosEnPlanDto.Ejercicios)
            {
                DiaDePlan diaDePlan = await _diaDePlanRepository.ObtenerDiaDePlan(planId, ejercicio.NumeroDiaDelPlan);
                EjercicioEnDiaDelPlan ejercicioEnDiaDelPlan = new EjercicioEnDiaDelPlan()
                {
                    EjercicioId = ejercicio.EjercicioId,
                    DiaDePlanId = diaDePlan.Id,
                    OrdenDeEjercicio = ejercicio.OrdenDelEjercicio,
                    Series = ejercicio.Series,
                    Repeticiones = ejercicio.Repeticiones,
                    DiaDePlan = diaDePlan
                };
                await _ejercicioDePlanRepository.AgregarEjercicioADiaDelPlan(ejercicioEnDiaDelPlan);
            }

            return plan;
        }

        public async Task<bool> Eliminar(int id)
        {
            return await _planEntrenamientoRepository.Eliminar(id);
        }


        public async Task<PlanDeEntrenamiento?> ConvertirEnPlantilla(int id)
        {
            var plan = await _planEntrenamientoRepository.ObtenerPorId(id);

            if (plan == null) throw new Exception("Plan de entrenamiento no encontrado.");

            plan.EsPlantilla = true;

            return await _planEntrenamientoRepository.Actualizar(id, plan);
        }

        public async Task<PlanDeEntrenamiento?> QuitarConvertirEnPlantilla(int id)
        {
            var plan = await _planEntrenamientoRepository.ObtenerPorId(id);

            if (plan == null) throw new Exception("Plan de entrenamiento no encontrado.");

            plan.EsPlantilla = false;

            return await _planEntrenamientoRepository.Actualizar(id, plan);
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPorNombre(string nombre)
        {
            return await _planEntrenamientoRepository.ObtenerPorNombre(nombre);
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPorObjetivo(int objetivoDelPlanId)
        {
            return await _planEntrenamientoRepository.ObtenerPorObjetivo(objetivoDelPlanId);
        }
        public async Task<List<PlanDeEntrenamiento>> ObtenerPlantillasDePlanes()
        {
            return await _planEntrenamientoRepository.ObtenerPlantillasDePlanes();
        }

        public async Task<IActionResult> ObtenerPorId(int id)
        {
            var plan = _planEntrenamientoRepository.ObtenerPorIdSimplificado(id).Result;
            return new OkObjectResult(plan);
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerPlanesDelUsuario(string identityUser)
        {
            var planes = await _planEntrenamientoRepository.ObtenerPlanesDelUsuario(identityUser);
            return planes;
        }

        public async Task<List<PlanDeEntrenamiento>> ObtenerTodosLosPlanes()
        {
            var planes = await _planEntrenamientoRepository.ObtenerTodosLosPlanes();
            return planes;
        }
    }
}
