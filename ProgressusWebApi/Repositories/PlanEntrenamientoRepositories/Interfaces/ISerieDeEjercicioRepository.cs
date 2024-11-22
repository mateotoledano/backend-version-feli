using ProgressusWebApi.Model;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces
{
    public interface ISerieDeEjercicioRepository
    {
        Task<SerieDeEjercicio> Crear(SerieDeEjercicio serieDeEjercicio);
        Task<SerieDeEjercicio> Eliminar(int serieDeEjercicioId);
        Task<List<SerieDeEjercicio>> ObtenerSeriesPorFecha(DateTime desde, DateTime hasta, int socioId);
        Task<List<SerieDeEjercicio>> ObtenerSeriesDeLaSemana(DateTime semana, int socioId);
    }
}
