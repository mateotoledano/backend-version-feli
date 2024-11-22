using ProgressusWebApi.Model;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.PlanEntrenamientoRepositories
{
    public class SerieDeEjercicioRepository : ISerieDeEjercicioRepository
    {
        public Task<SerieDeEjercicio> Crear(SerieDeEjercicio serieDeEjercicio)
        {
            throw new NotImplementedException();
        }

        public Task<SerieDeEjercicio> Eliminar(int serieDeEjercicioId)
        {
            throw new NotImplementedException();
        }

        public Task<List<SerieDeEjercicio>> ObtenerSeriesDeLaSemana(DateTime semana, int socioId)
        {
            throw new NotImplementedException();
        }

        public Task<List<SerieDeEjercicio>> ObtenerSeriesPorFecha(DateTime desde, DateTime hasta, int socioId)
        {
            throw new NotImplementedException();
        }
    }
}
