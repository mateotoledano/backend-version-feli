using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Dtos.MembresiaDtos;
using ProgressusWebApi.Models.MembresiaModels;
using ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces;

namespace ProgressusWebApi.Repositories.MembresiaRepositories
{
    public class SolicitudDePagoRepository : ISolicitudDePagoRepository
    {
        private readonly ProgressusDataContext _context;
        private readonly IMembresiaRepository _membresiaRepository;

        public SolicitudDePagoRepository(ProgressusDataContext context, IMembresiaRepository membresiaRepository)
        {
            _context = context;
            _membresiaRepository = membresiaRepository;
        }

        // Métodos para SolicitudDePago
        public async Task<SolicitudDePago> CrearSolicitudDePagoAsync(SolicitudDePago solicitud)
        {
            await _context.SolicitudDePagos.AddAsync(solicitud);
            await _context.SaveChangesAsync();
            return solicitud;
        }

        public async Task<SolicitudDePago> ModificarSolicitudDePagoAsync(SolicitudDePago solicitud)
        {
            _context.SolicitudDePagos.Update(solicitud);
            await _context.SaveChangesAsync();
            return solicitud;
        }

        public async Task<SolicitudDePago> ObtenerSolicitudDePagoPorIdAsync(int solicitudId)
        {
            return await _context.SolicitudDePagos
                .Include(s => s.TipoDePago)
                .Include(s => s.Membresia)
                .Include(s => s.HistorialSolicitudDePagos)
                .FirstOrDefaultAsync(s => s.Id == solicitudId);
        }

        // Métodos para TipoDePago
        public async Task<TipoDePago> ObtenerTipoDePagoPorNombreAsync(string nombre)
        {
            return await _context.TipoDePagos.FirstOrDefaultAsync(tp => tp.Nombre == nombre);
        }


        // Métodos para EstadoSolicitud
        public async Task<EstadoSolicitud> ObtenerEstadoSolicitudPorNombreAsync(string nombre)
        {
            return await _context.EstadoSolicitudes.FirstOrDefaultAsync(es => es.Nombre == nombre);
        }

        public async Task<EstadoSolicitud> ObtenerEstadoSolicitudPorIdAsync(int id)
        {
            return await _context.EstadoSolicitudes.FirstOrDefaultAsync(es => es.Id == id);
        }

        // Métodos para HistorialSolicitudDePago
        public async Task<HistorialSolicitudDePago> CrearHistorialSolicitudDePagoAsync(HistorialSolicitudDePago historial)
        {
            await _context.HistorialSolicitudDePagos.AddAsync(historial);
            await _context.SaveChangesAsync();
            return historial;
        }

        public async Task<IEnumerable<HistorialSolicitudDePago>> ObtenerTodoElHistorialDeUnaSolicitudAsync(int solicitudId)
        {
            return await _context.HistorialSolicitudDePagos
                .Where(h => h.SolicitudDePagoId == solicitudId)
                .OrderBy(h => h.FechaCambioEstado)
                .ToListAsync();
        }

        public async Task<HistorialSolicitudDePago> ObtenerUltimoHistorialDeUnaSolicitudAsync(int solicitudId)
        {
            HistorialSolicitudDePago historialSolicitudDePago = await _context.HistorialSolicitudDePagos
                .Where(h => h.SolicitudDePagoId == solicitudId)
                .OrderByDescending(h => h.FechaCambioEstado)
                .FirstOrDefaultAsync();
            return (historialSolicitudDePago);
        }

        public Task<TipoDePago> ObtenerTipoDePagoPorIdAsync(int id)
        {
            return  _context.TipoDePagos.FirstOrDefaultAsync(tp => tp.Id == id);
        }

        public async Task<IActionResult> ObtenerSolicitudDePagoDeSocio(string identityUserId)
        {
            var solicitud = await _context.SolicitudDePagos
                .Include(s => s.HistorialSolicitudDePagos) // Incluye el historial completo
                .ThenInclude(h => h.EstadoSolicitud)    // Incluye también el EstadoSolicitud de cada historial
                .OrderByDescending(h => h.FechaCreacion)
                .FirstOrDefaultAsync(tp => tp.IdentityUserId == identityUserId);
            solicitud.TipoDePago = this.ObtenerTipoDePagoPorIdAsync(solicitud.TipoDePagoId).Result;
            solicitud.Membresia =  _membresiaRepository.GetById(solicitud.MembresiaId).Result;
            return new OkObjectResult(solicitud);
        }

        public async Task<IActionResult> ObtenerTiposDePagos()
        {
            var tipos = await _context.TipoDePagos.ToListAsync();
            return new OkObjectResult(tipos);
        }

        public async Task<IActionResult> ConsultarVigenciaDeMembresia(string userId)
        {
            var solicitud = await _context.SolicitudDePagos
                .Where(s => s.IdentityUserId == userId.ToString())
                .Include(s => s.HistorialSolicitudDePagos) // Incluye el historial completo
                    .ThenInclude(h => h.EstadoSolicitud)    // Incluye también el EstadoSolicitud de cada historial
                .OrderByDescending(s => s.HistorialSolicitudDePagos
                    .Where(h => h.EstadoSolicitud.Nombre == "Confirmado")
                    .OrderByDescending(h => h.FechaCambioEstado)
                    .FirstOrDefault().FechaCambioEstado)
                .FirstOrDefaultAsync();

            // Verifica si no se encontró una solicitud con estado "Confirmado"
            if (solicitud == null)
            {
                return new NotFoundObjectResult("No se encontró ninguna solicitud confirmada para el usuario.");
            }

            var historial = await ObtenerUltimoHistorialDeUnaSolicitudAsync(solicitud.Id);
            solicitud.TipoDePago = this.ObtenerTipoDePagoPorIdAsync(solicitud.TipoDePagoId).Result;
            solicitud.Membresia = _membresiaRepository.GetById(solicitud.MembresiaId).Result;

            // Obtiene la fecha del último cambio de estado "Confirmado" y la duración de la membresía
            var fechaConfirmacion = historial.FechaCambioEstado;

            var duracionMeses = solicitud.Membresia.MesesDuracion;

            // Calcula la fecha de vigencia sumando los meses de duración de la membresía
            var fechaVigencia = fechaConfirmacion.AddMonths(duracionMeses);

            VigenciaDeMembresiaDto vigenciaDto = new VigenciaDeMembresiaDto
            {
                VigenteDesde = fechaConfirmacion,
                VigenteHasta = fechaVigencia,
                EsVigente = fechaVigencia >= DateTime.Now
            };

            return new OkObjectResult(vigenciaDto);
        }
    }
}
