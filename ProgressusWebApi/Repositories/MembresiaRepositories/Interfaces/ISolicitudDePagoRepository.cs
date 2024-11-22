using Microsoft.AspNetCore.Mvc;
using ProgressusWebApi.Models.MembresiaModels;

namespace ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces
{
    public interface ISolicitudDePagoRepository
    {
        // Métodos para SolicitudDePago
        Task<SolicitudDePago> CrearSolicitudDePagoAsync(SolicitudDePago solicitud);
        Task<SolicitudDePago> ModificarSolicitudDePagoAsync(SolicitudDePago solicitud);
        Task<SolicitudDePago> ObtenerSolicitudDePagoPorIdAsync(int solicitudId);

        // Métodos para TipoDePago
        Task<TipoDePago> ObtenerTipoDePagoPorNombreAsync(string nombre);
        Task<TipoDePago> ObtenerTipoDePagoPorIdAsync(int id);

        // Métodos para EstadoSolicitud
        Task<EstadoSolicitud> ObtenerEstadoSolicitudPorNombreAsync(string nombre);
        Task<EstadoSolicitud> ObtenerEstadoSolicitudPorIdAsync(int id);

        // Métodos para HistorialSolicitudDePago
        Task<HistorialSolicitudDePago> CrearHistorialSolicitudDePagoAsync(HistorialSolicitudDePago historial);
        Task<IEnumerable<HistorialSolicitudDePago>> ObtenerTodoElHistorialDeUnaSolicitudAsync(int solicitudId);
        Task<HistorialSolicitudDePago> ObtenerUltimoHistorialDeUnaSolicitudAsync(int solicitudId);
        Task<IActionResult> ObtenerSolicitudDePagoDeSocio(string identityUserId);
        Task<IActionResult> ObtenerTiposDePagos();

        Task<IActionResult> ConsultarVigenciaDeMembresia(string id);
    }
}
