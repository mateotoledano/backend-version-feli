using ProgressusWebApi.Dtos.MembresiaDtos;
using ProgressusWebApi.Models.CobroModels;

namespace ProgressusWebApi.Services.MembresiaServices.Interfaces
{
    public interface IMembresiaService
    {
        Task<List<Membresia>> GetAll();
        Task<CrearMembresiaDto> GetById(int id);
        Task Add(CrearMembresiaDto dto);
        Task Update(CrearMembresiaDto dto, int id);
        Task Delete(int id);
    }
}
