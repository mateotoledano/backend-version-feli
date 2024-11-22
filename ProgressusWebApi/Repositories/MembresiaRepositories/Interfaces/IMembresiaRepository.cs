using ProgressusWebApi.Models.CobroModels;

namespace ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces
{
    public interface IMembresiaRepository
    {
        Task<List<Membresia>> GetAll();
        Task<Membresia> GetById(int id);
        Task Add(Membresia membresia);
        Task Update(Membresia membresia);
        Task Delete(int id);
    }
}