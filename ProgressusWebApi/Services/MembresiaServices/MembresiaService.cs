using ProgressusWebApi.Dtos.MembresiaDtos;
using ProgressusWebApi.Models.CobroModels;
using ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces;
using ProgressusWebApi.Services.MembresiaServices.Interfaces;

namespace ProgressusWebApi.Services.MembresiaServices
{
    public class MembresiaService : IMembresiaService
    {
        private readonly IMembresiaRepository _repository;

        public MembresiaService(IMembresiaRepository repository)
        {
            _repository = repository;
        }

        public async Task<List<Membresia>> GetAll()
        {
            var membresias = await _repository.GetAll();
            return membresias.Select(m => new Membresia
            {
                Id = m.Id,
                Nombre = m.Nombre,
                MesesDuracion = m.MesesDuracion,
                Precio = m.Precio,
                Descripcion = m.Descripcion
            }).ToList();
        }

        public async Task<CrearMembresiaDto> GetById(int id)
        {
            var membresia = await _repository.GetById(id);
            return new CrearMembresiaDto
            {
                Nombre = membresia.Nombre,
                MesesDuracion = membresia.MesesDuracion,
                Precio = membresia.Precio,
                Descripcion = membresia.Descripcion
            };
        }

        public async Task Add(CrearMembresiaDto dto)
        {
            var membresia = new Membresia
            {
                Nombre = dto.Nombre,
                MesesDuracion = dto.MesesDuracion,
                Precio = dto.Precio,
                Descripcion = dto.Descripcion
            };
            await _repository.Add(membresia);
        }

        public async Task Update(CrearMembresiaDto dto, int id)
        {
            var membresia = await _repository.GetById(id);
            if (membresia != null)
            {
                membresia.Nombre = dto.Nombre;
                membresia.MesesDuracion = dto.MesesDuracion;
                membresia.Precio = dto.Precio;
                membresia.Descripcion = dto.Descripcion;
                await _repository.Update(membresia);
            }
        }

        public async Task Delete(int id)
        {
            await _repository.Delete(id);
        }
    }
}
