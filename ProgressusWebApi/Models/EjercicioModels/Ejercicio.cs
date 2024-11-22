using System.ComponentModel.DataAnnotations;

namespace ProgressusWebApi.Models.EjercicioModels
{
    public class Ejercicio
    {
        [Key]
        public int Id { get; set; }
        public string Nombre { get; set; }
        public string Descripcion { get; set; }
        public string? ImagenMaquina { get; set; }
        public string? VideoEjercicio { get; set; }
        public List<MusculoDeEjercicio>? MusculosDeEjercicio { get; set; } = new List<MusculoDeEjercicio>();
    }
}
