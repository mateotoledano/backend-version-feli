namespace ProgressusWebApi.Dtos.MembresiaDtos
{
    public class VigenciaDeMembresiaDto
    {
        public DateTime VigenteDesde { get; set; }
        public DateTime VigenteHasta { get; set; }
        public bool EsVigente {  get; set; }
    }
}
