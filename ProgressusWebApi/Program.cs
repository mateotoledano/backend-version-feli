using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using ProgressusWebApi.DataContext;
using ProgressusWebApi.Services.AuthServices;
using ProgressusWebApi.Services.AuthServices.Interfaces;
using ProgressusWebApi.Services.EmailServices;
using ProgressusWebApi.Services.EmailServices.Interfaces;
using ProgressusWebApi.Utilities;
using Swashbuckle.AspNetCore.Filters;
using WebApiMercadoPago.Repositories.Interface;
using WebApiMercadoPago.Repositories;
using WebApiMercadoPago.Services.Interface;
using WebApiMercadoPago.Services;
using MercadoPago.Config;
using ProgressusWebApi.Repositories.EjercicioRepositories;
using ProgressusWebApi.Repositories.EjercicioRepositories.Interfaces;
using ProgressusWebApi.Services.EjercicioServices.Interfaces;
using ProgressusWebApi.Services.EjercicioServices;
using ProgressusWebApi.Repositories.Interfaces;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories;
using ProgressusWebApi.Services.PlanEntrenamientoServices.Interfaces;
using ProgressusWebApi.Services.PlanEntrenamientoServices;
using ProgressusWebApi.Repositories.PlanEntrenamientoRepositories.Interfaces;
using ProgressusWebApi.Repositories.MembresiaRepositories.Interfaces;
using ProgressusWebApi.Repositories.MembresiaRepositories;
using ProgressusWebApi.Services.MembresiaServices.Interfaces;
using ProgressusWebApi.Services.MembresiaServices;

var builder = WebApplication.CreateBuilder(args);

// Agregar los servicios al contenedor
// Configuración para ignorar referencias cíclicas en la serialización JSON
builder.Services.AddControllers().AddNewtonsoftJson(options =>
{
    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
});

// Inyección de repositorios y servicios
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEjercicioRepository, EjercicioRepository>();
builder.Services.AddScoped<IEjercicioService, EjercicioService>();
builder.Services.AddScoped<IMusculoDeEjercicioRepository, MusculoDeEjercicioRepository>();
builder.Services.AddScoped<IMusculoDeEjercicioService, MusculoDeEjercicioService>();
builder.Services.AddScoped<IMusculoRepository, MusculoRepository>();
builder.Services.AddScoped<IMusculoService, MusculoService>();
builder.Services.AddScoped<IGrupoMuscularRepository, GrupoMuscularRepository>();
builder.Services.AddScoped<IGrupoMuscularService, GrupoMuscularService>();
builder.Services.AddScoped<IPlanDeEntrenamientoRepository, PlanDeEntrenamientoRepository>();
builder.Services.AddScoped<IPlanDeEntrenamientoService, PlanDeEntrenamientoService>();
builder.Services.AddScoped<IDiaDePlanRepository, DiaDePlanRepository>();
builder.Services.AddScoped<IEjercicioEnDiaDelPlanRepository, EjercicioEnDiaDelPlanRepository>();
builder.Services.AddScoped<IObjetivoDelPlanRepository, ObjetivoDelPlanRepository>();
builder.Services.AddScoped<ISerieDeEjercicioRepository, SerieDeEjercicioRepository>();
builder.Services.AddScoped<IObjetivoDelPlanService, ObjetivoDelPlanService>();
builder.Services.AddScoped<IAsignacionDePlanRepository, AsignacionDePlanRepository>();
builder.Services.AddScoped<IAsignacionDePlanService, AsignacionDePlanService>();

builder.Services.AddScoped<IMembresiaRepository, MembresiaRepository>();
builder.Services.AddScoped<IMembresiaService, MembresiaService>();
builder.Services.AddScoped<ISolicitudDePagoRepository, SolicitudDePagoRepository>();
builder.Services.AddScoped<ISolicitudDePagoService, SolicitudDePagoService>();
builder.Services.AddMemoryCache();

// Permitir documentación y acceso de los endpoints con swagger
// Configuración con oauth2 para requerir autorización en la ejecución de los endpoints 
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

// Conexión a la base de datos
builder.Services.AddDbContext<ProgressusDataContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Autenticación y autorización con Identity (endpoints)
builder.Services.AddAuthorization();
builder.Services.AddIdentityApiEndpoints<IdentityUser>(options =>
{
    options.SignIn.RequireConfirmedEmail = true;
})
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ProgressusDataContext>();

// Configuración para envio de emails con servidor SMTP de Gmail
builder.Services.AddTransient<IEmailSenderService, EmailSenderService>();
builder.Services.Configure<GmailSetter>(builder.Configuration.GetSection("GmailSettings"));

// Configuración para sistema de cobros con MercadoPago
builder.Services.AddScoped<IMercadoPagoRepository, MercadoPagoRepository>();
builder.Services.AddScoped<IMercadoPagoService, MercadoPagoService>(); MercadoPagoConfig.AccessToken = "APP_USR-2278733141716614-062815-583c9779901a7bbf32c8e8a73971e44c-1878150528";

// Construir la aplicación con todas las configuraciones y servicios definidos en el objeto builder
var app = builder.Build();

// Configuración de la pipeline del HTTP request
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Mapear endpoints de authorization y authentication
app.MapIdentityApi<IdentityUser>();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.Run();
