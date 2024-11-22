using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ProgressusWebApi.Migrations
{
    /// <inheritdoc />
    public partial class SolicitudDePago : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EstadoSolicitudes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Nombre = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EstadoSolicitudes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "TipoDePagos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Nombre = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TipoDePagos", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SolicitudDePagos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    IdentityUserId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    TipoDePagoId = table.Column<int>(type: "int", nullable: false),
                    MembresiaId = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SolicitudDePagos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SolicitudDePagos_Membresias_MembresiaId",
                        column: x => x.MembresiaId,
                        principalTable: "Membresias",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SolicitudDePagos_TipoDePagos_TipoDePagoId",
                        column: x => x.TipoDePagoId,
                        principalTable: "TipoDePagos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HistorialSolicitudDePagos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    EstadoSolicitudId = table.Column<int>(type: "int", nullable: false),
                    SolicitudDePagoId = table.Column<int>(type: "int", nullable: false),
                    FechaCambioEstado = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HistorialSolicitudDePagos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HistorialSolicitudDePagos_EstadoSolicitudes_EstadoSolicitudId",
                        column: x => x.EstadoSolicitudId,
                        principalTable: "EstadoSolicitudes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_HistorialSolicitudDePagos_SolicitudDePagos_SolicitudDePagoId",
                        column: x => x.SolicitudDePagoId,
                        principalTable: "SolicitudDePagos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_HistorialSolicitudDePagos_EstadoSolicitudId",
                table: "HistorialSolicitudDePagos",
                column: "EstadoSolicitudId");

            migrationBuilder.CreateIndex(
                name: "IX_HistorialSolicitudDePagos_SolicitudDePagoId",
                table: "HistorialSolicitudDePagos",
                column: "SolicitudDePagoId");

            migrationBuilder.CreateIndex(
                name: "IX_SolicitudDePagos_MembresiaId",
                table: "SolicitudDePagos",
                column: "MembresiaId");

            migrationBuilder.CreateIndex(
                name: "IX_SolicitudDePagos_TipoDePagoId",
                table: "SolicitudDePagos",
                column: "TipoDePagoId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HistorialSolicitudDePagos");

            migrationBuilder.DropTable(
                name: "EstadoSolicitudes");

            migrationBuilder.DropTable(
                name: "SolicitudDePagos");

            migrationBuilder.DropTable(
                name: "TipoDePagos");
        }
    }
}
