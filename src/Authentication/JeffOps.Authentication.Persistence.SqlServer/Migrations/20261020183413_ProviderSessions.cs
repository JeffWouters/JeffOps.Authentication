using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ProviderSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProviderSessions",
                schema: "auth",
                columns: table => new
                {
                    SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Provider = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ProtectedRefreshToken = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CheckedAtUnixMs = table.Column<long>(type: "bigint", nullable: false),
                    ExpiresAtUnixMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProviderSessions", x => x.SessionId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ProviderSessions_ExpiresAtUnixMs",
                schema: "auth",
                table: "ProviderSessions",
                column: "ExpiresAtUnixMs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProviderSessions",
                schema: "auth");
        }
    }
}
