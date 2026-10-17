using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ExternalSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ExternalSessions",
                schema: "auth",
                columns: table => new
                {
                    SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    Provider = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ProviderSessionHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: true),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ExpiresAtUnixMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalSessions", x => x.SessionId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ExternalSessions_ExpiresAtUnixMs",
                schema: "auth",
                table: "ExternalSessions",
                column: "ExpiresAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_ExternalSessions_Provider_AccountId",
                schema: "auth",
                table: "ExternalSessions",
                columns: new[] { "Provider", "AccountId" });

            migrationBuilder.CreateIndex(
                name: "IX_ExternalSessions_Provider_ProviderSessionHash",
                schema: "auth",
                table: "ExternalSessions",
                columns: new[] { "Provider", "ProviderSessionHash" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ExternalSessions",
                schema: "auth");
        }
    }
}
