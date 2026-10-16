using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ReplayEntries : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ReplayEntries",
                schema: "auth",
                columns: table => new
                {
                    Key = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ExpiresAtUnixMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ReplayEntries", x => x.Key);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ReplayEntries_ExpiresAtUnixMs",
                schema: "auth",
                table: "ReplayEntries",
                column: "ExpiresAtUnixMs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ReplayEntries",
                schema: "auth");
        }
    }
}
