using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class EndedSessions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EndedSessions",
                schema: "auth",
                columns: table => new
                {
                    SessionId = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    EndedAtUnixMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EndedSessions", x => x.SessionId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EndedSessions_EndedAtUnixMs",
                schema: "auth",
                table: "EndedSessions",
                column: "EndedAtUnixMs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EndedSessions",
                schema: "auth");
        }
    }
}
