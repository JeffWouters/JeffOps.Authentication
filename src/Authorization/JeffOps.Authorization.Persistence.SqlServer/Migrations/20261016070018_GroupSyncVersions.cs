using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authorization.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class GroupSyncVersions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "GroupSyncStates",
                schema: "authz",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    GroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_GroupSyncStates", x => new { x.TenantId, x.GroupId });
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "GroupSyncStates",
                schema: "authz");
        }
    }
}
