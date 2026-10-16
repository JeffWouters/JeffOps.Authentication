using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Enterprise.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ScimDisabledAccount : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "DisabledAccount",
                schema: "enterprise",
                table: "ScimUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DisabledAccount",
                schema: "enterprise",
                table: "ScimUsers");
        }
    }
}
