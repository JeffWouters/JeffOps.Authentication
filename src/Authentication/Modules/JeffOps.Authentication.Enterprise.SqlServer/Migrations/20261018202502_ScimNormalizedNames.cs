using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Enterprise.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class ScimNormalizedNames : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ScimUsers_TenantId_UserName",
                schema: "enterprise",
                table: "ScimUsers");

            migrationBuilder.DropIndex(
                name: "IX_ScimGroups_TenantId_DisplayName",
                schema: "enterprise",
                table: "ScimGroups");

            migrationBuilder.AddColumn<string>(
                name: "NormalizedUserName",
                schema: "enterprise",
                table: "ScimUsers",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "NormalizedDisplayName",
                schema: "enterprise",
                table: "ScimGroups",
                type: "nvarchar(256)",
                maxLength: 256,
                nullable: false,
                defaultValue: "");

            // Existing rows: the names as the domain now stores them (trimmed already; lower-cased here).
            migrationBuilder.Sql("UPDATE [enterprise].[ScimUsers] SET [NormalizedUserName] = LOWER([UserName]);");
            migrationBuilder.Sql("UPDATE [enterprise].[ScimGroups] SET [NormalizedDisplayName] = LOWER([DisplayName]);");

            migrationBuilder.CreateIndex(
                name: "IX_ScimUsers_TenantId_NormalizedUserName",
                schema: "enterprise",
                table: "ScimUsers",
                columns: new[] { "TenantId", "NormalizedUserName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroups_TenantId_NormalizedDisplayName",
                schema: "enterprise",
                table: "ScimGroups",
                columns: new[] { "TenantId", "NormalizedDisplayName" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ScimUsers_TenantId_NormalizedUserName",
                schema: "enterprise",
                table: "ScimUsers");

            migrationBuilder.DropIndex(
                name: "IX_ScimGroups_TenantId_NormalizedDisplayName",
                schema: "enterprise",
                table: "ScimGroups");

            migrationBuilder.DropColumn(
                name: "NormalizedUserName",
                schema: "enterprise",
                table: "ScimUsers");

            migrationBuilder.DropColumn(
                name: "NormalizedDisplayName",
                schema: "enterprise",
                table: "ScimGroups");

            migrationBuilder.CreateIndex(
                name: "IX_ScimUsers_TenantId_UserName",
                schema: "enterprise",
                table: "ScimUsers",
                columns: new[] { "TenantId", "UserName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroups_TenantId_DisplayName",
                schema: "enterprise",
                table: "ScimGroups",
                columns: new[] { "TenantId", "DisplayName" },
                unique: true);
        }
    }
}
