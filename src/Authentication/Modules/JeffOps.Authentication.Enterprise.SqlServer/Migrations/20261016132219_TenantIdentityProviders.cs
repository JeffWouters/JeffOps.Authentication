using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Enterprise.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class TenantIdentityProviders : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "CustomProvidersAllowed",
                schema: "enterprise",
                table: "SsoPolicies",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "TenantIdentityProviders",
                schema: "enterprise",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    EntityId = table.Column<string>(type: "nvarchar(512)", maxLength: 512, nullable: false),
                    MetadataUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    SingleSignOnUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    SingleLogoutUrl = table.Column<string>(type: "nvarchar(2048)", maxLength: 2048, nullable: true),
                    SigningCertificates = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    MultiFactorAuthnContexts = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uniqueidentifier", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TenantIdentityProviders", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TenantIdentityProviders_TenantId",
                schema: "enterprise",
                table: "TenantIdentityProviders",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TenantIdentityProviders",
                schema: "enterprise");

            migrationBuilder.DropColumn(
                name: "CustomProvidersAllowed",
                schema: "enterprise",
                table: "SsoPolicies");
        }
    }
}
