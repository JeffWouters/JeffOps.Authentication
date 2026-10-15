using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Enterprise.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class Scim : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScimGroups",
                schema: "enterprise",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    DisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    ExternalId = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    Created = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastModified = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Version = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimGroups", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScimTokens",
                schema: "enterprise",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    RevokedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ScimUsers",
                schema: "enterprise",
                columns: table => new
                {
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAccount = table.Column<bool>(type: "bit", nullable: false),
                    UserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                    ExternalId = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                    GivenName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    FamilyName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    DisplayName = table.Column<string>(type: "nvarchar(300)", maxLength: 300, nullable: true),
                    Active = table.Column<bool>(type: "bit", nullable: false),
                    Created = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastModified = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    Version = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimUsers", x => new { x.TenantId, x.AccountId });
                });

            migrationBuilder.CreateTable(
                name: "ScimGroupMembers",
                schema: "enterprise",
                columns: table => new
                {
                    GroupId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScimGroupMembers", x => new { x.GroupId, x.AccountId });
                    table.ForeignKey(
                        name: "FK_ScimGroupMembers_ScimGroups_GroupId",
                        column: x => x.GroupId,
                        principalSchema: "enterprise",
                        principalTable: "ScimGroups",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroupMembers_AccountId",
                schema: "enterprise",
                table: "ScimGroupMembers",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimGroups_TenantId_DisplayName",
                schema: "enterprise",
                table: "ScimGroups",
                columns: new[] { "TenantId", "DisplayName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimTokens_TenantId",
                schema: "enterprise",
                table: "ScimTokens",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ScimTokens_TokenHash",
                schema: "enterprise",
                table: "ScimTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScimUsers_TenantId_ExternalId",
                schema: "enterprise",
                table: "ScimUsers",
                columns: new[] { "TenantId", "ExternalId" });

            migrationBuilder.CreateIndex(
                name: "IX_ScimUsers_TenantId_UserName",
                schema: "enterprise",
                table: "ScimUsers",
                columns: new[] { "TenantId", "UserName" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScimGroupMembers",
                schema: "enterprise");

            migrationBuilder.DropTable(
                name: "ScimTokens",
                schema: "enterprise");

            migrationBuilder.DropTable(
                name: "ScimUsers",
                schema: "enterprise");

            migrationBuilder.DropTable(
                name: "ScimGroups",
                schema: "enterprise");
        }
    }
}
