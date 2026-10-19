using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Enterprise.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class TenantDomainProof : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ProofMissingSince",
                schema: "enterprise",
                table: "TenantDomains",
                type: "datetimeoffset",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_TenantDomains_Domain_Verified",
                schema: "enterprise",
                table: "TenantDomains",
                column: "Domain",
                unique: true,
                filter: "[Status] = 'Verified'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TenantDomains_Domain_Verified",
                schema: "enterprise",
                table: "TenantDomains");

            migrationBuilder.DropColumn(
                name: "ProofMissingSince",
                schema: "enterprise",
                table: "TenantDomains");
        }
    }
}
