using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.Persistence.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class AccountActivity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "DeletionWarnedAtUnixMs",
                schema: "auth",
                table: "Accounts",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "LastActiveAtUnixMs",
                schema: "auth",
                table: "Accounts",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            // Existing accounts count as active now: none is found inactive (or warned) for the time before this was recorded.
            migrationBuilder.Sql("UPDATE [auth].[Accounts] SET [LastActiveAtUnixMs] = DATEDIFF_BIG(millisecond, '19700101', SYSUTCDATETIME());");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_DeletionWarnedAtUnixMs",
                schema: "auth",
                table: "Accounts",
                column: "DeletionWarnedAtUnixMs");

            migrationBuilder.CreateIndex(
                name: "IX_Accounts_LastActiveAtUnixMs",
                schema: "auth",
                table: "Accounts",
                column: "LastActiveAtUnixMs");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Accounts_DeletionWarnedAtUnixMs",
                schema: "auth",
                table: "Accounts");

            migrationBuilder.DropIndex(
                name: "IX_Accounts_LastActiveAtUnixMs",
                schema: "auth",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "DeletionWarnedAtUnixMs",
                schema: "auth",
                table: "Accounts");

            migrationBuilder.DropColumn(
                name: "LastActiveAtUnixMs",
                schema: "auth",
                table: "Accounts");
        }
    }
}
