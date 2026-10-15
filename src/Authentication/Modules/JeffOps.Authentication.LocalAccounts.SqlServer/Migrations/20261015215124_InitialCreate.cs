using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JeffOps.Authentication.LocalAccounts.SqlServer.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "local");

            migrationBuilder.CreateTable(
                name: "AccountTokens",
                schema: "local",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Purpose = table.Column<string>(type: "nvarchar(30)", maxLength: 30, nullable: false),
                    TokenHash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    UsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AccountTokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Credentials",
                schema: "local",
                columns: table => new
                {
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PasswordHash = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    PasswordChangedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    FailedAttempts = table.Column<int>(type: "int", nullable: false),
                    LockedUntil = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    ProtectedTotpSecret = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                    TotpEnabled = table.Column<bool>(type: "bit", nullable: false),
                    TotpLastStep = table.Column<long>(type: "bigint", nullable: true),
                    SecurityStamp = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Credentials", x => x.AccountId);
                });

            migrationBuilder.CreateTable(
                name: "Passkeys",
                schema: "local",
                columns: table => new
                {
                    CredentialId = table.Column<byte[]>(type: "varbinary(1023)", maxLength: 1023, nullable: false),
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PublicKey = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: false),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    Transports = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    IsUserVerified = table.Column<bool>(type: "bit", nullable: false),
                    IsBackupEligible = table.Column<bool>(type: "bit", nullable: false),
                    IsBackedUp = table.Column<bool>(type: "bit", nullable: false),
                    AttestationObject = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    ClientDataJson = table.Column<byte[]>(type: "varbinary(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Passkeys", x => x.CredentialId);
                    table.ForeignKey(
                        name: "FK_Passkeys_Credentials_AccountId",
                        column: x => x.AccountId,
                        principalSchema: "local",
                        principalTable: "Credentials",
                        principalColumn: "AccountId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RecoveryCodes",
                schema: "local",
                columns: table => new
                {
                    AccountId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Hash = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RecoveryCodes", x => new { x.AccountId, x.Hash });
                    table.ForeignKey(
                        name: "FK_RecoveryCodes_Credentials_AccountId",
                        column: x => x.AccountId,
                        principalSchema: "local",
                        principalTable: "Credentials",
                        principalColumn: "AccountId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AccountTokens_AccountId_Purpose",
                schema: "local",
                table: "AccountTokens",
                columns: new[] { "AccountId", "Purpose" });

            migrationBuilder.CreateIndex(
                name: "IX_AccountTokens_TokenHash",
                schema: "local",
                table: "AccountTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Passkeys_AccountId",
                schema: "local",
                table: "Passkeys",
                column: "AccountId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AccountTokens",
                schema: "local");

            migrationBuilder.DropTable(
                name: "Passkeys",
                schema: "local");

            migrationBuilder.DropTable(
                name: "RecoveryCodes",
                schema: "local");

            migrationBuilder.DropTable(
                name: "Credentials",
                schema: "local");
        }
    }
}
