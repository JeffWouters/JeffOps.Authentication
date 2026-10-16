using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Keys;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Infrastructure.Persistence;

/// <summary>
/// The token server's store: accounts, external logins, personal access tokens, token keys, and the OpenIddict entities
/// (applications, authorizations, scopes, tokens). Provider-neutral; the provider and migrations come from a persistence
/// package such as <c>JeffOps.Authentication.Persistence.SqlServer</c>.
/// </summary>
public sealed class AuthenticationDbContext(DbContextOptions<AuthenticationDbContext> options) : DbContext(options)
{
    /// <summary>The database schema that holds the token server's tables.</summary>
    public const string Schema = "auth";

    /// <summary>The platform's user accounts.</summary>
    public DbSet<Account> Accounts => Set<Account>();

    /// <summary>External logins (provider issuer and subject) linked to accounts.</summary>
    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();

    /// <summary>Personal access tokens, stored as hashes of their secrets.</summary>
    public DbSet<PersonalAccessToken> PersonalAccessTokens => Set<PersonalAccessToken>();

    /// <summary>Token signing and encryption keys, their private keys protected with Data Protection.</summary>
    public DbSet<StoredKey> StoredKeys => Set<StoredKey>();

    /// <summary>One-time values seen (DPoP proofs, SAML assertions), shared by every instance of the token server.</summary>
    public DbSet<Server.ReplayEntry> ReplayEntries => Set<Server.ReplayEntry>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.HasDefaultSchema(Schema);
        modelBuilder.UseOpenIddict();

        modelBuilder.Entity<Account>(account =>
        {
            account.ToTable("Accounts");
            account.HasKey(entity => entity.Id);
            account.Property(entity => entity.Id).ValueGeneratedNever();
            account.Property(entity => entity.Email).HasMaxLength(320).IsRequired();
            account.Property(entity => entity.DisplayName).HasMaxLength(200).IsRequired();
            account.Property(entity => entity.Status).HasConversion<string>().HasMaxLength(20);
            account.HasIndex(entity => entity.Email);
            account.Ignore(entity => entity.DomainEvents);
            account.Ignore(entity => entity.CanAuthenticate);
            account.HasMany(entity => entity.ExternalLogins)
                .WithOne()
                .HasForeignKey(login => login.AccountId)
                .OnDelete(DeleteBehavior.Cascade);
            account.Navigation(entity => entity.ExternalLogins)
                .HasField("_externalLogins")
                .UsePropertyAccessMode(PropertyAccessMode.Field)
                .AutoInclude();
        });

        modelBuilder.Entity<ExternalLogin>(login =>
        {
            login.ToTable("ExternalLogins");
            login.HasKey(entity => new { entity.Issuer, entity.Subject });
            login.Property(entity => entity.Issuer).HasMaxLength(400);
            login.Property(entity => entity.Subject).HasMaxLength(200);
            login.Property(entity => entity.Provider).HasMaxLength(100).IsRequired();
            login.Ignore(entity => entity.Key);
            login.HasIndex(entity => entity.AccountId);
        });

        modelBuilder.Entity<PersonalAccessToken>(token =>
        {
            token.ToTable("PersonalAccessTokens");
            token.HasKey(entity => entity.Id);
            token.Property(entity => entity.Id).ValueGeneratedNever();
            token.Property(entity => entity.Name).HasMaxLength(100).IsRequired();
            token.Property(entity => entity.SecretHash).HasMaxLength(64).IsRequired();
            token.Property(entity => entity.PermissionCeiling).HasMaxLength(4000);
            token.HasIndex(entity => entity.SecretHash).IsUnique();
            token.HasIndex(entity => entity.AccountId);
            token.Ignore(entity => entity.DomainEvents);
            token.Ignore(entity => entity.IsRevoked);
        });

        modelBuilder.Entity<StoredKey>(key =>
        {
            key.ToTable("TokenKeys");
            key.HasKey(entity => entity.Id);
            key.Property(entity => entity.Id).ValueGeneratedNever();
            key.Property(entity => entity.Use).HasConversion<string>().HasMaxLength(20);
            key.Property(entity => entity.ProtectedPrivateKey).IsRequired();
            key.Ignore(entity => entity.KeyId);
        });

        modelBuilder.Entity<Server.ReplayEntry>(entry =>
        {
            entry.ToTable("ReplayEntries");
            entry.HasKey(entity => entity.Key);
            entry.Property(entity => entity.Key).HasMaxLength(100);
            entry.HasIndex(entity => entity.ExpiresAtUnixMs);
        });
    }
}
