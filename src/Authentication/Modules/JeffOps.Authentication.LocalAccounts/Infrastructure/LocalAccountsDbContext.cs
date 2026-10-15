using System.Security.Cryptography;
using JeffOps.Authentication.LocalAccounts.Application;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.LocalAccounts.Infrastructure;

/// <summary>The local credential store (schema <c>local</c>). Provider-neutral; SQL Server migrations ship separately.</summary>
public sealed class LocalAccountsDbContext(DbContextOptions<LocalAccountsDbContext> options) : DbContext(options)
{
    public const string Schema = "local";

    public DbSet<LocalCredential> Credentials => Set<LocalCredential>();

    public DbSet<AccountToken> Tokens => Set<AccountToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<LocalCredential>(credential =>
        {
            credential.ToTable("Credentials");
            credential.HasKey(entity => entity.Id);
            credential.Property(entity => entity.Id).HasColumnName("AccountId").ValueGeneratedNever();
            credential.Property(entity => entity.PasswordHash).HasMaxLength(200);
            credential.Property(entity => entity.ProtectedTotpSecret).HasMaxLength(1000);
            credential.Property(entity => entity.SecurityStamp).HasMaxLength(64).IsConcurrencyToken();
            credential.Ignore(entity => entity.DomainEvents);
            credential.Ignore(entity => entity.HasSecondFactor);

            credential.OwnsMany(entity => entity.Passkeys, passkey =>
            {
                passkey.ToTable("Passkeys");
                passkey.WithOwner().HasForeignKey(entity => entity.AccountId);
                passkey.HasKey(entity => entity.CredentialId);
                passkey.Property(entity => entity.CredentialId).HasMaxLength(1023);
                passkey.Property(entity => entity.Name).HasMaxLength(200);
            });
            credential.Navigation(entity => entity.Passkeys).HasField("_passkeys").UsePropertyAccessMode(PropertyAccessMode.Field);

            credential.OwnsMany(entity => entity.RecoveryCodes, code =>
            {
                code.ToTable("RecoveryCodes");
                code.WithOwner().HasForeignKey(entity => entity.AccountId);
                code.HasKey(entity => new { entity.AccountId, entity.Hash });
                code.Property(entity => entity.Hash).HasMaxLength(64);
            });
            credential.Navigation(entity => entity.RecoveryCodes).HasField("_recoveryCodes").UsePropertyAccessMode(PropertyAccessMode.Field);
        });

        modelBuilder.Entity<AccountToken>(token =>
        {
            token.ToTable("AccountTokens");
            token.HasKey(entity => entity.Id);
            token.Property(entity => entity.TokenHash).HasMaxLength(64);
            token.Property(entity => entity.Purpose).HasConversion<string>().HasMaxLength(30);
            token.HasIndex(entity => entity.TokenHash).IsUnique();
            token.HasIndex(entity => new { entity.AccountId, entity.Purpose });
        });
    }
}

internal sealed class LocalCredentialRepository(LocalAccountsDbContext db) : ILocalCredentialRepository
{
    public Task<LocalCredential?> FindAsync(Guid accountId, CancellationToken cancellationToken) =>
        db.Credentials.FirstOrDefaultAsync(credential => credential.Id == accountId, cancellationToken);

    public Task<LocalCredential?> FindByPasskeyAsync(byte[] credentialId, CancellationToken cancellationToken) =>
        db.Credentials.FirstOrDefaultAsync(credential => credential.Passkeys.Any(passkey => passkey.CredentialId == credentialId), cancellationToken);

    public void Add(LocalCredential credential) => db.Credentials.Add(credential);
}

internal sealed class AccountTokenRepository(LocalAccountsDbContext db) : IAccountTokenRepository
{
    public Task<AccountToken?> FindAsync(string tokenHash, AccountTokenPurpose purpose, CancellationToken cancellationToken) =>
        db.Tokens.FirstOrDefaultAsync(token => token.TokenHash == tokenHash && token.Purpose == purpose, cancellationToken);

    public async Task<IReadOnlyList<AccountToken>> ListUnusedAsync(Guid accountId, AccountTokenPurpose purpose, CancellationToken cancellationToken) =>
        await db.Tokens.Where(token => token.AccountId == accountId && token.Purpose == purpose && token.UsedAt == null).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(AccountToken token) => db.Tokens.Add(token);
}

internal sealed class LocalUnitOfWork(LocalAccountsDbContext db, IDomainEventDispatcher dispatcher) : ILocalUnitOfWork
{
    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var aggregates = db.ChangeTracker.Entries<IHasDomainEvents>().Select(entry => entry.Entity).Where(entity => entity.DomainEvents.Count > 0).ToList();
        var events = aggregates.SelectMany(aggregate => aggregate.DomainEvents).ToList();

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        await dispatcher.DispatchAsync(events, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Protects TOTP secrets with Data Protection (share the key ring across token server replicas).</summary>
internal sealed class DataProtectionTotpProtector(IDataProtectionProvider provider) : ITotpSecretProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("JeffOps.LocalAccounts.Totp");

    public string Protect(byte[] secret) => Convert.ToBase64String(_protector.Protect(secret));

    public byte[]? Unprotect(string protectedSecret)
    {
        try
        {
            return _protector.Unprotect(Convert.FromBase64String(protectedSecret));
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            return null;
        }
    }
}
