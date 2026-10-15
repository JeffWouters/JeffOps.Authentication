using JeffOps.Authorization.Domain.Management;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authorization.Infrastructure.Persistence;

/// <summary>The authorization management store. Provider-neutral; migrations come from a persistence package.</summary>
public sealed class AuthorizationDbContext(DbContextOptions<AuthorizationDbContext> options) : DbContext(options)
{
    public const string Schema = "authz";

    public DbSet<Role> Roles => Set<Role>();

    public DbSet<Assignment> Assignments => Set<Assignment>();

    public DbSet<RoleChangeRequest> RoleChangeRequests => Set<RoleChangeRequest>();

    public DbSet<ApprovalSetting> ApprovalSettings => Set<ApprovalSetting>();

    public DbSet<RegisteredPermission> RegisteredPermissions => Set<RegisteredPermission>();

    public DbSet<StoredPolicy> Policies => Set<StoredPolicy>();

    public DbSet<Scope> Scopes => Set<Scope>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<Role>(role =>
        {
            role.ToTable("Roles");
            role.HasKey(entity => entity.Id);
            role.Property(entity => entity.Id).ValueGeneratedNever();
            role.Property(entity => entity.Name).HasMaxLength(200).IsRequired();
            role.Property(entity => entity.MinScopeKey).HasMaxLength(100);
            role.Property(entity => entity.ComplianceControls).HasMaxLength(1000);
            role.HasIndex(entity => new { entity.TenantId, entity.Name }).IsUnique();
            role.Ignore(entity => entity.DomainEvents);
            role.OwnsMany(entity => entity.Permissions, permission =>
            {
                permission.ToTable("RolePermissions");
                permission.WithOwner().HasForeignKey(entity => entity.RoleId);
                permission.HasKey(entity => new { entity.RoleId, entity.Code });
                permission.Property(entity => entity.Code).HasMaxLength(200);
            });
            role.Navigation(entity => entity.Permissions).HasField("_permissions").UsePropertyAccessMode(PropertyAccessMode.Field);
        });

        modelBuilder.Entity<Assignment>(assignment =>
        {
            assignment.ToTable("Assignments");
            assignment.HasKey(entity => entity.Id);
            assignment.Property(entity => entity.Id).ValueGeneratedNever();
            assignment.Property(entity => entity.ScopeKey).HasMaxLength(100).IsRequired();
            assignment.HasIndex(entity => new { entity.UserId, entity.TenantId });
            assignment.HasIndex(entity => entity.TenantId);
            assignment.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<RoleChangeRequest>(request =>
        {
            request.ToTable("RoleChangeRequests");
            request.HasKey(entity => entity.Id);
            request.Property(entity => entity.Id).ValueGeneratedNever();
            request.Property(entity => entity.Kind).HasConversion<string>().HasMaxLength(30);
            request.Property(entity => entity.Status).HasConversion<string>().HasMaxLength(20);
            request.Property(entity => entity.PermissionCode).HasMaxLength(200);
            request.Property(entity => entity.ScopeKey).HasMaxLength(100);
            request.Property(entity => entity.Note).HasMaxLength(1000);
            request.HasIndex(entity => new { entity.TenantId, entity.Status });
            request.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<ApprovalSetting>(setting =>
        {
            setting.ToTable("ApprovalSettings");
            setting.HasKey(entity => entity.Id);
            setting.HasIndex(entity => entity.TenantId).IsUnique();
        });

        modelBuilder.Entity<RegisteredPermission>(permission =>
        {
            permission.ToTable("RegisteredPermissions");
            permission.HasKey(entity => entity.Code);
            permission.Property(entity => entity.Code).HasMaxLength(200);
            permission.Property(entity => entity.DisplayName).HasMaxLength(300);
            permission.Property(entity => entity.Domain).HasMaxLength(100);
            permission.Property(entity => entity.Source).HasMaxLength(100);
        });

        modelBuilder.Entity<StoredPolicy>(policy =>
        {
            policy.ToTable("Policies");
            policy.HasKey(entity => entity.Id);
            policy.Property(entity => entity.Id).ValueGeneratedNever();
            policy.Property(entity => entity.Name).HasMaxLength(200).IsRequired();
            policy.Property(entity => entity.TargetAction).HasMaxLength(200).IsRequired();
            policy.Property(entity => entity.TargetResourceType).HasMaxLength(100);
            policy.Property(entity => entity.Effect).HasConversion<string>().HasMaxLength(10);
            policy.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<Scope>(scope =>
        {
            scope.ToTable("Scopes");
            scope.HasKey(entity => entity.Id);
            scope.Property(entity => entity.Id).HasColumnName("Key").HasMaxLength(100);
            scope.Property(entity => entity.Name).HasMaxLength(200).IsRequired();
            scope.Property(entity => entity.ParentKey).HasMaxLength(100);
            scope.Ignore(entity => entity.DomainEvents);
        });
    }
}
