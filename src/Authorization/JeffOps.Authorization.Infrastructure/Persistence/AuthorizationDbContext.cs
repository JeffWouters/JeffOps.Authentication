using JeffOps.Authorization.Domain.Management;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authorization.Infrastructure.Persistence;

/// <summary>The authorization management store. Provider-neutral; migrations come from a persistence package.</summary>
public sealed class AuthorizationDbContext(DbContextOptions<AuthorizationDbContext> options) : DbContext(options)
{
    /// <summary>The database schema that holds the authorization management tables.</summary>
    public const string Schema = "authz";

    /// <summary>Roles: built-in ones from the host's role provider, and each tenant's custom ones.</summary>
    public DbSet<Role> Roles => Set<Role>();

    /// <summary>Roles assigned to users, per tenant and scope, optionally expiring.</summary>
    public DbSet<Assignment> Assignments => Set<Assignment>();

    /// <summary>Changes waiting for, or decided by, a second person's approval (four-eyes).</summary>
    public DbSet<RoleChangeRequest> RoleChangeRequests => Set<RoleChangeRequest>();

    /// <summary>Whether role changes need four-eyes approval, per tenant and as the global default.</summary>
    public DbSet<ApprovalSetting> ApprovalSettings => Set<ApprovalSetting>();

    /// <summary>The permissions services have declared to the registry.</summary>
    public DbSet<RegisteredPermission> RegisteredPermissions => Set<RegisteredPermission>();

    /// <summary>The managed ABAC policies.</summary>
    public DbSet<StoredPolicy> Policies => Set<StoredPolicy>();

    /// <summary>The nodes of the scope hierarchy, from the built-in <c>system</c> root down.</summary>
    public DbSet<Scope> Scopes => Set<Scope>();

    /// <summary>Roles assigned to groups, held by every member of the group.</summary>
    public DbSet<GroupAssignment> GroupAssignments => Set<GroupAssignment>();

    /// <summary>Group memberships, mirrored from the group's source (SCIM provisioning or the host).</summary>
    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();

    /// <inheritdoc />
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

        modelBuilder.Entity<GroupAssignment>(assignment =>
        {
            assignment.ToTable("GroupAssignments");
            assignment.HasKey(entity => entity.Id);
            assignment.Property(entity => entity.Id).ValueGeneratedNever();
            assignment.Property(entity => entity.ScopeKey).HasMaxLength(100).IsRequired();
            assignment.HasIndex(entity => new { entity.TenantId, entity.GroupId });
            assignment.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<GroupMember>(member =>
        {
            member.ToTable("GroupMembers");
            member.HasKey(entity => new { entity.TenantId, entity.GroupId, entity.UserId });
            member.HasIndex(entity => new { entity.TenantId, entity.UserId });
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
