using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Domain;

namespace JeffOps.Authentication.Tenancy.Application.Features.Signup;

/// <summary>
/// A product's backend creates a tenant for the person signing up: <paramref name="AdminAccountId"/> becomes its first
/// administrator. With <paramref name="EntraDirectoryId"/>, the directory that person signed in from is linked too, so their
/// colleagues join when they sign in. A directory already linked elsewhere means the organization exists: answered 409
/// <c>directory_taken</c> with nothing created, so the product can offer to join instead.
/// </summary>
public sealed record SignupTenantCommand(string ClientId, string Name, Guid AdminAccountId, Guid? EntraDirectoryId);

public sealed record SignupResult(TenantDto Tenant, string? LinkedDirectory);

public sealed class SignupTenantHandler(
    ITenantRepository tenants,
    IMembershipRepository memberships,
    IDirectoryLinkRepository links,
    IAccountRepository accounts,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<SignupTenantCommand, SignupResult>
{
    public async Task<Result<SignupResult>> HandleAsync(SignupTenantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (Tenant.NormalizeName(command.Name) is null)
        {
            return Error.Failure(TenancyErrors.InvalidName, $"A tenant needs a name of at most {Tenant.MaxNameLength} characters.");
        }

        if (await accounts.FindAsync(command.AdminAccountId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } admin)
        {
            return Error.NotFound(TenancyErrors.AccountNotFound, "No such active account.");
        }

        if (command.EntraDirectoryId is { } directory)
        {
            if (!TenancyMapping.EntraDirectoriesOf(admin).Contains(directory))
            {
                return Error.Forbidden(TenancyErrors.DirectoryNotYours, "The administrator hasn't signed in from that directory.");
            }

            if (await links.FindAsync(DirectoryLink.EntraKind, DirectoryLink.NormalizeEntra(directory), cancellationToken).ConfigureAwait(false) is not null)
            {
                return Error.Conflict(TenancyErrors.DirectoryTaken, "That organization already has a tenant.");
            }
        }

        var now = time.GetUtcNow();
        var tenant = Tenant.Create(command.Name, createdBy: command.AdminAccountId, now);
        tenants.Add(tenant);
        memberships.Add(Membership.Create(tenant.Id, command.AdminAccountId, MembershipRole.Admin, MembershipSource.Signup, addedBy: null, now));
        DirectoryLink? link = null;
        if (command.EntraDirectoryId is { } linked)
        {
            link = DirectoryLink.Entra(tenant.Id, linked, command.AdminAccountId, now);
            links.Add(link);
        }

        if (!await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict(TenancyErrors.DirectoryTaken, "That organization already has a tenant.");
        }

        await audit.WriteAsync(new AuditRecord("tenant.signed_up", "tenant", tenant.Id.ToString())
        {
            ActorId = command.AdminAccountId,
            TenantId = tenant.Id,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["name"] = tenant.Name, ["client"] = command.ClientId, ["directory"] = link?.DirectoryId },
        }, cancellationToken).ConfigureAwait(false);
        return new SignupResult(tenant.ToDto(), link?.DirectoryId);
    }
}
