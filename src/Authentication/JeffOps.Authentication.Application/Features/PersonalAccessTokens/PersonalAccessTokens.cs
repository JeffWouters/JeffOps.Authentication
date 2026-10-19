using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.SharedKernel.Validation;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.PersonalAccessTokens;

/// <summary>Facts about the caller's own credential that decide whether it may manage PATs. Read from claims by the endpoint.</summary>
/// <param name="AccountId">The caller.</param>
/// <param name="TenantId">The tenant of the caller's session; a new PAT is bound to it.</param>
/// <param name="IsImpersonation">The caller is impersonating someone.</param>
/// <param name="IsDelegated">The caller acts on a managed tenant.</param>
/// <param name="IsPatDerived">The caller's token came from a PAT.</param>
/// <param name="IsRoot">The caller is a platform administrator (Root level).</param>
/// <param name="IsSteppedUp">The caller's sign-in satisfied step-up.</param>
public sealed record PatCaller(Guid AccountId, Guid? TenantId, bool IsImpersonation, bool IsDelegated, bool IsPatDerived, bool IsSteppedUp, bool IsRoot = false);

public static class PatErrors
{
    public const string NotWhileImpersonating = "pat_not_while_impersonating";
    public const string NotWhileDelegated = "pat_not_while_delegated";
    public const string NotFromPat = "pat_not_from_pat";
    public const string NotForPlatformAdministrators = "pat_not_for_platform_administrators";
    public const string StepUpRequired = "step_up_required";
    public const string SensitivePatsDisabled = "pat_sensitive_disabled";
    public const string NotFound = "pat_not_found";
}

// ---- CreatePat ---------------------------------------------------------------------------------------------------------

public sealed record CreatePatCommand(PatCaller Caller, string Name, int? ExpiresInDays, IReadOnlyCollection<string> Permissions, bool AllowSensitiveActions);

public sealed record CreatePatResult(Guid Id, string Name, string Secret, DateTimeOffset ExpiresAt);

public sealed class CreatePatValidator(IOptions<TokenServerOptions> options) : IValidator<CreatePatCommand>
{
    public IEnumerable<ValidationFailure> Validate(CreatePatCommand instance)
    {
        ArgumentNullException.ThrowIfNull(instance);

        if (string.IsNullOrWhiteSpace(instance.Name))
        {
            yield return new ValidationFailure(nameof(instance.Name), "A name is required.");
        }
        else if (instance.Name.Trim().Length > 100)
        {
            yield return new ValidationFailure(nameof(instance.Name), "The name may be at most 100 characters.");
        }

        if (options.Value.Pat.ResolveLifetime(instance.ExpiresInDays) is null)
        {
            yield return new ValidationFailure(
                nameof(instance.ExpiresInDays),
                $"expiresInDays must be between 1 and {(int)options.Value.Pat.MaxLifetime.TotalDays}.");
        }
    }
}

/// <summary>
/// Creates a PAT. Refused for credentials that must not mint long-lived access: impersonation, delegated sessions, and PATs
/// themselves. Needs step-up when step-up is required for sensitive actions.
/// </summary>
public sealed class CreatePatHandler(
    IPersonalAccessTokenRepository tokens,
    IUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<TokenServerOptions> options,
    TimeProvider time) : ICommandHandler<CreatePatCommand, CreatePatResult>
{
    public async Task<Result<CreatePatResult>> HandleAsync(CreatePatCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;
        var settings = options.Value;

        if (caller.IsImpersonation)
        {
            return Error.Forbidden(PatErrors.NotWhileImpersonating, "Personal access tokens cannot be created while impersonating another user.");
        }

        if (caller.IsDelegated)
        {
            return Error.Forbidden(PatErrors.NotWhileDelegated, "Personal access tokens cannot be created while acting on a managed tenant.");
        }

        if (caller.IsPatDerived)
        {
            return Error.Forbidden(PatErrors.NotFromPat, "A personal access token cannot create another personal access token.");
        }

        // Platform administration happens interactively, with MFA and audit; a script's credential never carries Root.
        if (caller.IsRoot)
        {
            return Error.Forbidden(PatErrors.NotForPlatformAdministrators, "Platform administrators can't create personal access tokens.");
        }

        if (settings.Mfa.RequireForSensitiveActions && !caller.IsSteppedUp)
        {
            return Error.Forbidden(PatErrors.StepUpRequired, "Creating a personal access token requires a multi-factor sign-in.");
        }

        if (command.AllowSensitiveActions && !settings.Pat.AllowSensitiveActionPats)
        {
            return Error.Forbidden(PatErrors.SensitivePatsDisabled, "Personal access tokens for sensitive actions are disabled.");
        }

        var now = time.GetUtcNow();
        var (token, secret) = PersonalAccessToken.Create(
            caller.AccountId,
            command.Name,
            caller.TenantId,
            command.Permissions,
            command.AllowSensitiveActions,
            settings.Pat.ResolveLifetime(command.ExpiresInDays)!.Value,
            settings.Pat.Prefix,
            now);

        tokens.Add(token);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(
            new AuditRecord("pat.created", "pat", token.Id.ToString())
            {
                ActorId = caller.AccountId,
                TenantId = caller.TenantId,
                OccurredAt = now,
                Severity = token.AllowSensitiveActions ? AuditSeverity.Warning : AuditSeverity.Information,
                Details = new Dictionary<string, string?>
                {
                    ["name"] = token.Name,
                    ["expiresAt"] = token.ExpiresAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                    ["allowSensitiveActions"] = token.AllowSensitiveActions ? "true" : "false",
                },
            },
            cancellationToken).ConfigureAwait(false);

        return new CreatePatResult(token.Id, token.Name, secret, token.ExpiresAt);
    }
}

// ---- ListPats ----------------------------------------------------------------------------------------------------------

public sealed record ListPatsQuery(PatCaller Caller);

public sealed record PatSummary(
    Guid Id,
    string Name,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    bool Revoked,
    bool Active,
    IReadOnlyList<string> Permissions,
    bool AllowSensitiveActions);

public sealed class ListPatsHandler(IPersonalAccessTokenRepository tokens, IOptions<TokenServerOptions> options, TimeProvider time)
    : IQueryHandler<ListPatsQuery, IReadOnlyList<PatSummary>>
{
    public async Task<Result<IReadOnlyList<PatSummary>>> HandleAsync(ListPatsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (query.Caller.IsImpersonation)
        {
            return Error.Forbidden(PatErrors.NotWhileImpersonating, "Personal access tokens are not available while impersonating another user.");
        }

        var now = time.GetUtcNow();
        var max = options.Value.Pat.MaxLifetime;
        var list = await tokens.ListForAccountAsync(query.Caller.AccountId, cancellationToken).ConfigureAwait(false);

        return list
            .OrderByDescending(token => token.CreatedAt)
            .Select(token => new PatSummary(
                token.Id,
                token.Name,
                token.CreatedAt,
                token.EffectiveExpiresAt(max),
                token.LastUsedAt,
                token.IsRevoked,
                token.IsActive(now, max),
                token.Ceiling(),
                token.AllowSensitiveActions))
            .ToList();
    }
}

// ---- RevokePat ---------------------------------------------------------------------------------------------------------

public sealed record RevokePatCommand(PatCaller Caller, Guid TokenId);

public sealed class RevokePatHandler(
    IPersonalAccessTokenRepository tokens,
    IUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<RevokePatCommand>
{
    public async Task<Result> HandleAsync(RevokePatCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.Caller.IsImpersonation)
        {
            return Error.Forbidden(PatErrors.NotWhileImpersonating, "Personal access tokens are not available while impersonating another user.");
        }

        var token = await tokens.FindAsync(command.TokenId, command.Caller.AccountId, cancellationToken).ConfigureAwait(false);
        if (token is null)
        {
            return Error.NotFound(PatErrors.NotFound, "No such personal access token.");
        }

        var now = time.GetUtcNow();
        if (token.Revoke(now))
        {
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync(
                new AuditRecord("pat.revoked", "pat", token.Id.ToString()) { ActorId = command.Caller.AccountId, OccurredAt = now },
                cancellationToken).ConfigureAwait(false);
        }

        return Result.Success();
    }
}
