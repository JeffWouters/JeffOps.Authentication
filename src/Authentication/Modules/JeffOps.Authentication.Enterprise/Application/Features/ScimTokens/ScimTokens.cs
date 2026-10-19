using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.ScimTokens;

/// <summary>A SCIM token's details; <c>ExpiresAt</c> is null for a token that doesn't expire.</summary>
public sealed record ScimTokenDto(Guid Id, string Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, bool Active, DateTimeOffset? ExpiresAt = null);

/// <summary>A new SCIM token; <c>Token</c> is the bearer secret, shown once.</summary>
public sealed record CreatedScimToken(ScimTokenDto Details, string Token);

/// <summary>
/// A tenant administrator creates a token for their identity provider's SCIM connector, optionally expiring at
/// <paramref name="ExpiresAt"/> (which must be in the future).
/// </summary>
public sealed record CreateScimTokenCommand(EnterpriseCaller Caller, string Name, DateTimeOffset? ExpiresAt = null);

public sealed class CreateScimTokenHandler(IScimTokenRepository tokens, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<CreateScimTokenCommand, CreatedScimToken>
{
    public async Task<Result<CreatedScimToken>> HandleAsync(CreateScimTokenCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();
        if (command.ExpiresAt is { } expiresAt && expiresAt <= now)
        {
            return Error.Validation([new ValidationFailure("expiresAt", "A token's expiry must be in the future.")]);
        }

        var (token, secret) = ScimToken.Issue(command.Caller.TenantId, command.Name, now, command.ExpiresAt);
        tokens.Add(token);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("scim_token.created", "scim_token", token.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = token.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["expires_at"] = token.ExpiresAt?.ToString("O", System.Globalization.CultureInfo.InvariantCulture) },
        }, cancellationToken).ConfigureAwait(false);
        return new CreatedScimToken(ToDto(token, now), secret);
    }

    internal static ScimTokenDto ToDto(ScimToken token, DateTimeOffset now) =>
        new(token.Id, token.Name, token.CreatedAt, token.LastUsedAt, token.IsActiveAt(now), token.ExpiresAt);
}

public sealed record ListScimTokensQuery(EnterpriseCaller Caller);

public sealed class ListScimTokensHandler(IScimTokenRepository tokens, TimeProvider time) : IQueryHandler<ListScimTokensQuery, IReadOnlyList<ScimTokenDto>>
{
    public async Task<Result<IReadOnlyList<ScimTokenDto>>> HandleAsync(ListScimTokensQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var now = time.GetUtcNow();
        return Result.Success<IReadOnlyList<ScimTokenDto>>(
            [.. (await tokens.ListForTenantAsync(query.Caller.TenantId, cancellationToken).ConfigureAwait(false)).Select(token => CreateScimTokenHandler.ToDto(token, now))]);
    }
}

public sealed record RevokeScimTokenCommand(EnterpriseCaller Caller, Guid TokenId);

public sealed class RevokeScimTokenHandler(IScimTokenRepository tokens, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time) : ICommandHandler<RevokeScimTokenCommand>
{
    public async Task<Result> HandleAsync(RevokeScimTokenCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var token = await tokens.FindAsync(command.TokenId, cancellationToken).ConfigureAwait(false);
        if (token is null || token.TenantId != command.Caller.TenantId)
        {
            return Error.NotFound(EnterpriseErrors.NotFound, "No such token.");
        }

        var now = time.GetUtcNow();
        token.Revoke(now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("scim_token.revoked", "scim_token", token.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = token.TenantId,
            OccurredAt = now,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>
/// Finds the tenant a SCIM bearer token belongs to (null when unknown, revoked or expired, or the tenant is suspended or gone)
/// and records its use.
/// </summary>
public sealed class ScimTokenAuthenticator(IScimTokenRepository tokens, IEnterpriseUnitOfWork unitOfWork, ITenantDirectory tenants, TimeProvider time)
{
    public async Task<Guid?> AuthenticateAsync(string? secret, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(secret) || !secret.StartsWith(ScimToken.Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        var now = time.GetUtcNow();
        var token = await tokens.FindByHashAsync(ScimToken.HashOf(secret), cancellationToken).ConfigureAwait(false);
        if (token is null || !token.IsActiveAt(now)
            || await tenants.FindTenantAsync(token.TenantId, cancellationToken).ConfigureAwait(false) is not { AcceptsSessions: true })
        {
            return null;
        }

        if (token.LastUsedAt is not { } last || now - last > TimeSpan.FromMinutes(5))
        {
            token.Used(now);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return token.TenantId;
    }
}
