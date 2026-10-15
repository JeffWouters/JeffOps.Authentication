using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Delegation.Application.Features.Maintenance;

/// <summary>
/// Marks grants whose approval deadline or session window passed as expired, announcing each. Tokens already stop at those
/// times; this keeps the record and the event stream accurate. Run on a schedule.
/// </summary>
public sealed record ExpireGrantsCommand;

public sealed class ExpireGrantsHandler(IDueGrantSource due, IDelegationUnitOfWork unitOfWork, TimeProvider time) : ICommandHandler<ExpireGrantsCommand, int>
{
    public async Task<Result<int>> HandleAsync(ExpireGrantsCommand command, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var expired = (await due.ListDueAsync(now, cancellationToken).ConfigureAwait(false)).Count(grant => grant.ExpireIfDue(now));
        if (expired > 0 && !await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            // Another request changed one of them; the next run picks up what's still due.
            return 0;
        }

        return expired;
    }
}
