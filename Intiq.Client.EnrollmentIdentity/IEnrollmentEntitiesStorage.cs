using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;

namespace Intiq.Client.EnrollmentIdentity;

public interface IEnrollmentEntitiesStorage
{
    Task StoreEntityStatusesAsync(
        IEnumerable<(string entityId, EnrollEntityStatusEnum status)> statuses,
        long outboxPosition,
        string enrollmentIdentityId,
        CancellationToken cancellationToken = default);

    Task<(long? outboxPosition, Dictionary<string, EnrollEntityStatusEnum> statusesByEntityId)> GetEntityStatusesAsync(string enrollmentIdentityId, CancellationToken cancellationToken = default);
}