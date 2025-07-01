using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class MemoryEnrollmentEntitiesStorage : IEnrollmentEntitiesStorage
{
    private readonly Dictionary<string, EnrollEntityStatusEnum> _statusesByEntityId = new();
    private long? _lastOutboxPosition;

    public async Task StoreEntityStatusesAsync(
        IEnumerable<(string entityId, EnrollEntityStatusEnum status)> statuses, 
        long outboxPosition, 
        string enrollmentIdentityId, 
        CancellationToken cancellationToken = default)
    {
        foreach (var (entityId, status) in statuses)
        {
            _statusesByEntityId[entityId] = status;
        }

        _lastOutboxPosition = outboxPosition;
    }

    public async Task<(long? outboxPosition, Dictionary<string, EnrollEntityStatusEnum> statusesByEntityId)> GetEntityStatusesAsync(
        string enrollmentIdentityId,
        CancellationToken cancellationToken = default)
    {
        return (_lastOutboxPosition, _statusesByEntityId);
    }
}