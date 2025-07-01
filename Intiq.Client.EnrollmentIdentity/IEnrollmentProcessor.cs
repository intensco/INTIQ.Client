using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using EnrollmentEntityDescriptor = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EnrollmentEntityDescriptor;

namespace Intiq.Client.EnrollmentIdentity;

public interface IEnrollmentProcessor : IAsyncDisposable
{
    /// <summary>
    /// Ensures identity is successfully enrolled. Task result is set after identity is approved from the server side.
    /// </summary>
    Task EnsureIdentityIsEnrolledAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets bearer token that can be used when calling server API on the behalf of the given entity. 
    /// </summary>
    /// <exception cref="Exceptions.UnauthorizedEntityException">Thrown if entity is not approved yet</exception>
    Task<string> GetEntityBearerTokenAsync(string entityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets bearer token that can be used when calling server API on the behalf of the given entity. If the entity is not approved yet, null is returned.
    /// </summary>
    /// <returns>Bearer token for authorized entity, otherwise null.</returns>
    Task<string?> TryGetEntityBearerTokenAsync(string entityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets bucketized entity IDs along with the bearer token for given entities. Not approved entities are not returned.
    /// </summary>
    /// <returns>Dictionary having approved entity IDs as a key and bearer token as a value.</returns>
    Task<IDictionary<string[], string>> GetEntityBearerTokensPerBucketAsync(IList<string> entityIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers additional entities to the enrollment identity. It is safe to call multiple times, even with the same entities.
    /// </summary>
    Task RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default);

    /// <summary>
    /// Watches for entity status changes. At first, it emits all known statuses, and then listens for updates from the server.
    /// </summary>
    IAsyncEnumerable<(string entityId, EnrollEntityStatusEnum status)[]> WatchEntityStatusesAsync(CancellationToken cancellationToken = default);
}