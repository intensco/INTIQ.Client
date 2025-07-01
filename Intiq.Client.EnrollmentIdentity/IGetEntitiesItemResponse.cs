using Intiq.Shared.Common.V1;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;

namespace Intiq.Client.EnrollmentIdentity;

public interface IGetEntitiesItemResponse
{
    EnrollmentEntity? Entity { get; set; }
    EventVersionInfo? EventVersionInfo { get; set; }
}