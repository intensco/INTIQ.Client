using Intiq.Shared.Common.V1;

namespace Intiq.Client.EnrollmentIdentity;

public class GetEntitiesItemRequest
{
    public EventVersionInfo? EventVersionInfo { get; set; }
    public EventVersionInfo? ConfirmedEventVersionInfo { get; set; }
}