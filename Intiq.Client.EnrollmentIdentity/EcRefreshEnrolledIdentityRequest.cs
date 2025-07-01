using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class EcRefreshEnrolledIdentityRequest : IRefreshEnrolledIdentityRequest
{
    public required RefreshEnrolledIdentityEcRequest Request { get; set; }
}