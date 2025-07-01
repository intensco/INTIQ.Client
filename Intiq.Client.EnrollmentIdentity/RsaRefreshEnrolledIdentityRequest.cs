using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class RsaRefreshEnrolledIdentityRequest : IRefreshEnrolledIdentityRequest
{
    public required RefreshEnrolledIdentityRsaRequest Request { get; set; }
}