using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class RsaEnrollIdentityRequest : IEnrollIdentityRequest
{
    public required EnrollIdentityRsaRequest Request { get; set; }
}