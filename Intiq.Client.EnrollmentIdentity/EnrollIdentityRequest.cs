using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public class EcEnrollIdentityRequest : IEnrollIdentityRequest
{
    public required EnrollIdentityEcRequest Request { get; set; }
}