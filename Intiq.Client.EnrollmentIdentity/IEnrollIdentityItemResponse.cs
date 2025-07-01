using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;

namespace Intiq.Client.EnrollmentIdentity;

public interface IEnrollIdentityItemResponse
{
    string Id { get; }
    bool? FinalMessage { get; }
    EnrollIdentityStatusEnum Status { get; }
    CertificateData? IssuedCertificate { get; }
}