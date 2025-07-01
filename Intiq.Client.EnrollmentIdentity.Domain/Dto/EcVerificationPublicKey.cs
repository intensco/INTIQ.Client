using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class EcVerificationPublicKey
{
    public SupportedVerificationAlgorithms SignatureAlgorithm { get; set; }

    public required EcPublicKeyData Key { get; set; }
}