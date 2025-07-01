using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class RsaVerificationPublicKey
{
    public SupportedVerificationAlgorithms SignatureAlgorithm { get; set; }

    public required RsaVerificationPublicKeyData Key { get; set; }
}