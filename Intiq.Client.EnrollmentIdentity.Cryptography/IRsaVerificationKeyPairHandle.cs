using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IRsaVerificationKeyPairHandle : IKeyPairHandle
{
    RsaVerificationPublicKey GetVerificationPublicKey();
}