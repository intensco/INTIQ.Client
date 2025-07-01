using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IEcVerificationKeyPairHandle : IKeyPairHandle
{
    EcVerificationPublicKey GetVerificationPublicKey();
}