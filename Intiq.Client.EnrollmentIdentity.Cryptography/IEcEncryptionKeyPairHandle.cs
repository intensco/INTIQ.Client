using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IEcEncryptionKeyPairHandle : IKeyPairHandle
{
    EcEncryptionPublicKey GetEncryptionPublicKey();
}