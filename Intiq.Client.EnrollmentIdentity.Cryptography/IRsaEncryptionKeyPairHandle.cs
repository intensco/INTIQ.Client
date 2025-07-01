using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IRsaEncryptionKeyPairHandle : IKeyPairHandle
{
    RsaEncryptionPublicKey GetEncryptionPublicKey();
}