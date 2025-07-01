using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class RsaEncryptionPublicKey
{
    public SupportedEncryptionAlgorithms EncryptionAlgorithm { get; set; }

    public required RsaEncryptionPublicKeyData Key { get; set; }
}