using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Domain.Dto;

public class EcEncryptionPublicKey
{
    public SupportedEncryptionAlgorithms EncryptionAlgorithm { get; set; }

    public required EcPublicKeyData Key { get; set; }
}