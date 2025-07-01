using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IEcEncryptionPrimitives
{
    IEcEncryptionKeyPairHandle GenerateKeyPair();

    IEcEncryptionKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair);

    PlainTextData Decrypt(EncryptedEcData encryptedData, IEcEncryptionKeyPairHandle encryptionKeyPair);

    EncryptedEcData Encrypt(PlainTextData plainTextData, EcEncryptionPublicKey encryptionPublicKey);
}