using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography;

public interface IRsaEncryptionPrimitives
{
    IRsaEncryptionKeyPairHandle GenerateKeyPair();

    IRsaEncryptionKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair);

    PlainTextData Decrypt(EncryptedRsaData encryptedData, IRsaEncryptionKeyPairHandle encryptionKeyPair);

    EncryptedRsaData Encrypt(PlainTextData plainTextData, RsaEncryptionPublicKey encryptionPublicKey);
}