using Intiq.Client.EnrollmentIdentity.Cryptography;

namespace Intiq.Client.EnrollmentIdentity.Encryption.RSA;

public class RsaKeyPairGenerator : IKeyPairGenerator
{
    private readonly IRsaSignaturePrimitives _rsaSignaturePrimitives;
    private readonly IRsaEncryptionPrimitives _rsaEncryptionPrimitives;

    public RsaKeyPairGenerator(IRsaSignaturePrimitives rsaSignaturePrimitives,
        IRsaEncryptionPrimitives rsaEncryptionPrimitives)
    {
        _rsaSignaturePrimitives = rsaSignaturePrimitives;
        _rsaEncryptionPrimitives = rsaEncryptionPrimitives;
    }

    public CryptographyKeys GenerateKeyPairs()
    {
        var encryptionKeyPair = _rsaEncryptionPrimitives.GenerateKeyPair();
        var verificationKeyPair = _rsaSignaturePrimitives.GenerateKeyPair();
        return new CryptographyKeys(encryptionKeyPair, verificationKeyPair);
    }

    public CryptographyKeys DeserializeKeyPairs(byte[] encryptionKeyPair, byte[] verificationKeyPair)
    {
        var encryptionKey = _rsaEncryptionPrimitives.DeserializeKeyPair(encryptionKeyPair);
        var verificationKey = _rsaSignaturePrimitives.DeserializeKeyPair(verificationKeyPair);
        return new CryptographyKeys(encryptionKey, verificationKey);
    }
}