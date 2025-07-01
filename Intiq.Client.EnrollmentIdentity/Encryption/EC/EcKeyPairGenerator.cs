using Intiq.Client.EnrollmentIdentity.Cryptography;

namespace Intiq.Client.EnrollmentIdentity.Encryption.EC;

public class EcKeyPairGenerator : IKeyPairGenerator
{
    private readonly IEcSignaturePrimitives _ecSignaturePrimitives;
    private readonly IEcEncryptionPrimitives _ecEncryptionPrimitives;

    public EcKeyPairGenerator(IEcSignaturePrimitives ecSignaturePrimitives,
        IEcEncryptionPrimitives ecEncryptionPrimitives)
    {
        _ecSignaturePrimitives = ecSignaturePrimitives;
        _ecEncryptionPrimitives = ecEncryptionPrimitives;
    }

    public CryptographyKeys GenerateKeyPairs()
    {
        var encryptionKeyPair = _ecEncryptionPrimitives.GenerateKeyPair();
        var verificationKeyPair = _ecSignaturePrimitives.GenerateKeyPair();
        return new CryptographyKeys(encryptionKeyPair, verificationKeyPair);
    }

    public CryptographyKeys DeserializeKeyPairs(byte[] encryptionKeyPair, byte[] verificationKeyPair)
    {
        var encryptionKey = _ecEncryptionPrimitives.DeserializeKeyPair(encryptionKeyPair);
        var verificationKey = _ecSignaturePrimitives.DeserializeKeyPair(verificationKeyPair);
        return new CryptographyKeys(encryptionKey, verificationKey);
    }
}