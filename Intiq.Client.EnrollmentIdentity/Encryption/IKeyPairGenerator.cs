namespace Intiq.Client.EnrollmentIdentity.Encryption;

public interface IKeyPairGenerator
{
    CryptographyKeys GenerateKeyPairs();

    CryptographyKeys DeserializeKeyPairs(byte[] encryptionKeyPair, byte[] verificationKeyPair);
}