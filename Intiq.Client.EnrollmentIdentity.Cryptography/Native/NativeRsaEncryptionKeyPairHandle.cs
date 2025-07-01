using System.Text;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeRsaEncryptionKeyPairHandle : IRsaEncryptionKeyPairHandle
{
    private readonly RsaEncryptionPublicKey _encryptionPublicKey;

    public string KeyPair { get; }
    
    public NativeRsaEncryptionKeyPairHandle(string keyPair)
    {
        KeyPair = keyPair;
        _encryptionPublicKey = GetRsaEncryptionPublicKey(keyPair);
    }

    public byte[] Serialize()
    {
        return Encoding.ASCII.GetBytes(KeyPair);
    }

    public RsaEncryptionPublicKey GetEncryptionPublicKey()
    {
        return _encryptionPublicKey;
    }

    private static RsaEncryptionPublicKey GetRsaEncryptionPublicKey(string keyPair)
    {
        using var rsa = RsaCryptographyKeysHelpers.CreateRsa(keyPair);
        var publicKey = rsa.ExportRSAPublicKey();
        var encryptionPublicKey = new RsaEncryptionPublicKey
        {
            Key = new RsaEncryptionPublicKeyData
            {
                Rsa = publicKey,
            },
            EncryptionAlgorithm = SupportedEncryptionAlgorithms.Aes256
        };
        return encryptionPublicKey;
    }

    public static NativeRsaEncryptionKeyPairHandle Deserialize(byte[] serializedKeyPair)
    {
        var keyPair = Encoding.ASCII.GetString(serializedKeyPair);
        return new NativeRsaEncryptionKeyPairHandle(keyPair);
    }
}