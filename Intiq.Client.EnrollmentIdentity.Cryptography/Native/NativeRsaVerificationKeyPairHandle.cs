using System.Text;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeRsaVerificationKeyPairHandle : IRsaVerificationKeyPairHandle
{
    private readonly RsaVerificationPublicKey _verificationPublicKey;

    public string KeyPair { get; }
    
    public NativeRsaVerificationKeyPairHandle(string keyPair)
    {
        KeyPair = keyPair;
        _verificationPublicKey = GetRsaVerificationPublicKey(keyPair);
    }

    public byte[] Serialize()
    {
        return Encoding.ASCII.GetBytes(KeyPair);
    }

    public RsaVerificationPublicKey GetVerificationPublicKey()
    {
        return _verificationPublicKey;
    }

    private static RsaVerificationPublicKey GetRsaVerificationPublicKey(string keyPair)
    {
        using var rsa = RsaCryptographyKeysHelpers.CreateRsa(keyPair);
        var publicKey = rsa.ExportRSAPublicKey();
        var verificationPublicKey = new RsaVerificationPublicKey
        {
            SignatureAlgorithm = SupportedVerificationAlgorithms.Sha256,
            Key = new RsaVerificationPublicKeyData
            {
                Rsa = publicKey,
            },
        };
        return verificationPublicKey;
    }

    public static NativeRsaVerificationKeyPairHandle Deserialize(byte[] serializedKeyPair)
    {
        var keyPair = Encoding.ASCII.GetString(serializedKeyPair);
        return new NativeRsaVerificationKeyPairHandle(keyPair);
    }
}