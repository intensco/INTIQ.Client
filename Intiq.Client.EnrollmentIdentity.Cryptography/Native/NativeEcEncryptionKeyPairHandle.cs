using System.Text;
using Intiq.Client.EnrollmentIdentity.Cryptography.Constants;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeEcEncryptionKeyPairHandle : IEcEncryptionKeyPairHandle
{
    private readonly EcEncryptionPublicKey _encryptionPublicKey;

    public string KeyPair { get; }
    
    public NativeEcEncryptionKeyPairHandle(string keyPair)
    {
        KeyPair = keyPair;
        _encryptionPublicKey = EcHelpers.GetEncryptionPublicKeyFromPem(keyPair, EcCurveConstants.CurveName);
    }

    public byte[] Serialize()
    {
        return Encoding.ASCII.GetBytes(KeyPair);
    }

    public EcEncryptionPublicKey GetEncryptionPublicKey()
    {
        return _encryptionPublicKey;
    }

    public static NativeEcEncryptionKeyPairHandle Deserialize(byte[] serializedKeyPair)
    {
        var keyPair = Encoding.ASCII.GetString(serializedKeyPair);
        return new NativeEcEncryptionKeyPairHandle(keyPair);
    }
}