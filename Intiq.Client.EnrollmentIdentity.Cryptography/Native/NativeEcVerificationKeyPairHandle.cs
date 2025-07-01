using System.Text;
using Intiq.Client.EnrollmentIdentity.Cryptography.Constants;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeEcVerificationKeyPairHandle : IEcVerificationKeyPairHandle
{
    private readonly EcVerificationPublicKey _verificationPublicKey;

    public string KeyPair { get; }
    
    public NativeEcVerificationKeyPairHandle(string keyPair)
    {
        KeyPair = keyPair;
        _verificationPublicKey = EcHelpers.GetVerificationPublicKeyFromPem(keyPair, EcCurveConstants.CurveName);
    }
    
    public byte[] Serialize()
    {
        return Encoding.ASCII.GetBytes(KeyPair);
    }

    public EcVerificationPublicKey GetVerificationPublicKey()
    {
        return _verificationPublicKey;
    }

    public static NativeEcVerificationKeyPairHandle Deserialize(byte[] serializedKeyPair)
    {
        var keyPair = Encoding.ASCII.GetString(serializedKeyPair);
        return new NativeEcVerificationKeyPairHandle(keyPair);
    }
}