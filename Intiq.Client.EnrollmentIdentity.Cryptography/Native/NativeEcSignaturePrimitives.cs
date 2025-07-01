using System;
using System.Security.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeEcSignaturePrimitives : IEcSignaturePrimitives
{
    private const int PublicKeyLength = 32;
    private const EcCurveName SupportedCurveName = EcCurveName.NistP256;
    private const SupportedVerificationAlgorithms SupportedVerificationAlgorithm = SupportedVerificationAlgorithms.Sha256;

    public IEcVerificationKeyPairHandle GenerateKeyPair()
    {
        var verificationKeyPair = EcHelpers.GenerateKeyPair(EcCurveName.NistP256);
        var verificationHandle = new NativeEcVerificationKeyPairHandle(verificationKeyPair);
        return verificationHandle;
    }

    public IEcVerificationKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        return NativeEcVerificationKeyPairHandle.Deserialize(serializedKeyPair);
    }

    public virtual bool Verify(SignedEcData signedData)
    {
        var signedEcdsaData = signedData.SignedData;
        if (signedData.VerificationPublicKey.SignatureAlgorithm != SupportedVerificationAlgorithms.Sha256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {SupportedVerificationAlgorithm}"));
        var verificationKey = signedData.VerificationPublicKey.Key;
        if(verificationKey.CurveName != SupportedCurveName)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {SupportedCurveName}"));
        if(verificationKey.X.Length != PublicKeyLength)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {PublicKeyLength} bytes long public key."));
        if(verificationKey.Y.Length != PublicKeyLength)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {PublicKeyLength} bytes long public key."));

        using var ecdsa = ECDsa.Create();
        var publicKeyParameters = EcHelpers.CreateEcParameters(verificationKey);
        ecdsa.ImportParameters(publicKeyParameters);
        var r = signedEcdsaData.R;
        var s = signedEcdsaData.S;
        var signature = new byte[r.Length + s.Length];
        Array.Copy(r, signature, r.Length);
        Array.Copy(s, 0, signature, r.Length, s.Length);
        var verified = ecdsa.VerifyData(signedEcdsaData.Data, signature, HashAlgorithmName.SHA256);

        return verified;
    }

    public virtual SignedEcData Sign(PlainTextData plainText, SupportedVerificationAlgorithms algorithm, IEcVerificationKeyPairHandle verificationKeyPair)
    {
        if (verificationKeyPair is not NativeEcVerificationKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(NativeEcVerificationKeyPairHandle)}"));
        if (algorithm != SupportedVerificationAlgorithms.Sha256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {SupportedVerificationAlgorithm}"));

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(nativeKeyPairHandle.KeyPair);
        var signature = ecdsa.SignData(plainText.Data, HashAlgorithmName.SHA256);
        var publicKey = ecdsa.ExportParameters(false);
        var signedData = new SignedEcData
        {
            SignedData = new SignedEcDataPayload
            {
                Data = plainText.Data,
                R = signature.AsSpan(0, PublicKeyLength).ToArray(),
                S = signature.AsSpan(PublicKeyLength, PublicKeyLength).ToArray(),
            },
            VerificationPublicKey = new EcVerificationPublicKey
            {
                SignatureAlgorithm = SupportedVerificationAlgorithm,
                Key = new EcPublicKeyData
                {
                    CurveName = SupportedCurveName,
                    X = publicKey.Q.X ?? Array.Empty<byte>(),
                    Y = publicKey.Q.Y ?? Array.Empty<byte>(),
                },
            },
        };

        return signedData;
    }
}