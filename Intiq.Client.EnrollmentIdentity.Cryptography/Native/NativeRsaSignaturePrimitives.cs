using System;
using System.Security.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeRsaSignaturePrimitives : IRsaSignaturePrimitives
{
    public IRsaVerificationKeyPairHandle GenerateKeyPair()
    {
        using var verificationRsa = RSA.Create(2048);
        var verificationKeyPair = RsaHelpers.ExportKeyPairAsPem(verificationRsa.ExportParameters(true));
        var verificationHandle = new NativeRsaVerificationKeyPairHandle(verificationKeyPair);
        return verificationHandle;
    }

    public IRsaVerificationKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        return NativeRsaVerificationKeyPairHandle.Deserialize(serializedKeyPair);
    }

    public virtual bool Verify(SignedRsaData signedData)
    {
        var signedRsaData = signedData.SignedData;
        if (signedData.VerificationPublicKey.SignatureAlgorithm != SupportedVerificationAlgorithms.Sha256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedVerificationAlgorithms.Sha256)}"));
        var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(signedData.VerificationPublicKey.Key.Rsa, out _);
        var verified = rsa.VerifyData(signedRsaData.Data, signedRsaData.Signature, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return verified;
    }

    public virtual SignedRsaData Sign(PlainTextData plainText, SupportedVerificationAlgorithms algorithm, IRsaVerificationKeyPairHandle verificationKeyPair)
    {
        if (verificationKeyPair is not NativeRsaVerificationKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(NativeRsaVerificationKeyPairHandle)}"));
        if (algorithm != SupportedVerificationAlgorithms.Sha256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedVerificationAlgorithms.Sha256)}"));

        using var rsa = PrepareRsa(nativeKeyPairHandle.KeyPair);
        var signature = rsa.SignData(plainText.Data, 0, plainText.Data.Length, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var verificationPublicKey = rsa.ExportRSAPublicKey();
        var signedData = new SignedRsaData
        {
            SignedData = new SignedRsaDataPayload
            {
                Data = plainText.Data,
                Signature = signature,
            },
            VerificationPublicKey = new RsaVerificationPublicKey
            {
                SignatureAlgorithm = SupportedVerificationAlgorithms.Sha256,
                Key = new RsaVerificationPublicKeyData
                {
                    Rsa = verificationPublicKey,
                },
            },
        };
        return signedData;
    }

    private RSA PrepareRsa(string verificationKeyPair)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(verificationKeyPair);
        return rsa;
    }
}