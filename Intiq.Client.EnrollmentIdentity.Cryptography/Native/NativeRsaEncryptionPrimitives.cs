using System;
using System.Security.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeRsaEncryptionPrimitives : IRsaEncryptionPrimitives
{
    public IRsaEncryptionKeyPairHandle GenerateKeyPair()
    {
        using var encryptionRsa = RSA.Create(2048);
        var encryptionKeyPair = RsaHelpers.ExportKeyPairAsPem(encryptionRsa.ExportParameters(true));
        var encryptionHandle = new NativeRsaEncryptionKeyPairHandle(encryptionKeyPair);
        return encryptionHandle;
    }

    public IRsaEncryptionKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        return NativeRsaEncryptionKeyPairHandle.Deserialize(serializedKeyPair);
    }

    public virtual PlainTextData Decrypt(EncryptedRsaData encryptedData, IRsaEncryptionKeyPairHandle encryptionKeyPair)
    {
        if (encryptionKeyPair is not NativeRsaEncryptionKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(NativeRsaEncryptionKeyPairHandle)}"));
        var encryptedRsaData = encryptedData.Data;
        using var rsa = PrepareRsa(nativeKeyPairHandle.KeyPair);
        var aesKey = rsa.Decrypt(encryptedRsaData.EncryptedSymmetricKey, RSAEncryptionPadding.Pkcs1);
        if (aesKey.Length != 32)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedEncryptionAlgorithms.Aes256)}"));
        using var aesAlg = Aes.Create();
        aesAlg.Key = aesKey;
        var plainText = aesAlg.DecryptCbc(encryptedRsaData.Data, encryptedRsaData.IV);
        var plainTextData = new PlainTextData
        {
            Data = plainText,
        };
        return plainTextData;
    }

    public virtual EncryptedRsaData Encrypt(PlainTextData plainTextData, RsaEncryptionPublicKey encryptionPublicKey)
    {
        if (encryptionPublicKey.EncryptionAlgorithm != SupportedEncryptionAlgorithms.Aes256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedEncryptionAlgorithms.Aes256)}"));
        if (encryptionPublicKey.Key.Rsa == null)
            throw new InvalidOperationException("Missing public key.");
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(encryptionPublicKey.Key.Rsa, out _);
        using var aesAlg = Aes.Create();
        aesAlg.GenerateIV();
        aesAlg.GenerateKey();
        var aesEncrypted = aesAlg.EncryptCbc(plainTextData.Data, aesAlg.IV);
        var encryptedAesKey = rsa.Encrypt(aesAlg.Key, RSAEncryptionPadding.Pkcs1);
        var encryptedData = new EncryptedRsaData
        {
            Data = new EncryptedRsaDataPayload
            {
                Data = aesEncrypted,
                IV = aesAlg.IV,
                EncryptedSymmetricKey = encryptedAesKey,
            },
        };
        return encryptedData;
    }

    private RSA PrepareRsa(string encryptionKeyPair)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(encryptionKeyPair);
        return rsa;
    }
}