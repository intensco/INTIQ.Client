using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public class NativeEcEncryptionPrimitives : IEcEncryptionPrimitives
{
    private const int AesKeyLength = 16;
    private const int PublicKeyLength = 32;
    private const int NonceLength = 12;

    public IEcEncryptionKeyPairHandle GenerateKeyPair()
    {
        var encryptionKeyPair = EcHelpers.GenerateKeyPair(EcCurveName.NistP256);
        return new NativeEcEncryptionKeyPairHandle(encryptionKeyPair);
    }

    public IEcEncryptionKeyPairHandle DeserializeKeyPair(byte[] serializedKeyPair)
    {
        return NativeEcEncryptionKeyPairHandle.Deserialize(serializedKeyPair);
    }

    public virtual PlainTextData Decrypt(EncryptedEcData encryptedData, IEcEncryptionKeyPairHandle encryptionKeyPair)
    {
        if (encryptionKeyPair is not NativeEcEncryptionKeyPairHandle nativeKeyPairHandle)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(NativeEcEncryptionKeyPairHandle)}"));
        if (encryptedData.EncryptedSymmetricKey.Length != AesKeyLength)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedEncryptionAlgorithms.Aes128)}"));
        if(encryptedData.Nonce.Length != NonceLength)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Nonce must have length {0}", NonceLength), nameof(encryptedData.Nonce));
            
        var aesEncryptionKey = DecryptAesKey(encryptedData, nativeKeyPairHandle.KeyPair);
        using var  aesCcm = new AesCcm(aesEncryptionKey);
        var plainText = new byte[encryptedData.Data.Length];
        aesCcm.Decrypt(encryptedData.Nonce, encryptedData.Data, encryptedData.Tag, plainText);
        var plainTextData = new PlainTextData
        {
            Data = plainText,
        };
        return plainTextData;
    }

    public virtual EncryptedEcData Encrypt(PlainTextData plainTextData, EcEncryptionPublicKey encryptionPublicKey)
    {
        if (encryptionPublicKey.EncryptionAlgorithm != SupportedEncryptionAlgorithms.Aes128)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(SupportedEncryptionAlgorithms.Aes128)}"));
        if (encryptionPublicKey.Key.CurveName != EcCurveName.NistP256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(EcCurveName.NistP256)}"));

        var aesEncryptionKey = new byte[AesKeyLength];
        var nonce = new byte[NonceLength];
        var secureRandom = new SecureRandom();
        secureRandom.NextBytes(aesEncryptionKey);
        secureRandom.NextBytes(nonce);
        var encryptedEncryptionKey = EncryptAesKey(aesEncryptionKey, encryptionPublicKey.Key);
        using var aesCcm = new AesCcm(aesEncryptionKey);
        var cipherText = new byte[plainTextData.Data.Length];
        var tag = new byte[AesKeyLength];
        aesCcm.Encrypt(nonce, plainTextData.Data, cipherText, tag);
        var encryptedEcData = new EncryptedEcData
        {
            EncryptedSymmetricKey = encryptedEncryptionKey.EncryptedSymmetricKey,
            KeyAuthenticationTag = encryptedEncryptionKey.KeyAuthenticationTag,
            EphemeralPublicKey = encryptedEncryptionKey.EphemeralPublicKey,
            Nonce = nonce,
            Data = cipherText,
            Tag = tag,
        };

        return encryptedEcData;
    }

    private byte[] DecryptAesKey(EncryptedEcData encryptedEcData, string encryptionKeyPair)
    {
        const int aesLength = AesKeyLength;
        const int publicKeyLength = PublicKeyLength;
        if (encryptedEcData.EphemeralPublicKey.CurveName != EcCurveName.NistP256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(EcCurveName.NistP256)}"));
        if (encryptedEcData.EncryptedSymmetricKey.Length != aesLength)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Encrypted AES key must have length {0}", aesLength), nameof(encryptedEcData.EncryptedSymmetricKey));
        if (encryptedEcData.EphemeralPublicKey.X.Length != publicKeyLength)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Ephemeral public key must have length {0}", publicKeyLength), nameof(encryptedEcData.EphemeralPublicKey.X));
        if (encryptedEcData.EphemeralPublicKey.Y.Length != publicKeyLength)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Ephemeral public key must have length {0}", publicKeyLength), nameof(encryptedEcData.EphemeralPublicKey.Y));

        var bcPrivateKey = EcHelpers.CreateBcPrivateKeyParameters(encryptionKeyPair, EcCurveName.NistP256);
        var bcPublicKey = EcHelpers.CreateBcPublicKeyParameters(encryptedEcData.EphemeralPublicKey);
        var agreement = new ECDHCBasicAgreement();
        agreement.Init(bcPrivateKey);
        var ss = agreement.CalculateAgreement(bcPublicKey);
        var ssArray = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), ss);
        var k1K2 = new byte[aesLength + publicKeyLength];
        var kdf2BytesGenerator = new Kdf2BytesGenerator(new Sha256Digest());
        kdf2BytesGenerator.Init(new KdfParameters(ssArray, Array.Empty<byte>()));
        kdf2BytesGenerator.GenerateBytes(k1K2, 0, k1K2.Length);
        var k2 = new byte[publicKeyLength];
        Array.Copy(k1K2, aesLength, k2, 0, publicKeyLength);
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(k2));
        foreach (var val in encryptedEcData.EncryptedSymmetricKey)
            mac.Update(val);
        var macResult = new byte[mac.GetMacSize()];
        mac.DoFinal(macResult, 0);
        var tag = new byte[aesLength];
        Array.Copy(macResult, tag, aesLength);
        if (!tag.SequenceEqual(encryptedEcData.KeyAuthenticationTag))
            throw new InvalidOperationException("Authentication tag does not match.");

        var keyData = new byte[aesLength];
        Span<byte> encryptedKey = encryptedEcData.EncryptedSymmetricKey;
        for (var i = 0; i < aesLength; i++)
            keyData[i] = (byte)(encryptedKey[i] ^ k1K2[i]);

        return keyData;
    }

    private EncryptedEncryptionKey EncryptAesKey(byte[] aesCcmKey, EcPublicKeyData recipientPublicKey)
    {
        const int length = PublicKeyLength;
        const int aesLength = AesKeyLength;
        if (aesCcmKey.Length != aesLength)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "AES key must have length {0}", aesLength), nameof(aesCcmKey));

        if(recipientPublicKey.CurveName != EcCurveName.NistP256)
            throw new NotSupportedException(FormattableString.Invariant($"Implementation supports only {nameof(EcCurveName.NistP256)}"));
        if (recipientPublicKey.X == null || recipientPublicKey.Y == null)
            throw new InvalidOperationException("Missing public key.");
        if (recipientPublicKey.X.Length != length)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Public key must have length {0}", length), nameof(recipientPublicKey.X));
        if (recipientPublicKey.Y.Length != length)
            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "Public key must have length {0}", length), nameof(recipientPublicKey.Y));

        var ecDomainParameters = EcHelpers.CreateBcEcDomainParameters(recipientPublicKey.CurveName);
        var keyPair = GenerateEphemeralKeyPair(ecDomainParameters);
        var agreement = new ECDHCBasicAgreement();
        var recipientPublicKeyParameters = EcHelpers.CreateBcPublicKeyParameters(recipientPublicKey);
        agreement.Init(keyPair.Item1);
        var ss = agreement.CalculateAgreement(recipientPublicKeyParameters);
        var ssArray = BigIntegers.AsUnsignedByteArray(agreement.GetFieldSize(), ss);
        var k1K2 = new byte[aesLength + length];

        var kdf2BytesGenerator = new Kdf2BytesGenerator(new Sha256Digest());
        kdf2BytesGenerator.Init(new KdfParameters(ssArray, Array.Empty<byte>()));
        kdf2BytesGenerator.GenerateBytes(k1K2, 0, k1K2.Length);
        var c = new byte[aesLength];
        for (var i = 0; i < aesLength; i++)
            c[i] = (byte)(aesCcmKey[i] ^ k1K2[i]);
        var mac = new HMac(new Sha256Digest());
        mac.Init(new KeyParameter(k1K2, aesLength, length));
        foreach (var val in c)
            mac.Update(val);
        var macResult = new byte[mac.GetMacSize()];
        mac.DoFinal(macResult, 0);
        var t = new byte[aesLength];
        Array.Copy(macResult, t, aesLength);
        var ephemeralPublicKeyData = new EcPublicKeyData
        {
            CurveName = recipientPublicKey.CurveName,
            X = keyPair.publicKeyParameters.Q.AffineXCoord.GetEncoded(),
            Y = keyPair.publicKeyParameters.Q.AffineYCoord.GetEncoded(),
        };

        return new EncryptedEncryptionKey(c, t, ephemeralPublicKeyData);
    }

    protected (ECPrivateKeyParameters privateKeyParameters, ECPublicKeyParameters publicKeyParameters) GenerateEphemeralKeyPair(ECDomainParameters domainParameters)
    {
        var secureRandom = new SecureRandom();
        var ecKeyGenerationParameters = new ECKeyGenerationParameters(domainParameters, secureRandom);
        var ecKeyPairGenerator = new ECKeyPairGenerator();
        ecKeyPairGenerator.Init(ecKeyGenerationParameters);
        var keyPair = ecKeyPairGenerator.GenerateKeyPair();
        return ((ECPrivateKeyParameters)keyPair.Private, (ECPublicKeyParameters)keyPair.Public);
    }

    private record EncryptedEncryptionKey(byte[] EncryptedSymmetricKey, byte[] KeyAuthenticationTag, EcPublicKeyData EphemeralPublicKey);
}