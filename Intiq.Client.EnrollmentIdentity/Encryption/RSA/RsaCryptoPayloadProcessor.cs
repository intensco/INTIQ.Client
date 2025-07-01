using Google.Protobuf;
using Intiq.Client.EnrollmentIdentity.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;
using Intiq.Client.EnrollmentIdentity.Helpers;
using EncryptedRsaData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedRsaData;
using EncryptionPublicKeyRsa = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyRsa;
using SignedRsaData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedRsaData;

namespace Intiq.Client.EnrollmentIdentity.Encryption.RSA;

public class RsaCryptoPayloadProcessor
{
    private readonly IRsaEncryptionPrimitives _encryptionPrimitives;
    private readonly IRsaSignaturePrimitives _signaturePrimitives;

    public RsaCryptoPayloadProcessor(IRsaSignaturePrimitives signaturePrimitives, IRsaEncryptionPrimitives encryptionPrimitives)
    {
        _encryptionPrimitives = encryptionPrimitives;
        _signaturePrimitives = signaturePrimitives;
    }

    public EncryptedRsaData EncryptData<T>(T data, EncryptionPublicKeyRsa encryptionPublicKey)
        where T : IMessage<T>, new()
    {
        var plainTextPayload = data.ToByteArray();
        var plainTextData = new PlainTextData
        {
            Data = plainTextPayload,
        };
        var pkiEncryptedData = _encryptionPrimitives.Encrypt(plainTextData, encryptionPublicKey.ToDomainDto());
        var encryptedData = pkiEncryptedData.ToProto();
        return encryptedData;
    }

    public T DecryptData<T>(EncryptedRsaData data, IRsaEncryptionKeyPairHandle encryptionKeyPair)
        where T : IMessage<T>, new()
    {
        var pkiChallengeDataPlain = _encryptionPrimitives.Decrypt(data.ToDomainDto(), encryptionKeyPair);
        var value = pkiChallengeDataPlain.Data.ProtoDeserialize<T>();
        return value;
    }

    public EncryptedRsaData DecryptSignAndEncryptWithOtherKey(
        EncryptedRsaData data, 
        EncryptionPublicKeyRsa encryptionPublicKey,
        RsaCryptographyKeys keyPairs)
    {
        var pkiChallengeDataPlain = _encryptionPrimitives.Decrypt(data.ToDomainDto(), keyPairs.EncryptionKeyPair);
        var pkiSignedData = _signaturePrimitives.Sign(pkiChallengeDataPlain, SupportedVerificationAlgorithms.Sha256, keyPairs.VerificationKeyPair);
        var signedData = pkiSignedData.ToProto();
        var pkiSignedDataContent = signedData.ToByteArray();
        var pkiSignedDataPlain = new PlainTextData
        {
            Data = pkiSignedDataContent,
        };
        var pkiSignedAndEncryptedData = _encryptionPrimitives
            .Encrypt(pkiSignedDataPlain, encryptionPublicKey.ToDomainDto());
        var signedAndEncryptedData = pkiSignedAndEncryptedData.ToProto();
        return signedAndEncryptedData;
    }

    public EncryptedRsaData SignAndEncryptWithOtherKey<T>(T data, EncryptionPublicKeyRsa encryptionPublicKey, IRsaVerificationKeyPairHandle verificationKeyPair)
        where T : IMessage<T>, new()
    {
        var plainTextDataContent = data.ToByteArray();
        var plainText = new PlainTextData
        {
            Data = plainTextDataContent,
        };
        var pkiSignedData = _signaturePrimitives.Sign(plainText, SupportedVerificationAlgorithms.Sha256, verificationKeyPair);
        var signedData = pkiSignedData.ToProto();
        var signedDataContent = signedData.ToByteArray();
        var signedPlainText = new PlainTextData
        {
            Data = signedDataContent,
        };
        var signedEncrypted = _encryptionPrimitives.Encrypt(signedPlainText, encryptionPublicKey.ToDomainDto());
        var encryptedData = signedEncrypted.ToProto();
        return encryptedData;
    }

    public SignedRsaData Sign<T>(T data, IRsaVerificationKeyPairHandle verificationKeyPair)
        where T : IMessage<T>, new()
    {
        var plainTextDataContent = data.ToByteArray();
        var plainText = new PlainTextData
        {
            Data = plainTextDataContent,
        };
        var pkiSignedData = _signaturePrimitives.Sign(plainText, SupportedVerificationAlgorithms.Sha256, verificationKeyPair);
        var signedData = pkiSignedData.ToProto();
        return signedData;
    }
}