using Google.Protobuf;
using Intiq.Client.EnrollmentIdentity.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;
using Intiq.Client.EnrollmentIdentity.Helpers;
using EncryptedEcData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedEcData;
using EncryptionPublicKeyEc = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyEc;
using SignedEcData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedEcData;

namespace Intiq.Client.EnrollmentIdentity.Encryption.EC;

public class EcCryptoPayloadProcessor
{
    private readonly IEcEncryptionPrimitives _encryptionPrimitives;
    private readonly IEcSignaturePrimitives _signaturePrimitives;

    public EcCryptoPayloadProcessor(IEcSignaturePrimitives signaturePrimitives, IEcEncryptionPrimitives encryptionPrimitives)
    {
        _encryptionPrimitives = encryptionPrimitives;
        _signaturePrimitives = signaturePrimitives;
    }

    public EncryptedEcData EncryptData<T>(T data, EncryptionPublicKeyEc encryptionPublicKey)
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

    public T DecryptData<T>(EncryptedEcData data, IEcEncryptionKeyPairHandle encryptionKeyPair)
        where T : IMessage<T>, new()
    {
        var pkiChallengeDataPlain = _encryptionPrimitives.Decrypt(data.ToDomainDto(), encryptionKeyPair);
        var value = pkiChallengeDataPlain.Data.ProtoDeserialize<T>();
        return value;
    }

    public EncryptedEcData DecryptSignAndEncryptWithOtherKey(
        EncryptedEcData data, 
        EncryptionPublicKeyEc encryptionPublicKey,
        EcCryptographyKeys keyPairs)
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

    public EncryptedEcData SignAndEncryptWithOtherKey<T>(T data, EncryptionPublicKeyEc encryptionPublicKey, IEcVerificationKeyPairHandle verificationKeyPair)
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

    public SignedEcData Sign<T>(T data, IEcVerificationKeyPairHandle verificationKeyPair)
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