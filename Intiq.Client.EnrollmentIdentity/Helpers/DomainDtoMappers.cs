using System;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;

namespace Intiq.Client.EnrollmentIdentity.Helpers;

public static class DomainDtoMappers
{
    public static RsaEncryptionPublicKey ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyRsa value)
    {
        var mappedValue = new RsaEncryptionPublicKey
        {
            Key = value.Key.ToDomainDto(),
            EncryptionAlgorithm = value.EncryptionAlgorithm.ToDomainDto(),
        };
        return mappedValue;
    }

    public static EcEncryptionPublicKey ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyEc value)
    {
        var mappedValue = new EcEncryptionPublicKey
        {
            Key = value.Key.ToDomainDto(),
            EncryptionAlgorithm = value.EncryptionAlgorithm.ToDomainDto(),
        };
        return mappedValue;
    }

    public static EcPublicKeyData ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EcPublicKeyData value)
    {
        var mappedValue = new EcPublicKeyData
        {
            X = value.X.ToByteArray(),
            Y = value.Y.ToByteArray(),
            CurveName = value.CurveName.ToDomainDto(),
        };
        return mappedValue;
    }

    public static RsaEncryptionPublicKeyData ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyRsaData value)
    {
        var mappedValue = new RsaEncryptionPublicKeyData
        {
            Rsa = value.Rsa.ToByteArray(),
        };
        return mappedValue;
    }

    public static SupportedEncryptionAlgorithms ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.SupportedEncryptionAlgorithmsEnum value)
    {
        switch (value)
        {
            case SystemGateways.EnrollmentAuthority.Common.V2.SupportedEncryptionAlgorithmsEnum.Unknown:
                return SupportedEncryptionAlgorithms.Unknown;
            case SystemGateways.EnrollmentAuthority.Common.V2.SupportedEncryptionAlgorithmsEnum.Aes128:
                return SupportedEncryptionAlgorithms.Aes128;
            case SystemGateways.EnrollmentAuthority.Common.V2.SupportedEncryptionAlgorithmsEnum.Aes256:
                return SupportedEncryptionAlgorithms.Aes256;
            default:
                return SupportedEncryptionAlgorithms.Invalid;
        }
    }

    public static EcCurveName ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EcCurveNameEnum value)
    {
        switch (value)
        {
            case SystemGateways.EnrollmentAuthority.Common.V2.EcCurveNameEnum.Unknown:
                return EcCurveName.Unknown;
            case SystemGateways.EnrollmentAuthority.Common.V2.EcCurveNameEnum.Nistp256:
                return EcCurveName.NistP256;
            default:
                throw new NotSupportedException("Not supported curve " + value);
        }
    }

    public static EncryptedRsaData ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptedRsaData value)
    {
        var mappedValue = new EncryptedRsaData
        {
            Data = value.Data.ToDomainDto(),
        };

        return mappedValue;
    }

    public static EncryptedEcData ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptedEcData value)
    {
        var mappedValue = new EncryptedEcData
        {
            EphemeralPublicKey = value.EphemeralPublicKey.ToDomainDto(),
            Tag = value.Tag.ToByteArray(),
            KeyAuthenticationTag = value.KeyAuthenticationTag.ToByteArray(),
            Data = value.Data.ToByteArray(),
            EncryptedSymmetricKey = value.EncryptedSymmetricKey.ToByteArray(),
            Nonce = value.Nonce.ToByteArray(),
        };

        return mappedValue;
    }

    public static EncryptedRsaDataPayload ToDomainDto(this SystemGateways.EnrollmentAuthority.Common.V2.EncryptedRsaDataPayload value)
    {
        var mappedValue = new EncryptedRsaDataPayload
        {
            Data = value.Data.ToByteArray(),
            EncryptedSymmetricKey = value.EncryptedSymmetricKey.ToByteArray(),
            IV = value.Iv.ToByteArray(),
        };
        return mappedValue;
    }
}