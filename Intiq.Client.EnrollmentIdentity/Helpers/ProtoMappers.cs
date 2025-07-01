using System.IO;
using Google.Protobuf;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using EcPublicKeyData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EcPublicKeyData;
using EncryptedEcData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedEcData;
using EncryptedRsaData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedRsaData;
using EncryptedRsaDataPayload = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedRsaDataPayload;
using EncryptionPublicKeyEc = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyEc;
using EncryptionPublicKeyRsa = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyRsa;
using EncryptionPublicKeyRsaData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyRsaData;
using SignedEcData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedEcData;
using SignedEcdsaDataPayload = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedEcdsaDataPayload;
using SignedRsaData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedRsaData;
using SignedRsaDataPayload = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedRsaDataPayload;
using VerificationPublicKeyEc = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.VerificationPublicKeyEc;
using VerificationPublicKeyRsa = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.VerificationPublicKeyRsa;
using VerificationPublicKeyRsaData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.VerificationPublicKeyRsaData;

namespace Intiq.Client.EnrollmentIdentity.Helpers;

public static class ProtoMappers
{
    public static EncryptionPublicKeyRsa? ToProto(this Domain.Dto.RsaEncryptionPublicKey? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new EncryptionPublicKeyRsa
        {
            Key = value.Key.ToProto(),
            EncryptionAlgorithm = value.EncryptionAlgorithm.ToProto(),
        };
        return mappedValue;
    }

    public static EncryptionPublicKeyEc? ToProto(this Domain.Dto.EcEncryptionPublicKey? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new EncryptionPublicKeyEc
        {
            Key = value.Key.ToProto(),
            EncryptionAlgorithm = value.EncryptionAlgorithm.ToProto(),
        };
        return mappedValue;
    }

    public static EncryptionPublicKeyRsaData? ToProto(this Domain.Dto.RsaEncryptionPublicKeyData? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new EncryptionPublicKeyRsaData
        {
            Rsa = ByteString.CopyFrom(value.Rsa),
        };
        return mappedValue;
    }

    public static SupportedEncryptionAlgorithmsEnum ToProto(
        this SupportedEncryptionAlgorithms value)
    {
        switch (value)
        {
            case SupportedEncryptionAlgorithms.Unknown:
                return SupportedEncryptionAlgorithmsEnum.Unknown;
            case SupportedEncryptionAlgorithms.Aes128:
                return SupportedEncryptionAlgorithmsEnum.Aes128;
            case SupportedEncryptionAlgorithms.Aes256:
                return SupportedEncryptionAlgorithmsEnum.Aes256;
            default:
                return SupportedEncryptionAlgorithmsEnum.Invalid;
        }
    }

    public static VerificationPublicKeyRsa? ToProto(this Domain.Dto.RsaVerificationPublicKey? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new VerificationPublicKeyRsa
        {
            Key = value.Key.ToProto(),
            SignatureAlgorithm = value.SignatureAlgorithm.ToProto(),
        };

        return mappedValue;
    }

    public static SupportedVerificationAlgorithmsEnum ToProto(this SupportedVerificationAlgorithms value)
    {
        switch (value)
        {
            case SupportedVerificationAlgorithms.Unknown:
                return SupportedVerificationAlgorithmsEnum.Unknown;
            case SupportedVerificationAlgorithms.Sha256:
                return SupportedVerificationAlgorithmsEnum.Sha256;
            default:
                return SupportedVerificationAlgorithmsEnum.Invalid;
        }
    }

    public static EcCurveNameEnum ToProto(this EcCurveName value)
    {
        switch (value)
        {
            case EcCurveName.Unknown:
                return EcCurveNameEnum.Unknown;
            case EcCurveName.NistP256:
                return EcCurveNameEnum.Nistp256;
            default:
                return EcCurveNameEnum.Unknown;
        }
    }

    public static VerificationPublicKeyRsaData? ToProto(this Domain.Dto.RsaVerificationPublicKeyData? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new VerificationPublicKeyRsaData
        {
            Rsa = ByteString.CopyFrom(value.Rsa)
        };
        return mappedValue;
    }

    public static EncryptedRsaData ToProto(this Domain.Dto.EncryptedRsaData value)
    {
        var mappedValue = new EncryptedRsaData
        {
            Data = value.Data.ToProto()
        };

        return mappedValue;
    }

    public static EncryptedEcData ToProto(this Domain.Dto.EncryptedEcData value)
    {
        var mappedValue = new EncryptedEcData
        {
            Data = ByteString.CopyFrom(value.Data),
            Nonce = ByteString.CopyFrom(value.Nonce),
            Tag = ByteString.CopyFrom(value.Tag),
            EncryptedSymmetricKey = ByteString.CopyFrom(value.EncryptedSymmetricKey),
            KeyAuthenticationTag = ByteString.CopyFrom(value.KeyAuthenticationTag),
            EphemeralPublicKey = value.EphemeralPublicKey.ToProto(),
        };

        return mappedValue;
    }

    public static EcPublicKeyData ToProto(this Domain.Dto.EcPublicKeyData value)
    {
        var mappedValue = new EcPublicKeyData
        {
            CurveName = value.CurveName.ToProto(),
            X = ByteString.CopyFrom(value.X),
            Y = ByteString.CopyFrom(value.Y),
        };

        return mappedValue;
    }

    public static EncryptedRsaDataPayload? ToProto(this Domain.Dto.EncryptedRsaDataPayload? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new EncryptedRsaDataPayload
        {
            Data = ByteString.CopyFrom(value.Data),
            EncryptedSymmetricKey = ByteString.CopyFrom(value.EncryptedSymmetricKey),
            Iv = ByteString.CopyFrom(value.IV),
        };

        return mappedValue;
    }

    public static SignedRsaData ToProto(this Domain.Dto.SignedRsaData value)
    {
        var mappedValue = new SignedRsaData
        {
            VerificationPublicKey = value.VerificationPublicKey.ToProto(),
            SignedData = value.SignedData.ToProto(),
        };

        return mappedValue;
    }

    public static SignedEcData ToProto(this Domain.Dto.SignedEcData value)
    {
        var mappedValue = new SignedEcData
        {
            SignedData = value.SignedData.ToProto(),
            VerificationPublicKey = value.VerificationPublicKey.ToProto(),
        };

        return mappedValue;
    }

    public static SignedEcdsaDataPayload ToProto(this Domain.Dto.SignedEcDataPayload value)
    {
        var mappedValue = new SignedEcdsaDataPayload
        {
            Data = ByteString.CopyFrom(value.Data),
            R = ByteString.CopyFrom(value.R),
            S = ByteString.CopyFrom(value.S),
        };

        return mappedValue;
    }

    public static VerificationPublicKeyEc ToProto(this Domain.Dto.EcVerificationPublicKey value)
    {
        var mappedValue = new VerificationPublicKeyEc
        {
            Key = value.Key.ToProto(),
            SignatureAlgorithm = value.SignatureAlgorithm.ToProto(),
        };

        return mappedValue;
    }

    public static SignedRsaDataPayload? ToProto(this Domain.Dto.SignedRsaDataPayload? value)
    {
        if (value == null)
        {
            return null;
        }

        var mappedValue = new SignedRsaDataPayload
        {
            Data = ByteString.CopyFrom(value.Data),
            Signature = ByteString.CopyFrom(value.Signature)
        };
        return mappedValue;
    }

    public static T ProtoDeserialize<T>(this byte[] buf) where T : IMessage<T>, new()
    {
        using var ms = new MemoryStream();
        ms.Write(buf, 0, buf.Length);
        ms.Seek(0, SeekOrigin.Begin);

        MessageParser<T> parser = new MessageParser<T>(() => new T());
        return parser.ParseFrom(ms);
    }
}