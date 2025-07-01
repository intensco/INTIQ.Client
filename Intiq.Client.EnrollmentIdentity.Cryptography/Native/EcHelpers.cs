using System;
using System.Security.Cryptography;
using Intiq.Client.EnrollmentIdentity.Domain.Dto;
using Intiq.Client.EnrollmentIdentity.Domain.Enums;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Intiq.Client.EnrollmentIdentity.Cryptography.Native;

public static class EcHelpers
{
    public static string GenerateKeyPair(EcCurveName curveName)
    {
        ECCurve curve;
        switch (curveName)
        {
            case EcCurveName.NistP256:
                curve = ECCurve.NamedCurves.nistP256;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, null);
        }

        using var ecdsa = ECDsa.Create(curve);
        return ecdsa.ExportECPrivateKeyPem();
    }

    public static ECPrivateKeyParameters CreateBcPrivateKeyParameters(string pem, EcCurveName curveName)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        var privateKeyParameters = ecdsa.ExportParameters(true);
        var ecDomain = CreateBcEcDomainParameters(curveName);
        var privateKey = privateKeyParameters.D;
        var dValue = new BigInteger(1, privateKey);

        return new ECPrivateKeyParameters(dValue, ecDomain);
    }

    public static ECParameters CreateEcParameters(EcPublicKeyData ecPublicKeyData)
    {
        var ecParameters = new ECParameters
        {
            Curve = CreateEcCurve(ecPublicKeyData.CurveName),
            Q = new ECPoint
            {
                X = ecPublicKeyData.X,
                Y = ecPublicKeyData.Y,
            }
        };
        return ecParameters;
    }

    private static ECCurve CreateEcCurve(EcCurveName curveName)
    {
        ECCurve curve;
        switch (curveName)
        {
            case EcCurveName.NistP256:
                curve = ECCurve.NamedCurves.nistP256;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, null);
        }

        return curve;
    }

    public static ECDomainParameters CreateBcEcDomainParameters(EcCurveName curveName)
    {
        string bcCurveName;
        switch (curveName)
        {
            case EcCurveName.NistP256:
                bcCurveName = "secp256r1";
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(curveName), curveName, null);
        }

        var ecNistP256Parameters = SecNamedCurves.GetByName(bcCurveName);
        var ecDomain = new ECDomainParameters(ecNistP256Parameters.Curve,
            ecNistP256Parameters.G,
            ecNistP256Parameters.N,
            ecNistP256Parameters.H);
        return ecDomain;
    }

    public static ECPublicKeyParameters CreateBcPublicKeyParameters(EcPublicKeyData publicKey)
    {
        var domainParameters = CreateBcEcDomainParameters(publicKey.CurveName);
        var publicKeyParameters = new ECPublicKeyParameters(
            domainParameters.Curve.CreatePoint(
                new BigInteger(1, publicKey.X),
                new BigInteger(1, publicKey.Y)),
            domainParameters);
        return publicKeyParameters;
    }

    public static EcEncryptionPublicKey GetEncryptionPublicKeyFromPem(string pem, EcCurveName curveName)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        var publicKey = ecdsa.ExportParameters(false);
        return new EcEncryptionPublicKey
        {
            EncryptionAlgorithm = SupportedEncryptionAlgorithms.Aes128,
            Key = new EcPublicKeyData
            {
                CurveName = curveName,
                X = publicKey.Q.X!,
                Y = publicKey.Q.Y!,
            },
        };
    }

    public static EcVerificationPublicKey GetVerificationPublicKeyFromPem(string pem, EcCurveName curveName)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        var publicKey = ecdsa.ExportParameters(false);
        return new EcVerificationPublicKey
        {
            SignatureAlgorithm = SupportedVerificationAlgorithms.Sha256,
            Key = new EcPublicKeyData
            {
                CurveName = curveName,
                X = publicKey.Q.X!,
                Y = publicKey.Q.Y!,
            }
        };
    }
}