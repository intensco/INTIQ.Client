using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Intiq.Client.EnrollmentIdentity.Configuration;
using Intiq.Client.EnrollmentIdentity.Cryptography;
using Intiq.Client.EnrollmentIdentity.Enums;
using Intiq.Client.EnrollmentIdentity.Helpers;
using Intiq.SystemGateways.EnrollmentAuthority.Authority.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Common.V2;
using Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2;
using Microsoft.Extensions.Options;
using EcPublicKeyData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EcPublicKeyData;
using EncryptedEcData = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptedEcData;
using EncryptionPublicKeyEc = Intiq.SystemGateways.EnrollmentAuthority.Common.V2.EncryptionPublicKeyEc;
using SignedEcData = Intiq.SystemGateways.EnrollmentAuthority.Encrypted.V2.SignedEcData;

namespace Intiq.Client.EnrollmentIdentity.Encryption.EC;

public class EcEnrollmentEncryptionHandler : IEnrollmentEncryptionHandler
{
    private readonly EnrollmentAuthorityService.EnrollmentAuthorityServiceClient _enrollmentAuthorityClient;
    private readonly EcCryptoPayloadProcessor _cryptoPayloadProcessor;
    private readonly EnrollmentOptions _options;

    private CertificateData? _certificate;
    private string? _certificateDataEncoded;
    private EcCryptographyKeys? _keyPairs;

    private string CertificateDataEncoded
    {
        get
        {
            if (_certificateDataEncoded == null)
            {
                throw new InvalidOperationException("Certificate needs to be loaded first. Use ImportCertificateAsync first.");
            }

            return _certificateDataEncoded;
        }
    }

    public EcEnrollmentEncryptionHandler(
        EnrollmentAuthorityService.EnrollmentAuthorityServiceClient enrollmentAuthorityClient,
        EcCryptoPayloadProcessor cryptoPayloadProcessor,
        IOptions<EnrollmentOptions> options)
    {
        _enrollmentAuthorityClient = enrollmentAuthorityClient;
        _cryptoPayloadProcessor = cryptoPayloadProcessor;
        _options = options.Value;
    }

    private void CheckCertificate()
    {
        if (_certificate == null)
        {
            throw new InvalidOperationException("Certificate needs to be loaded first. Use ImportCertificate first");
        }
    }

    public void ImportKeyPairs(CryptographyKeys keyPairs)
    {
        _keyPairs = ToEcCryptographyKeys(keyPairs);
    }

    public void ImportCertificate(CertificateData certificate)
    {
        _certificate = certificate;
        _certificateDataEncoded = Convert.ToBase64String(certificate.Data.Span);

        ValidateKeyPairsAndCertificate(certificate);
    }

    private void ValidateKeyPairsAndCertificate(CertificateData certificate)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("Public keys needs to be imported at first");
        }

        var csr = DeserializeCsr(certificate);
        if (csr.Data?.EncryptionPublicKey?.Key == null)
        {
            throw new InvalidOperationException("Missing encryption public key in certificate.");
        }

        if (csr.Data?.VerificationPublicKey?.Key.X == null || csr.Data?.VerificationPublicKey?.Key.Y == null)
        {
            throw new InvalidOperationException("Missing verification public key in certificate.");
        }

        var encryptionKey = _keyPairs.Value.EncryptionKeyPair.GetEncryptionPublicKey();
        if (encryptionKey.Key == null)
        {
            throw new InvalidOperationException("Missing encryption key.");
        }

        if (encryptionKey.Key.X == null || encryptionKey.Key.Y == null)
        {
            throw new InvalidOperationException("Missing encryption key.");
        }

        if (!encryptionKey.Key.X.SequenceEqual(csr.Data.EncryptionPublicKey.Key.X))
        {
            throw new InvalidOperationException("Certificate and encryption keypair mismatch.");
        }

        if (!encryptionKey.Key.Y.SequenceEqual(csr.Data.EncryptionPublicKey.Key.Y))
        {
            throw new InvalidOperationException("Certificate and encryption keypair mismatch.");
        }

        var verificationKey = _keyPairs.Value.VerificationKeyPair.GetVerificationPublicKey();
        if (verificationKey.Key == null)
        {
            throw new InvalidOperationException("Missing verification key.");
        }

        if (verificationKey.Key.X == null || verificationKey.Key.Y == null)
        {
            throw new InvalidOperationException("Missing verification key.");
        }

        if (!verificationKey.Key.X.SequenceEqual(csr.Data.VerificationPublicKey.Key.X))
        {
            throw new InvalidOperationException("Certificate and verification keypair mismatch.");
        }

        if (!verificationKey.Key.Y.SequenceEqual(csr.Data.VerificationPublicKey.Key.Y))
        {
            throw new InvalidOperationException("Certificate and verification keypair mismatch.");
        }
    }

    private CertificateSigningRequestEc DeserializeCsr(CertificateData certificate)
    {
        var signedData = certificate.Data.ToByteArray().ProtoDeserialize<SignedEcData>();
        if (signedData.SignedData == null)
        {
            throw new InvalidOperationException("Missing signed data.");
        }

        return signedData.SignedData.Data.ToByteArray().ProtoDeserialize<CertificateSigningRequestEc>();
    }

    public async IAsyncEnumerable<IEnrollIdentityItemResponse> EnrollIdentity(IEnrollIdentityRequest request, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (request is not EcEnrollIdentityRequest ecRequest)
        {
            throw new NotSupportedException("This implementation supports only EC requests.");
        }

        using var call = _enrollmentAuthorityClient.EnrollIdentityEc(ecRequest.Request, cancellationToken: cancellationToken);

        await foreach (var ecResponse in call.ResponseStream.ReadAllAsync(cancellationToken: cancellationToken))
        {
            yield return ecResponse;
        }
    }

    public async Task<AuthTokens> GetAuthTokenAsync(
        EnrollmentEntityDescriptor[] entities,
        EnrollmentIdentityScopesEnum[] scopes,
        CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);

        var authenticationTokenRequestData = new AuthTokenRequestEcData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
        };
        authenticationTokenRequestData.Scopes.AddRange(scopes);
        authenticationTokenRequestData.Entities.AddRange(entities);

        var authenticationTokenRequestDataEncrypted = _cryptoPayloadProcessor.EncryptData(authenticationTokenRequestData, eaEncryptionPublicKey);

        var request = new GetAuthTokenEcRequest
        {
            TokenRequestData = authenticationTokenRequestDataEncrypted,
        };

        var callOptions = GetCallOptions(cancellationToken);

        var response = await _enrollmentAuthorityClient.GetAuthTokenEcAsync(request, callOptions);

        if (response.AuthTokenData == null)
        {
            return new AuthTokens();
        }

        return _cryptoPayloadProcessor.DecryptData<AuthTokens>(response.AuthTokenData, _keyPairs.Value.EncryptionKeyPair);
    }

    private CallOptions GetCallOptions(CancellationToken cancellationToken)
    {
        var headers = new Metadata
        {
            { WellKnownHeaders.XCert, CertificateDataEncoded }
        };
        return new CallOptions(headers: headers, cancellationToken: cancellationToken);
    }

    public async Task<TokenData> RefreshAuthTokenAsync(TokenData refreshToken, CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);
        var refreshAuthenticationTokenData = new RefreshAuthTokenData
        {
            RefreshToken = refreshToken,
        };

        var refreshAuthenticationTokenDataEncrypted = _cryptoPayloadProcessor.EncryptData(refreshAuthenticationTokenData, eaEncryptionPublicKey);
        var request = new RefreshAuthTokenEcRequest
        {
            RefreshTokenData = refreshAuthenticationTokenDataEncrypted,
        };

        var response = await _enrollmentAuthorityClient.RefreshAuthTokenEcAsync(request, GetCallOptions(cancellationToken));

        if (response.AuthTokenData == null)
        {
            return new TokenData();
        }

        return _cryptoPayloadProcessor.DecryptData<TokenData>(response.AuthTokenData, _keyPairs.Value.EncryptionKeyPair);
    }

    public async Task<RegisteredEntitiesData> RegisterEntitiesAsync(EnrollmentEntityDescriptor[] entities, CancellationToken cancellationToken = default)
    {
        CheckCertificate();
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var registeredEntitiesData = new RegisterEntitiesRequestEcData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
        };
        registeredEntitiesData.Entities.AddRange(entities);

        var registerEntitiesEncrypted = _cryptoPayloadProcessor.EncryptData(registeredEntitiesData, eaEncryptionPublicKey);
        var request = new RegisterEntitiesEcRequest
        {
            RegisterEntitiesData = registerEntitiesEncrypted,
        };

        var response = await _enrollmentAuthorityClient.RegisterEntitiesEcAsync(request, GetCallOptions(cancellationToken));

        if (response.RegisteredEntities == null)
        {
            return new RegisteredEntitiesData();
        }

        return _cryptoPayloadProcessor.DecryptData<RegisteredEntitiesData>(response.RegisteredEntities, _keyPairs.Value.EncryptionKeyPair);
    }

    public IDuplexStream<GetEntitiesItemRequest, IGetEntitiesItemResponse> GetEntities(CancellationToken cancellationToken = default)
    {
        CheckCertificate();

        return new GrpcDuplexStreamWrapper<GetEntitiesItemRequest, IGetEntitiesItemResponse, GetEntitiesItemEcRequest, GetEntitiesItemEcResponse>(
            _enrollmentAuthorityClient.GetEntitiesEc(GetCallOptions(cancellationToken)),
            async (r, ct) =>
            {
                if (r.EventVersionInfo != null) // first request
                {
                    var getEntitiesRequest = new GetEntitiesItemEcRequest
                    {
                        EventVersionInfo = r.EventVersionInfo,
                        RequestId = Guid.NewGuid().ToString(),
                    };

                    // always authorize request with new loop and new stream
                    await AuthorizeEntitiesRequestAsync(getEntitiesRequest, ct);

                    return getEntitiesRequest;
                }

                return new GetEntitiesItemEcRequest
                {
                    ConfirmedEventVersionInfo = r.ConfirmedEventVersionInfo,
                    RequestId = Guid.NewGuid().ToString(),
                };
            },
            r => r);
    }

    private async Task<GetChallengeDataEcResponse> GetChallengeDataAsync(CallOptions callOptions)
    {
        var getChallengeData = new GetChallengeDataEcRequest();

        return await _enrollmentAuthorityClient.GetChallengeDataEcAsync(getChallengeData, callOptions);
    }

    private async Task<PreparedChallengeData> PrepareChallengeDataAsync(
        EncryptionPublicKeyEc eaEncryptionPublicKey,
        EcCryptoPayloadProcessor cryptoPayloadProcessor,
        CancellationToken cancel = default)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var headers = new Metadata
        {
            {WellKnownHeaders.XCert, CertificateDataEncoded}
        };

        var challengeDataResponse = await GetChallengeDataAsync(new CallOptions(headers: headers, cancellationToken: cancel));

        if (challengeDataResponse.EncryptedData == null)
        {
            throw new InvalidOperationException("Could not get challenge data.");
        }

        var preparedChallengeData = cryptoPayloadProcessor.DecryptSignAndEncryptWithOtherKey(
            challengeDataResponse.EncryptedData,
            eaEncryptionPublicKey,
            _keyPairs.Value);

        return new PreparedChallengeData(Guid.Parse(challengeDataResponse.Id), preparedChallengeData);
    }

    private async Task<EncryptionPublicKeyEc> GetEaEncryptionPublicKeyAsync(CancellationToken cancellationToken = default)
    {
        var request = new GetEncryptionPublicKeyEcRequest
        {
            AcceptableCiphers = AvailableCiphersEcEnum.EcNistP256,
        };
        var eaEncryptionPublicKeyResponse = await _enrollmentAuthorityClient.GetEncryptionPublicKeyEcAsync(request, new CallOptions(cancellationToken: cancellationToken));
        return new EncryptionPublicKeyEc
        {
            Key = new EcPublicKeyData
            {
                CurveName = eaEncryptionPublicKeyResponse.EncryptionPublicKey.Key.CurveName,
                X = eaEncryptionPublicKeyResponse.EncryptionPublicKey.Key.X,
                Y = eaEncryptionPublicKeyResponse.EncryptionPublicKey.Key.Y,
            },
            EncryptionAlgorithm = eaEncryptionPublicKeyResponse.EncryptionPublicKey.EncryptionAlgorithm,
        };
    }
    
    public async Task<IEnrollIdentityRequest> BuildCertificateSigningRequestAsync(CancellationToken cancellationToken = default)
    {
        if (!_keyPairs.HasValue)
        {
            throw new InvalidOperationException("No certificate nor public keys were imported");
        }

        var encryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);

        var csrBuilder = new EcCsrBuilder();
        var csr = csrBuilder.BuildCertificateSigningRequest(
            _options.CsrTitle,
            _options.EnrollmentIdentity,
            _options.Entities,
            _keyPairs.Value);

        var encryptedData = _cryptoPayloadProcessor.SignAndEncryptWithOtherKey(csr, encryptionPublicKey, _keyPairs.Value.VerificationKeyPair);
        var enrollIdentity = new EnrollIdentityEcRequest
        {
            Id = _options.EnrollmentIdentity!.Id.ToString(),
            CsrEncryptedData = encryptedData,
        };
        return new EcEnrollIdentityRequest
        {
            Request = enrollIdentity
        };
    }

    public async Task<IRefreshEnrolledIdentityRequest> BuildRefreshEnrolledIdentityRequestAsync(CryptographyKeys refreshKeys,
        CancellationToken cancellationToken = default)
    {
        var rsaRefreshKeys = ToEcCryptographyKeys(refreshKeys);
        var encryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(encryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var csrBuilder = new EcCsrBuilder();
        var refreshCsr = csrBuilder.BuildCertificateSigningRequest(
            _options.CsrTitle,
            _options.EnrollmentIdentity,
            _options.Entities,
            rsaRefreshKeys);
        var refreshCsrSigned = _cryptoPayloadProcessor.Sign(refreshCsr, rsaRefreshKeys.VerificationKeyPair);
        var refreshEncryptedData = new RefreshEncryptedEcData
        {
            ChallengeData = preparedChallengeData.ChallengeData,
            Id = preparedChallengeData.ChallengeId.ToString(),
            SignedCsrData = refreshCsrSigned
        };
        var refreshEncryptedDataEncrypted = _cryptoPayloadProcessor.EncryptData(refreshEncryptedData, encryptionPublicKey);
        var refreshEnrollmentIdentityRequest = new RefreshEnrolledIdentityEcRequest
        {
            RefreshEncryptedData = refreshEncryptedDataEncrypted,
            Id = refreshCsr.Data.Id,
        };

        return new EcRefreshEnrolledIdentityRequest
        {
            Request = refreshEnrollmentIdentityRequest
        };
    }

    public async Task<CertificateData> RefreshEnrolledIdentityAsync(IRefreshEnrolledIdentityRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is not EcRefreshEnrolledIdentityRequest ecRequest)
        {
            throw new NotSupportedException("This implementation supports only EC requests.");
        }

        var response = await _enrollmentAuthorityClient.RefreshEnrolledIdentityEcAsync(ecRequest.Request, GetCallOptions(cancellationToken));

        return response.IssuedCertificate;
    }

    public async Task ConfirmEnrolledIdentityAsync(CertificateData newCertificate, CancellationToken cancellationToken = default)
    {
        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancellationToken);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancellationToken);
        var confirmedRequestRsaData = new ConfirmedRequestEcData
        {
            Id = preparedChallengeData.ChallengeId.ToString(),
            ChallengeData = preparedChallengeData.ChallengeData,
            XNewCert = newCertificate.Data,
        };
        var confirmedRequestRsaDataEncrypted = _cryptoPayloadProcessor.EncryptData(confirmedRequestRsaData, eaEncryptionPublicKey);
        var request = new ConfirmEnrolledIdentityEcRequest
        {
            ConfirmRequestData = confirmedRequestRsaDataEncrypted,
        };
        await _enrollmentAuthorityClient.ConfirmEnrolledIdentityEcAsync(request, GetCallOptions(cancellationToken));
    }

    private async Task AuthorizeEntitiesRequestAsync(GetEntitiesItemEcRequest request, CancellationToken cancel)
    {
        var eaEncryptionPublicKey = await GetEaEncryptionPublicKeyAsync(cancel);
        var preparedChallengeData = await PrepareChallengeDataAsync(eaEncryptionPublicKey, _cryptoPayloadProcessor, cancel);
        request.ChallengeData = preparedChallengeData.ChallengeData;
        request.Id = preparedChallengeData.ChallengeId.ToString();
    }

    private static EcCryptographyKeys ToEcCryptographyKeys(CryptographyKeys keyPairs)
    {
        if (keyPairs.EncryptionKeyPair is not IEcEncryptionKeyPairHandle encryptionKeyPair)
        {
            throw new NotSupportedException("This implementation supports only EC encryption key pairs.");
        }

        if (keyPairs.VerificationKeyPair is not IEcVerificationKeyPairHandle verificationKeyPair)
        {
            throw new NotSupportedException("This implementation supports only EC verification key pairs.");
        }

        var ecKeyPairs = new EcCryptographyKeys(encryptionKeyPair, verificationKeyPair);
        
        return ecKeyPairs;
    }

    private record PreparedChallengeData(Guid ChallengeId, EncryptedEcData ChallengeData);
}